/*
 * Copyright (C) 2026 Deltik <https://www.deltik.net/>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of LibreProtect.
 *
 * LibreProtect is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LibreProtect is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LibreProtect.  If not, see <https://www.gnu.org/licenses/>.
 */

package net.deltik.mc.libreprotect.extension.upstream.clickhouse;

import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.Row;
import net.deltik.mc.libreprotect.extension.migration.RowSink;
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import net.deltik.mc.libreprotect.extension.upstream.Capabilities;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Family;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamChanged;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Path;
import java.sql.SQLDataException;
import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * What the ClickHouse endpoints do without a server.
 */
class ClickHouseEndpointsTest {

    private ClickHouseApi api;
    private ClickHouseEndpoints endpoints;
    private UpstreamCodecs codecs;

    @BeforeEach
    void setUp() throws Exception {
        api = ClickHouseTestServer.writes();
        endpoints = new ClickHouseEndpoints(Capabilities.current());
        codecs = new UpstreamCodecs();
    }

    private Family family(String table) {
        return api.family(table);
    }

    @Nested
    @DisplayName("Settings")
    class Settings {

        @Test
        @DisplayName("should refuse settings of another engine")
        void otherEngine() {
            DatabaseSettings mysql = DatabaseSettings.server(Engine.MYSQL, "127.0.0.1", 3306, "coreprotect",
                "coreprotect", "", false, "co_");
            assertThrows(IllegalArgumentException.class, () -> endpoints.openSource(mysql));
            assertThrows(IllegalArgumentException.class, () -> endpoints.openSink(mysql));
        }

        @Test
        @DisplayName("should report settings CoreProtect can't use as a connection error")
        void invalid() {
            DatabaseSettings noUser = DatabaseSettings.server(Engine.CLICKHOUSE, "127.0.0.1", 8123, "coreprotect",
                null, "", false, "co_");
            SQLException e = assertThrows(SQLNonTransientConnectionException.class,
                () -> endpoints.openSource(noUser));
            assertTrue(e.getMessage().contains("username"), e.getMessage());
        }

        @Test
        @DisplayName("should refuse a table prefix that isn't a plain identifier")
        void prefix() {
            DatabaseSettings settings = DatabaseSettings.server(Engine.CLICKHOUSE, "127.0.0.1", 8123, "coreprotect",
                "coreprotect", "", false, "co-");
            assertThrows(SQLException.class, () -> endpoints.openSource(settings));
        }
    }

    @Nested
    @DisplayName("Source timeouts")
    class SourceTimeouts {

        /**
         * CoreProtect's migration-read settings differ from its normal ones in
         * two ways: no socket timeout, and wait_end_of_query=0, which the
         * client sends with each query where the server can see it.
         */
        @Test
        @DisplayName("should give every query CoreProtect's normal timeout except the one streaming a table")
        void onlyStreamingWaits() throws Exception {
            try (RecordingClickHouse clickHouse = new RecordingClickHouse();
                 ClickHouseRowSource source = new ClickHouseRowSource(api, clickHouse.config(api), "co_")) {
                List<String> columns = List.of("time", "message");
                assertThrows(SQLException.class, source::tables);
                assertThrows(SQLException.class, () -> source.columns("chat"));
                assertThrows(SQLException.class, () -> source.stats("chat"));
                assertThrows(SQLException.class, () -> source.stats("entity_spawn"));
                assertThrows(SQLException.class, () -> source.highWater("chat"));
                assertThrows(SQLException.class, () -> source.readRanges("chat", columns, List.of(new long[]{1, 5})));
                assertThrows(SQLException.class, () -> source.read("chat", columns, 0, 10));

                for (String query : List.of("FROM system.tables", "FROM system.columns", "SELECT count(), min(rowid)",
                    "HAVING count() > 1", "max(batch_sequence)", "(rowid >= 1 AND rowid <= 5)")) {
                    List<RecordingClickHouse.Request> requests = clickHouse.requests(query);
                    assertFalse(requests.isEmpty(), query);
                    for (RecordingClickHouse.Request request : requests) {
                        assertTrue(request.settings().contains("wait_end_of_query=1"), query + ": " + request);
                    }
                }
                List<RecordingClickHouse.Request> streaming = clickHouse.requests("WHERE rowid >= 0 ORDER BY rowid");
                assertEquals(1, streaming.size());
                assertTrue(streaming.get(0).settings().contains("wait_end_of_query=0"), streaming.toString());
            }
        }
    }

    @Nested
    @DisplayName("Handing over the prepared database")
    class HandOver {

        @Test
        @DisplayName("should refuse sinks of other engines")
        void otherSink() {
            assertThrows(IllegalArgumentException.class, () -> ClickHouseEndpoints.preparedDatabase(new OtherSink()));
            assertThrows(IllegalArgumentException.class, () -> endpoints.handOver(new OtherSink()));
        }

        @Test
        @DisplayName("should refuse a sink that isn't prepared")
        void unprepared(@TempDir Path controlDirectory) throws SQLException {
            try (ClickHouseRowSink sink = unreachableSink(controlDirectory)) {
                assertThrows(IllegalStateException.class, () -> ClickHouseEndpoints.preparedDatabase(sink));
                assertThrows(IllegalStateException.class, () -> endpoints.handOver(sink));
            }
        }

        @Test
        @DisplayName("should refuse a closed sink")
        void closed(@TempDir Path controlDirectory) throws SQLException {
            ClickHouseRowSink sink = unreachableSink(controlDirectory);
            sink.close();
            sink.close();
            assertThrows(IllegalStateException.class, () -> ClickHouseEndpoints.preparedDatabase(sink));
            assertThrows(IllegalStateException.class, () -> sink.prepare(Map.of()));
        }

        private ClickHouseRowSink unreachableSink(Path controlDirectory) throws SQLException {
            return new ClickHouseRowSink(api, api.config("127.0.0.1", 1, "coreprotect", "coreprotect", "", false),
                "co_", controlDirectory, "2.24.1", (map, floor, candidates) -> List.of(),
                new PublishDeadline(ClickHouseRowSink.PUBLISH_LIMIT, () -> false));
        }
    }

    @Nested
    @DisplayName("Values written to ClickHouse")
    class Values {

        @Test
        @DisplayName("should keep entity data that is already in CoreProtect's columnar encoding")
        void encodedEntityData() throws SQLException {
            byte[] encoded = codecs.encodeEntity("ENTITY", List.of("zombie", 20));
            assertSame(encoded, ClickHouseRowSink.toClickHouse(family("entity"), "entity", "data", encoded, 1));
        }

        @Test
        @DisplayName("should convert legacy entity data to CoreProtect's columnar encoding")
        void legacyEntityData() throws Exception {
            List<Object> data = new ArrayList<>(Arrays.asList("minecraft:cow", 7, 1.5, null, true));
            byte[] legacy = javaSerialized(data);

            byte[] converted = (byte[]) ClickHouseRowSink.toClickHouse(family("entity_spawn"), "entity_spawn",
                "data", legacy, 9);

            assertTrue(codecs.isEncoded(converted));
            assertArrayEquals(codecs.forClickHouse("entity_spawn", legacy), converted);
            assertEquals(data, codecs.decodeEntity("ENTITY_SPAWN", converted));
        }

        @Test
        @DisplayName("should keep data the copier already converted as it is, so nothing is converted twice")
        void convertedByCopier() throws Exception {
            // What the copier hands over from a relational source: CoreProtect's conversion for ClickHouse
            byte[] entity = codecs.forClickHouse("entity", javaSerialized(new ArrayList<>(Arrays.asList(
                "minecraft:zombie", 20))));
            byte[] spawn = codecs.forClickHouse("entity_spawn", javaSerialized(new ArrayList<>(Arrays.asList(
                "minecraft:sheep", "WHITE"))));
            byte[] meta = codecs.forClickHouse("block", javaSerialized(new ArrayList<>(Arrays.asList(
                "minecraft:chest", 3))));

            assertSame(entity, ClickHouseRowSink.toClickHouse(family("entity"), "entity", "data", entity, 1));
            assertSame(spawn, ClickHouseRowSink.toClickHouse(family("entity_spawn"), "entity_spawn", "data",
                spawn, 1));
            assertSame(meta, ClickHouseRowSink.toClickHouse(family("block"), "block", "meta", meta, 1));
            // CoreProtect's writer canonicalizes block metadata itself, which changes nothing that's canonical
            assertArrayEquals(meta, codecs.forClickHouse("block", meta));
        }

        @Test
        @DisplayName("should name the row CoreProtect's writer refuses, but not blame a row for a change of CoreProtect")
        void refusedRow() {
            SQLDataException refused = ClickHouseRowSink.refusedRow("chat", 3,
                new IllegalArgumentException("Reserved ClickHouse compatibility column: rowid"));
            assertEquals("Can't write chat row 3 to ClickHouse: Reserved ClickHouse compatibility column: rowid",
                refused.getMessage());

            // As when a handle can't be made the first time the sink writes
            UpstreamChanged changed = new UpstreamChanged("CoreProtect's ClickHouseEventBatch.addCompatibilityRow("
                + "ClickHouseFamily, long, Map) can't be reached: java.lang.NoSuchMethodException");
            assertSame(changed, assertThrows(UpstreamChanged.class,
                () -> ClickHouseRowSink.refusedRow("chat", 3, changed)));
        }

        @Test
        @DisplayName("should name the row whose entity data can't be converted")
        void badEntityData() {
            SQLDataException e = assertThrows(SQLDataException.class, () -> ClickHouseRowSink.toClickHouse(
                family("entity"), "entity", "data", new byte[]{1, 2, 3}, 77));
            assertTrue(e.getMessage().contains("entity row 77"), e.getMessage());
        }

        @Test
        @DisplayName("should store an empty user UUID as none, as CoreProtect does")
        void emptyUuid() throws SQLException {
            assertNull(ClickHouseRowSink.toClickHouse(family("user"), "user", "uuid", "", 1));
            assertNull(ClickHouseRowSink.toClickHouse(family("username_log"), "username_log", "uuid", "", 1));
            assertEquals("", ClickHouseRowSink.toClickHouse(family("entity_spawn"), "entity_spawn", "uuid", "", 1));
            assertEquals("", ClickHouseRowSink.toClickHouse(family("user"), "user", "user", "", 1));
        }

        @Test
        @DisplayName("should pass other values through, block metadata included")
        void others() throws SQLException {
            byte[] meta = {(byte) 0xac, (byte) 0xed, 0, 5};
            assertSame(meta, ClickHouseRowSink.toClickHouse(family("block"), "block", "meta", meta, 1));
            assertEquals(5L, ClickHouseRowSink.toClickHouse(family("block"), "block", "data", 5L, 1));
            assertNull(ClickHouseRowSink.toClickHouse(family("entity"), "entity", "data", null, 1));
        }

        @ParameterizedTest(name = "{0}.{1} = {2}")
        @MethodSource("net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseEndpointsTest#unfit")
        @DisplayName("should refuse values ClickHouse would store as 0, wrap or truncate")
        void unfit(String table, String column, Object value, String problem) {
            SQLDataException e = assertThrows(SQLDataException.class, () -> ClickHouseRowSink.toClickHouse(
                family(table), table, column, value, 42));
            assertEquals("Can't write " + table + " row 42 to ClickHouse: its " + column + " " + problem,
                e.getMessage());
        }

        @ParameterizedTest(name = "{0}.{1} = {2}")
        @MethodSource("net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseEndpointsTest#fit")
        @DisplayName("should accept values ClickHouse holds as they are, and NULL where it keeps NULL")
        void fit(String table, String column, Object value) {
            assertDoesNotThrow(() -> ClickHouseRowSink.toClickHouse(family(table), table, column, value, 42));
        }

        @Test
        @DisplayName("should describe an error with the causes CoreProtect wraps it in")
        void describe() {
            SQLException cause = new SQLException("Code: 115. UNKNOWN_SETTING");
            SQLException wrapper = new SQLException("ClickHouse batch publication failed", cause);
            assertEquals("Batch remained incomplete: ClickHouse batch publication failed: Code: 115. UNKNOWN_SETTING",
                ClickHouseRowSink.describe(new SQLException("Batch remained incomplete", wrapper)));
            assertEquals("IllegalStateException", ClickHouseRowSink.describe(new IllegalStateException()));
        }

        private byte[] javaSerialized(Object value) throws IOException {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (ObjectOutputStream output = new ObjectOutputStream(bytes)) {
                output.writeObject(value);
            }
            return bytes.toByteArray();
        }
    }

    static Stream<Arguments> unfit() {
        return Stream.of(
            Arguments.of("chat", "time", null, "is missing, which ClickHouse requires"),
            Arguments.of("chat", "time", -1L, "(-1) is out of range for ClickHouse's UInt32"),
            Arguments.of("chat", "time", 4_294_967_296L, "(4294967296) is out of range for ClickHouse's UInt32"),
            Arguments.of("user", "time", null, "is missing, which ClickHouse requires"),
            Arguments.of("block", "action", 256L, "(256) is out of range for ClickHouse's UInt8"),
            Arguments.of("block", "data", 1.5, "(1.5) isn't a whole number, as ClickHouse's Int64 requires"),
            Arguments.of("block", "x", 2_147_483_648L, "(2147483648) is out of range for ClickHouse's Int32"),
            Arguments.of("block", "wid", -1L, "(-1) is out of range for ClickHouse's UInt32"),
            Arguments.of("block", "user", "Notch", "('Notch') isn't a number, as ClickHouse's UInt32 requires"),
            Arguments.of("block", "type", new byte[]{1}, "(1 bytes of binary data) isn't a number, as ClickHouse's"
                + " UInt32 requires"),
            Arguments.of("sign", "data", 300L, "(300) is out of range for ClickHouse's UInt8"),
            Arguments.of("entity_spawn", "kill_rowid", -1L, "(-1) is out of range for ClickHouse's UInt64"),
            Arguments.of("entity_spawn", "yaw", 1e40, "(1.0E40) is out of range for ClickHouse's Float32"),
            Arguments.of("entity_spawn", "x", "far", "('far') isn't a number"),
            Arguments.of("chat", "message", 5L, "(5) isn't text or binary data"),
            Arguments.of("material_map", "id", -3L, "(-3) is out of range for ClickHouse's UInt32"));
    }

    static Stream<Arguments> fit() {
        return Stream.of(
            Arguments.of("chat", "time", 0L),
            Arguments.of("chat", "time", 4_294_967_295L),
            Arguments.of("chat", "time", 1_700_000_000.0),
            Arguments.of("chat", "user", null),
            Arguments.of("block", "wid", null),
            Arguments.of("block", "x", null),
            Arguments.of("block", "y", null),
            Arguments.of("block", "z", -2_147_483_648L),
            Arguments.of("block", "data", Long.MIN_VALUE),
            Arguments.of("block", "blockdata", new byte[]{0, 1}),
            Arguments.of("block", "meta", null),
            Arguments.of("item", "data", new byte[0]),
            Arguments.of("entity_spawn", "x", -1e300),
            Arguments.of("entity_spawn", "yaw", 90.5),
            Arguments.of("entity_spawn", "block_rowid", 5_000_000_000L),
            Arguments.of("user", "uuid", ""),
            Arguments.of("skull", "skin", null),
            Arguments.of("world", "world", "world_the_end"));
    }

    /**
     * A sink of another engine
     */
    private static final class OtherSink implements RowSink {
        @Override
        public Engine engine() {
            return Engine.SQLITE;
        }

        @Override
        public Optional<String> nonEmptyReason() {
            return Optional.empty();
        }

        @Override
        public void prepare(Map<String, Long> highWater) {
        }

        @Override
        public List<String> columns(String table) {
            return List.of();
        }

        @Override
        public void markIncomplete() {
        }

        @Override
        public void write(String table, List<String> columns, List<Row> rows) {
        }

        @Override
        public void finish(Map<String, Long> highWater) {
        }

        @Override
        public RowSource readBack() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void markComplete() {
        }

        @Override
        public void close() {
        }
    }
}
