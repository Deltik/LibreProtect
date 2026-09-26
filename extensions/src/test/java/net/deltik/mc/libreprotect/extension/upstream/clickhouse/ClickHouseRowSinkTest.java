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

import net.deltik.mc.libreprotect.extension.migration.Row;
import net.deltik.mc.libreprotect.extension.upstream.Designs;
import net.deltik.mc.libreprotect.extension.upstream.Names;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Config;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Family;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Pool;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Target;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.WriteBatch;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;
import net.deltik.mc.libreprotect.testutil.CoreProtectFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLDataException;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseTestServer.located;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Preparing a ClickHouse target. Writing through CoreProtect's writer is in
 * {@link ClickHouseRoundTripTest}.
 */
class ClickHouseRowSinkTest {

    @TempDir
    Path controlDirectory;

    @RegisterExtension
    final CoreProtectFixture coreProtect = new CoreProtectFixture();

    private ClickHouseTestServer server;
    private ClickHouseApi api;
    private String prefix;
    private final RecordingAssignments assignments = new RecordingAssignments();
    private final List<AutoCloseable> closeables = new ArrayList<>();

    @BeforeEach
    void setUp() throws Exception {
        server = ClickHouseTestServer.connect();
        api = server.api();
        prefix = server.newPrefix();
    }

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable closeable : closeables) {
            closeable.close();
        }
        if (server != null) {
            server.close();
        }
    }

    private ClickHouseRowSink sink(String prefix, Path controlDirectory) throws SQLException {
        return sink(server.config(), prefix, controlDirectory);
    }

    private ClickHouseRowSink sink(Config config, String prefix, Path controlDirectory)
        throws SQLException {
        return sink(config, prefix, controlDirectory, assignments, ClickHouseRowSink.PUBLISH_LIMIT);
    }

    private ClickHouseRowSink sink(Config config, String prefix, Path controlDirectory,
                                   IdentifierAssignments identifiers, Duration publishLimit) throws SQLException {
        return sink(config, prefix, controlDirectory, identifiers, publishLimit, ClickHouseTestServer.serverVersion());
    }

    private ClickHouseRowSink sink(Config config, String prefix, Path controlDirectory,
                                   IdentifierAssignments identifiers, Duration publishLimit,
                                   ClickHouseServerVersion serverVersion) throws SQLException {
        ClickHouseRowSink sink = new ClickHouseRowSink(api, config, prefix, controlDirectory, "2.24.1", identifiers,
            new PublishDeadline(publishLimit, () -> false), serverVersion);
        closeables.add(sink);
        return sink;
    }

    @Nested
    @DisplayName("The server's version")
    class Version {

        private long tables() throws SQLException {
            return server.queryLong("SELECT count() FROM system.tables WHERE database = '" + server.database()
                + "' AND startsWith(name, '" + prefix + "')");
        }

        @Test
        @DisplayName("should take a server that CoreProtect's writer takes, and create nothing")
        void taken() throws SQLException {
            server.assumeWriterSupported();

            assertEquals(Optional.empty(), sink(prefix, controlDirectory).unsupportedReason());
            assertEquals(0, tables());
        }

        @Test
        @DisplayName("should refuse a server that the check refuses, saying why, and create nothing")
        void refused() throws SQLException {
            String version = server.queryString("SELECT version()");
            ClickHouseRowSink sink = sink(server.config(), prefix, controlDirectory, assignments,
                ClickHouseRowSink.PUBLISH_LIMIT, ClickHouseServerVersion.checking(connection -> {
                    throw new SQLException("ClickHouse 999.0 or newer is required; found " + version);
                }));

            assertEquals(Optional.of("CoreProtect can't write to this ClickHouse server: ClickHouse 999.0 or newer is"
                + " required; found " + version), sink.unsupportedReason());
            assertEquals(0, tables());
        }
    }

    @Nested
    @DisplayName("Emptiness")
    class Emptiness {

        @Test
        @DisplayName("should find a new namespace empty, without creating anything in it")
        void fresh() throws SQLException {
            assertEquals(Optional.empty(), sink(prefix, controlDirectory).nonEmptyReason());
            assertEquals(0, server.queryLong("SELECT count() FROM system.tables WHERE database = '"
                + server.database() + "' AND startsWith(name, '" + prefix + "')"));
        }

        @Test
        @DisplayName("should find a namespace with only allocator state empty")
        void allocatorState() throws SQLException {
            server.createSchema(prefix, controlDirectory);
            server.insertEvent(prefix, "_batch_receipt", 5, Map.of("wid", 0, "amount", 1));
            server.execute("INSERT INTO " + server.table(prefix, "retention_high_water")
                + " (batch_sequence, family, rowid, recorded_at) VALUES (5, 'block', 900, now64(3))");
            server.execute("INSERT INTO " + server.table(prefix, "identity_reservation")
                + " (sequence, block_start, writer_id) VALUES ('block', 4096, generateUUIDv4()),"
                + " ('batch_sequence', 0, generateUUIDv4())");

            assertEquals(Optional.empty(), sink(prefix, controlDirectory).nonEmptyReason());
        }

        @Test
        @DisplayName("should count rows of CoreProtect's lookup index as data of the tables they index")
        void lookupIndex() throws Exception {
            assumeTrue(Designs.CLICKHOUSE_LOOKUP_INDEX.isIn(Upstream.coreProtect()),
                "needs CoreProtect's ClickHouse lookup index");
            server.createSchema(prefix, controlDirectory);
            // An index row of block row 2 of user 3, without the row, which lookups by player read instead
            Map<String, Object> indexed = located(1_700_000_000L, 3L, 202311, 1, 64, 3);
            indexed.putAll(Map.of("lookup_kind", 1, "lookup_wid", 1, "lookup_x", -5, "lookup_z", 7));
            server.insertEvent(prefix, "_batch_receipt", 2, indexed);

            assertEquals(0, server.queryLong("SELECT count() FROM " + server.table(prefix, "block")));
            UpstreamClass lookups = Upstream.coreProtect().type(Names.CLICKHOUSE_LOOKUP);
            Object byUser = lookups.constructor(String.class, boolean.class, boolean.class, String.class, long.class,
                long.class).create(prefix, false, true, "3", 0L, 0L);
            String found = lookups.method("lookupTable", String.class, String.class, String.class)
                .call(byUser, "block", "");
            assertEquals(1, server.queryLong("SELECT count() FROM " + found), "CoreProtect's lookup of user 3");
            assertEquals(Optional.of("ClickHouse database '" + server.database() + "' already has CoreProtect"
                + " data with table prefix '" + prefix + "' (block lookup index: 1 row). Use a table prefix"
                + " without CoreProtect data, or drop CoreProtect's tables and views with this prefix first."),
                sink(prefix, controlDirectory).nonEmptyReason());
        }

        @Test
        @DisplayName("should count a lookup index that a purge left closed as CoreProtect data, but not once opened")
        void closedLookupIndex() throws Exception {
            assumeTrue(Designs.CLICKHOUSE_LOOKUP_INDEX.isIn(Upstream.coreProtect()),
                "needs CoreProtect's ClickHouse lookup index");
            server.createSchema(prefix, controlDirectory);
            UUID installation = UUID.randomUUID();
            // As a purge does before it deletes anything
            setLookupIndexReady(installation, false);

            assertEquals(Optional.of("ClickHouse database '" + server.database() + "' already has CoreProtect"
                + " data with table prefix '" + prefix + "' (a lookup index that a purge or schema upgrade that"
                + " didn't complete left closed). Use a table prefix without CoreProtect data, or drop CoreProtect's"
                + " tables and views with this prefix first."), sink(prefix, controlDirectory).nonEmptyReason());

            // As the purge does once it completes
            setLookupIndexReady(installation, true);
            assertEquals(Optional.empty(), sink(prefix, controlDirectory).nonEmptyReason());
        }

        /**
         * Close or open the lookup index for an installation, as CoreProtect does
         */
        private void setLookupIndexReady(UUID installation, boolean ready) throws Exception {
            try (Pool pool = api.pool(server.config()); Connection connection = pool.openConnection()) {
                Upstream.coreProtect().type(Names.CLICKHOUSE_LOOKUP_INDEX).staticMethod("setReady", void.class,
                        Connection.class, String.class, UUID.class, boolean.class).throwing(SQLException.class)
                    .call(connection, server.table(prefix, "event_data"), installation, ready);
            }
        }

        @Test
        @DisplayName("should name the tables holding CoreProtect data")
        void data() throws SQLException {
            server.createSchema(prefix, controlDirectory);
            Map<String, Object> chat = located(1_700_000_000L, 1L, 1, 0, 64, 0);
            chat.put("message", "hello");
            server.insertEvent(prefix, "chat", 1, chat);
            server.insertEvent(prefix, "chat", 2, chat);
            server.insertEvent(prefix, "version", 1, Map.of("time", 1L, "version", "2.24.1"));

            assertEquals(Optional.of("ClickHouse database '" + server.database() + "' already has CoreProtect"
                + " data with table prefix '" + prefix + "' (chat: 2 rows, version: 1 row). Use a table prefix"
                + " without CoreProtect data, or drop CoreProtect's tables and views with this prefix first."),
                sink(prefix, controlDirectory).nonEmptyReason());
        }

        @Test
        @DisplayName("should count a server that started without logging anything as CoreProtect data")
        void coreRowsOnly() throws SQLException {
            server.createSchema(prefix, controlDirectory);
            server.insertEvent(prefix, "database_lock", 1, Map.of("time", 1L, "status", 0, "database_lock_time", 1L));

            assertTrue(sink(prefix, controlDirectory).nonEmptyReason().orElseThrow().contains("database_lock: 1 row"));
        }

        @Test
        @DisplayName("should refuse identifier claims left by an earlier installation")
        void claims() throws SQLException {
            server.createSchema(prefix, controlDirectory);
            server.execute("INSERT INTO " + server.table(prefix, "identity_reservation")
                + " (sequence, block_start, writer_id) VALUES ('canonical:material_map:minecraft:stone', 7,"
                + " generateUUIDv4())");

            assertTrue(sink(prefix, controlDirectory).nonEmptyReason().orElseThrow()
                .contains("(1 identifier claim from an earlier installation)"));
        }
    }

    @Nested
    @DisplayName("Preparing")
    class Preparing {

        @Test
        @DisplayName("should create CoreProtect's schema")
        void schema() throws SQLException {
            ClickHouseRowSink sink = sink(prefix, controlDirectory);
            assertThrows(SQLException.class, () -> sink.columns("block"));
            assertThrows(IllegalStateException.class, () -> sink.write("chat", List.of("time"),
                List.of(new Row(1, new Object[]{1L}))));

            sink.prepare(Map.of("block", 10L));

            assertEquals(List.of("time", "user", "wid", "x", "y", "z", "type", "data", "meta", "blockdata", "action",
                "rolled_back"), sink.columns("block"));
            assertEquals(List.of("status", "time"), sink.columns("database_lock"));
            assertEquals(Optional.empty(), sink.nonEmptyReason());
            assertThrows(IllegalStateException.class, () -> sink.prepare(Map.of()));
        }

        @Test
        @DisplayName("should skip version rows and refuse lock rows, which ClickHouse keeps itself")
        void coreTables() throws SQLException {
            ClickHouseRowSink sink = sink(prefix, controlDirectory);
            sink.prepare(Map.of());

            sink.write("version", List.of("time", "version"), List.of(new Row(1, new Object[]{1L, "2.22.0"}),
                new Row(2, new Object[]{2L, "2.24.1"})));

            assertEquals(0, server.queryLong("SELECT count() FROM " + server.table(prefix, "version")));
            assertThrows(IllegalArgumentException.class, () -> sink.write("database_lock", List.of("status", "time"),
                List.of(new Row(1, new Object[]{1L, 1L}))));
            assertThrows(SQLException.class, () -> sink.write("co_block", List.of(), List.of()));
        }

        @Test
        @DisplayName("should report what CoreProtect requires of the database")
        void persistentDatabase(@TempDir Path otherDirectory) throws SQLException {
            String database = prefix + "memory";
            server.execute("CREATE DATABASE " + database + " ENGINE = Memory");
            try {
                ClickHouseRowSink sink = sink(server.config(database), "co_", otherDirectory);
                SQLException e = assertThrows(SQLException.class, () -> sink.prepare(Map.of()));
                assertTrue(e.getMessage().contains("Atomic"), e.getMessage());
            } finally {
                server.execute("DROP DATABASE IF EXISTS " + database + " SYNC");
            }
        }
    }

    @Nested
    @DisplayName("Encoding")
    class Encoding {

        @Test
        @DisplayName("should lay out rows of every table as CoreProtect's writer does")
        void everyTable() throws Exception {
            ClickHouseFixture fixture = new ClickHouseFixture();
            ClickHouseRowSink sink = sink(prefix, controlDirectory);
            sink.prepare(fixture.highWater);

            for (Map.Entry<String, List<Row>> entry : fixture.written.entrySet()) {
                String table = entry.getKey();
                if (table.equals("version")) {
                    continue;
                }
                try (WriteBatch batch = sink.encode(ClickHouseColumns.family(api, table), table,
                    fixture.columns.get(table), entry.getValue())) {
                    assertEquals(entry.getValue().size(), batch.events().size(), table);
                }
            }
        }

        @Test
        @DisplayName("should name the row with a value ClickHouse can't store")
        void unstorable() throws SQLException {
            ClickHouseRowSink sink = sink(prefix, controlDirectory);
            sink.prepare(Map.of());
            List<String> columns = List.of("time", "user", "wid", "x", "y", "z", "action");

            Family session = api.family("session");
            SQLDataException range = assertThrows(SQLDataException.class, () -> sink.encode(session,
                "session", columns, List.of(new Row(1, new Object[]{1L, 1L, 1L, 0L, 64L, 0L, 1L}),
                    new Row(8, new Object[]{1L, 1L, 1L, 0L, 64L, 0L, 300L}))));
            assertTrue(range.getMessage().startsWith("Can't write session row 8 to ClickHouse: "), range.getMessage());
            assertTrue(range.getMessage().contains("300"), range.getMessage());

            SQLDataException type = assertThrows(SQLDataException.class, () -> sink.encode(session,
                "session", columns, List.of(new Row(9, new Object[]{"yesterday", 1L, 1L, 0L, 64L, 0L, 1L}))));
            assertTrue(type.getMessage().startsWith("Can't write session row 9 to ClickHouse: "), type.getMessage());

            assertThrows(IllegalArgumentException.class, () -> sink.encode(session, "session",
                columns, List.of(new Row(10, new Object[]{1L}))));
        }
    }

    @Nested
    @DisplayName("Writes ClickHouse refuses")
    class Refused {

        private static final Duration LIMIT = Duration.ofSeconds(3);

        @AfterEach
        void stopServer() {
            coreProtect.reset();
        }

        /**
         * What happened to a sink call made in another thread
         */
        private record Outcome(Exception failure, boolean interrupted) {
        }

        /**
         * Run a sink call as a migration would while the server runs, where
         * CoreProtect's writer retries refused publications until they succeed
         */
        private Outcome whileServerRuns(SinkCall call) {
            coreProtect.set("ConfigHandler.serverRunning", true);
            return assertTimeoutPreemptively(Duration.ofSeconds(90), () -> {
                Exception failure = null;
                try {
                    call.run();
                } catch (Exception e) {
                    failure = e;
                }
                return new Outcome(failure, Thread.currentThread().isInterrupted());
            }, "the sink kept retrying");
        }

        @Test
        @DisplayName("should fail a write that ClickHouse refuses every time, and write it on retry once accepted")
        void refusedWrite() throws Exception {
            server.assumeWriterSupported();
            ClickHouseRowSink sink = sink(server.config(), prefix, controlDirectory, assignments, LIMIT);
            sink.prepare(Map.of());
            sink.markIncomplete();
            // A refusal that never clears, like an unknown setting, a memory limit or a missing grant
            server.execute("ALTER TABLE " + server.table(prefix, "event_data")
                + " ADD CONSTRAINT lpt_no_chat CHECK family != 'chat'");
            List<String> columns = List.of("time", "user", "wid", "x", "y", "z", "message");
            List<Row> rows = List.of(new Row(1, new Object[]{1_700_000_000L, 1L, 1L, 0L, 64L, 0L, "hello"}));

            Outcome outcome = whileServerRuns(() -> sink.write("chat", columns, rows));

            assertInstanceOf(PublishDeadline.ExpiredException.class, outcome.failure());
            assertTrue(outcome.failure().getMessage().startsWith("Writing the 1 chat rows with row IDs 1 to 1 to"
                + " ClickHouse didn't succeed within 3 seconds of retrying: "), outcome.failure().getMessage());
            assertFalse(outcome.interrupted(), "the interrupt outlived the publication");

            server.execute("ALTER TABLE " + server.table(prefix, "event_data") + " DROP CONSTRAINT lpt_no_chat");
            assertNull(whileServerRuns(() -> sink.write("chat", columns, rows)).failure());
            assertEquals(1, server.queryLong("SELECT count() FROM " + server.table(prefix, "chat")));
        }

        @Test
        @DisplayName("should bound the other publications too")
        void refusedMark() throws Exception {
            server.assumeWriterSupported();
            ClickHouseRowSink sink = sink(server.config(), prefix, controlDirectory, assignments, LIMIT);
            sink.prepare(Map.of());
            server.execute("ALTER TABLE " + server.table(prefix, "event_data")
                + " ADD CONSTRAINT lpt_no_lock CHECK family != 'database_lock'");
            server.execute("ALTER TABLE " + server.table(prefix, "retention_high_water")
                + " ADD CONSTRAINT lpt_no_marks CHECK family != 'chat'");

            Outcome mark = whileServerRuns(sink::markIncomplete);
            Outcome marks = whileServerRuns(() -> sink.finish(Map.of("chat", 900L)));

            assertInstanceOf(PublishDeadline.ExpiredException.class, mark.failure());
            assertTrue(mark.failure().getMessage().startsWith("Writing the incomplete-migration mark to ClickHouse"),
                mark.failure().getMessage());
            assertInstanceOf(PublishDeadline.ExpiredException.class, marks.failure());
            assertTrue(marks.failure().getMessage().startsWith("Writing the row ID high-water marks to ClickHouse"),
                marks.failure().getMessage());
            assertFalse(mark.interrupted() || marks.interrupted(), "the interrupt outlived the publication");
        }
    }

    @FunctionalInterface
    private interface SinkCall {
        void run() throws Exception;
    }

    @Nested
    @DisplayName("The ClickHouse writer of this installation")
    class Writer {

        @Test
        @DisplayName("should allow only one prepared target per data folder, until it's closed")
        void single() throws SQLException {
            ClickHouseRowSink first = sink(prefix, controlDirectory);
            first.prepare(Map.of());
            ClickHouseRowSink second = sink(server.newPrefix(), controlDirectory);

            SQLException e = assertThrows(SQLException.class, () -> second.prepare(Map.of()));
            assertTrue(e.getMessage().contains("already has an active ClickHouse writer"), e.getMessage());

            first.close();
            second.prepare(Map.of());
        }

        @Test
        @DisplayName("should leave a handed-over database open, and registered as the writer, when closed")
        void handOver() throws SQLException {
            ClickHouseRowSink sink = sink(prefix, controlDirectory);
            sink.prepare(Map.of());

            Target prepared = ClickHouseEndpoints.preparedDatabase(sink);
            sink.close();

            try (Connection connection = prepared.openConnection()) {
                assertTrue(connection.isValid(5));
            }
            ClickHouseRowSink other = sink(server.newPrefix(), controlDirectory);
            assertThrows(SQLException.class, () -> other.prepare(Map.of()));
            prepared.close();
            prepared.close();
            other.prepare(Map.of());
        }

        @Test
        @DisplayName("should close the prepared database with the sink unless handed over")
        void closes() throws SQLException {
            ClickHouseRowSink sink = sink(prefix, controlDirectory);
            sink.prepare(Map.of());

            sink.close();

            assertThrows(IllegalStateException.class, () -> ClickHouseEndpoints.preparedDatabase(sink));
            sink(server.newPrefix(), controlDirectory).prepare(Map.of());
        }
    }

    @Nested
    @DisplayName("Identifier maps")
    class IdentifierMaps {

        @Test
        @DisplayName("should raise CoreProtect's counters above the source's map high-water marks when preparing")
        void raiseWhenPreparing() throws SQLException {
            ClickHouseRowSink sink = sink(prefix, controlDirectory);

            sink.prepare(Map.of("material_map", 7L, "world", 2L, "art_map", 0L, "block", 99L));

            assertEquals(Set.of("material_map 7 []", "world 2 []"), new HashSet<>(assignments.calls));
        }

        @Test
        @DisplayName("should keep identifiers CoreProtect assigns during the copy clear of copied map rows")
        void assignedDuringCopy() throws Exception {
            server.assumeWriterSupported();
            try {
                // A MySQL source's material_map after a rolled-back insert: row IDs one ahead of identifiers
                coreProtect.set("ConfigHandler.materialId", 2);
                ClickHouseRowSink sink = sink(server.config(), prefix, controlDirectory,
                    IdentifierAssignments.coreProtect(api), ClickHouseRowSink.PUBLISH_LIMIT);
                sink.prepare(Map.of("material_map", 3L));
                sink.markIncomplete();
                sink.write("material_map", List.of("id", "material"), List.of(
                    new Row(1, new Object[]{1L, "minecraft:stone"}),
                    new Row(3, new Object[]{2L, "minecraft:dirt"})));
                // A new block type logged during the copy, as CoreProtect assigns it on SQLite and MySQL
                int assigned;
                synchronized (configHandler()) {
                    assigned = (int) coreProtect.get("ConfigHandler.materialId") + 1;
                    materialsReversed().put(assigned, "lpt:new_block");
                    coreProtect.set("ConfigHandler.materialId", assigned);
                }

                assertEquals(4, assigned, "above the source's high-water mark 3, not the copied row ID 3");
                assertDoesNotThrow(() -> sink.finish(Map.of("material_map", 3L)));
            } finally {
                materialsReversed().values().remove("lpt:new_block");
            }
        }

        @Test
        @DisplayName("should raise CoreProtect's counters above copied row IDs that are free as identifiers")
        void raise() throws SQLException {
            ClickHouseRowSink sink = sink(prefix, controlDirectory);
            sink.prepare(Map.of());
            // Row IDs that ran ahead of the identifiers, as MySQL's can
            map("material_map", 1, 1, "minecraft:stone");
            map("material_map", 5, 2, "minecraft:dirt");
            map("material_map", 6, 4, "minecraft:sand");
            map("world", 1, 1, "world");

            sink.guardIdentifierMaps();

            assertEquals(List.of("art_map 0 []", "entity_map 0 []", "material_map 6 [5, 6]", "blockdata_map 0 []",
                "world 1 []"), assignments.calls);
        }

        @Test
        @DisplayName("should refuse when CoreProtect assigned one of those IDs during the migration")
        void conflict() throws SQLException {
            ClickHouseRowSink sink = sink(prefix, controlDirectory);
            sink.prepare(Map.of());
            map("material_map", 1, 1, "minecraft:stone");
            map("material_map", 5, 2, "minecraft:dirt");
            map("blockdata_map", 9, 3, "minecraft:oak_log[axis=y]");
            assignments.assigned.add("material_map 5");
            assignments.assigned.add("blockdata_map 9");

            SQLException e = assertThrows(SQLException.class, sink::guardIdentifierMaps);
            assertEquals("CoreProtect assigned new identifiers during the migration (material_map 5, blockdata_map 9)"
                + " that equal the row IDs of copied rows with other identifiers, which ClickHouse would overwrite."
                + " Clear the ClickHouse target and migrate again.", e.getMessage());
        }

        private void map(String table, long rowId, int id, String name) throws SQLException {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("time", 0);
            row.put("id", id);
            row.put(table.equals("blockdata_map") ? "text" : "name", name);
            server.insertEvent(prefix, table, rowId, row);
        }
    }

    @Test
    @DisplayName("should raise CoreProtect's own identifier counters and find its assignments")
    void coreProtectAssignments() {
        IdentifierAssignments caches = IdentifierAssignments.coreProtect(api);
        int before = (int) coreProtect.get("ConfigHandler.materialId");
        coreProtect.set("ConfigHandler.materialId", before);
        materialsReversed().put(before + 3, "minecraft:test");
        try {
            assertEquals(List.of((long) before + 3),
                caches.raiseAndFindAssigned(api.family("material_map"), before + 5,
                    List.of((long) before + 3, (long) before + 4)));
            assertEquals(before + 5, coreProtect.get("ConfigHandler.materialId"));
            caches.raiseAndFindAssigned(api.family("material_map"), before + 1, List.of());
            assertEquals(before + 5, coreProtect.get("ConfigHandler.materialId"), "never lowered");
            assertThrows(IllegalArgumentException.class,
                () -> caches.raiseAndFindAssigned(api.family("user"), 1, List.of()));
        } finally {
            materialsReversed().remove(before + 3);
        }
    }

    /**
     * @return the class whose lock CoreProtect assigns identifiers under
     */
    private static Object configHandler() throws Exception {
        return Upstream.coreProtect().type(Names.CONFIG_HANDLER).type();
    }

    @SuppressWarnings("unchecked")
    private Map<Integer, String> materialsReversed() {
        return (Map<Integer, String>) coreProtect.get("ConfigHandler.materialsReversed");
    }

    /**
     * Records what the sink asks of CoreProtect's identifier caches
     */
    static final class RecordingAssignments implements IdentifierAssignments {
        final List<String> calls = new ArrayList<>();
        final Set<String> assigned = new HashSet<>();

        @Override
        public List<Long> raiseAndFindAssigned(Family map, long floor, List<Long> candidates) {
            calls.add(map.tableName() + " " + floor + " " + candidates);
            List<Long> found = new ArrayList<>();
            for (Long candidate : candidates) {
                if (assigned.contains(map.tableName() + " " + candidate)) {
                    found.add(candidate);
                }
            }
            return found;
        }
    }
}
