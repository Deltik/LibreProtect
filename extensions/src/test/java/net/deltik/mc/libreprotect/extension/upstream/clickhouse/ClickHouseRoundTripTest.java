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
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import net.deltik.mc.libreprotect.extension.upstream.Designs;
import net.deltik.mc.libreprotect.extension.upstream.Names;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Target;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.WriteBatch;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Creator;
import net.deltik.mc.libreprotect.extension.upstream.reflect.InstanceMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;
import net.deltik.mc.libreprotect.testutil.CoreProtectFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;

import static net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseFixture.BLOCK_HIGH_WATER;
import static net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseFixture.CHAT_HIGH_WATER;
import static net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseFixture.CORE_VERSION;
import static net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseFixture.USER_HIGH_WATER;
import static net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseFixture.stats;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Relational rows through the ClickHouse sink, into CoreProtect's ClickHouse
 * storage, and back out through the ClickHouse source, as a migration to
 * ClickHouse and validation of it do. Needs a server that CoreProtect's
 * ClickHouse writer can publish to.
 */
class ClickHouseRoundTripTest {

    @TempDir
    Path controlDirectory;

    @RegisterExtension
    final CoreProtectFixture coreProtect = new CoreProtectFixture();

    private ClickHouseTestServer server;
    private ClickHouseApi api;
    private String prefix;
    private final ClickHouseRowSinkTest.RecordingAssignments assignments =
        new ClickHouseRowSinkTest.RecordingAssignments();
    private final List<AutoCloseable> closeables = new ArrayList<>();
    private ClickHouseFixture fixture;

    @BeforeEach
    void setUp() throws Exception {
        server = ClickHouseTestServer.connect();
        server.assumeWriterSupported();
        api = server.api();
        prefix = server.newPrefix();
        fixture = new ClickHouseFixture();
    }

    @AfterEach
    void tearDown() throws Exception {
        Collections.reverse(closeables);
        for (AutoCloseable closeable : closeables) {
            closeable.close();
        }
        if (server != null) {
            server.close();
        }
    }

    @Test
    @DisplayName("should read back every row with its row ID, in CoreProtect's ClickHouse encodings")
    void rows() throws Exception {
        ClickHouseRowSink sink = migrate();
        RowSource readBack = sink.readBack();

        assertEquals(21, readBack.tables().size());
        for (String table : fixture.expected.keySet()) {
            List<String> columns = fixture.columns.get(table);
            assertEquals(columns, readBack.columns(table), table);
            List<Row> expected = fixture.expected.get(table);
            List<Row> actual = new ArrayList<>();
            List<Row> page;
            long after = 0;
            while (!(page = readBack.read(table, columns, after, 2)).isEmpty()) {
                actual.addAll(page);
                after = page.get(page.size() - 1).rowId();
            }
            assertRows(table, expected, actual);
            assertEquals(stats(expected), readBack.stats(table), table);
            Row first = expected.get(0);
            assertRows(table, List.of(first), readBack.readRange(table, columns, first.rowId(), first.rowId()));
        }
    }

    @Test
    @DisplayName("should keep the source's high-water marks, so CoreProtect's next IDs continue after them")
    void highWater() throws Exception {
        ClickHouseRowSink sink = migrate();
        RowSource readBack = sink.readBack();

        assertEquals(OptionalLong.of(BLOCK_HIGH_WATER), readBack.highWater("block"));
        assertEquals(OptionalLong.of(CHAT_HIGH_WATER), readBack.highWater("chat"));
        assertEquals(OptionalLong.of(USER_HIGH_WATER), readBack.highWater("user"));
        assertEquals(OptionalLong.of(stats(fixture.expected.get("sign")).maxRowId()), readBack.highWater("sign"));
        assertEquals(OptionalLong.of(1), readBack.highWater("version"));

        sink.markComplete();
        Target activated = ClickHouseEndpoints.preparedDatabase(sink);
        sink.close();
        long chat;
        long block;
        try (WriteBatch batch = activated.newWriteBatch()) {
            chat = addChat(batch, 1_700_000_500, "after activation");
            block = (long) events().method("addBlock", long.class, int.class, int.class, int.class, int.class,
                int.class, int.class, int.class, int.class, byte[].class, byte[].class, int.class, int.class)
                .throwing(SQLException.class)
                .call(batch.events().upstream(), 1_700_000_500, 1, 1, 0, 64, 0, 1, 0, null, null, 0, 0);
            activated.publish(batch);
        }
        activated.close();
        assertTrue(chat > CHAT_HIGH_WATER, "chat row ID " + chat);
        assertTrue(block > BLOCK_HIGH_WATER, "block row ID " + block);

        // And after a restart
        try (Target restarted = api.initialize(server.config(), prefix, controlDirectory);
             WriteBatch batch = restarted.newWriteBatch()) {
            long next = addChat(batch, 1_700_000_501, "after a restart");
            restarted.publish(batch);
            assertTrue(next > chat, "chat row ID " + next + " after " + chat);
        }
    }

    @Test
    @DisplayName("should keep only CoreProtect's current version")
    void version() throws Exception {
        ClickHouseRowSink sink = migrate();

        List<Row> versions = sink.readBack().read("version", List.of("time", "version"), 0, 10);

        assertEquals(1, versions.size());
        assertEquals(1, versions.get(0).rowId());
        assertEquals(CORE_VERSION, versions.get(0).values()[1]);
    }

    @Test
    @DisplayName("should mark the target as an incomplete migration until it's complete")
    void marker() throws Exception {
        String marker = "SELECT count() FROM " + server.table(prefix, "database_lock") + " WHERE rowid = 1 AND status = 2";
        ClickHouseRowSink sink = migrate();
        assertEquals(1, server.queryLong(marker));

        sink.markComplete();

        assertEquals(0, server.queryLong(marker));
        assertEquals(1, server.queryLong("SELECT count() FROM " + server.table(prefix, "database_lock")));
        assertTrue(sink.nonEmptyReason().isPresent());
    }

    @Test
    @DisplayName("should keep the identifiers CoreProtect assigns from now on clear of copied map rows")
    void identifiers() throws Exception {
        migrate();

        assertTrue(assignments.calls.contains("material_map 7 [7]"), assignments.calls.toString());
        assertTrue(assignments.calls.contains("world 2 []"), assignments.calls.toString());
    }

    @Test
    @DisplayName("should write a failed batch again, not a second copy, when the write is retried")
    void retry() throws Exception {
        ClickHouseRowSink sink = sink();
        sink.prepare(fixture.highWater);
        sink.markIncomplete();
        List<String> columns = fixture.columns.get("chat");
        List<Row> rows = fixture.written.get("chat");
        String events = server.table(prefix, "event_data");
        // So CoreProtect's writer gives up after a few attempts, as it does when the server isn't running
        coreProtect.set("ConfigHandler.serverRunning", false).set("ConfigHandler.shutdownDrainRunning", false);

        server.execute("DETACH TABLE " + events);
        try {
            assertThrows(SQLException.class, () -> sink.write("chat", columns, rows));
            assertThrows(IllegalStateException.class,
                () -> sink.write("block", fixture.columns.get("block"), fixture.written.get("block")));
        } finally {
            server.execute("ATTACH TABLE " + events);
        }
        sink.write("chat", columns, rows);

        assertEquals(rows.size(), server.queryLong("SELECT count() FROM " + server.table(prefix, "chat")));
        assertEquals(1, server.queryLong("SELECT uniqExact(batch_sequence) FROM " + events + " WHERE family = 'chat'"));
        assertEquals(server.queryLong("SELECT max(batch_sequence) FROM " + events + " WHERE family = 'database_lock'")
            + 1, server.queryLong("SELECT any(batch_sequence) FROM " + events + " WHERE family = 'chat'"),
            "the batch encoded for the failed write");
    }

    @Test
    @DisplayName("should index migrated rows for CoreProtect's lookups")
    void lookupIndex() throws Exception {
        Upstream upstream = Upstream.coreProtect();
        assumeTrue(Designs.CLICKHOUSE_LOOKUP_INDEX.isIn(upstream), "needs CoreProtect's ClickHouse lookup index");
        migrate();
        int writeVersion = upstream.type(Names.CLICKHOUSE_SCHEMA).intConstant("VERSION").getAsInt();

        assertEquals(0, server.queryLong("SELECT countIf(write_version != " + writeVersion + ") FROM "
            + server.table(prefix, "event_data")), "rows without CoreProtect's write version " + writeVersion);
        // What CoreProtect's lookups count and page through, which read the index
        UpstreamClass lookups = upstream.type(Names.CLICKHOUSE_LOOKUP);
        Creator lookup = lookups.constructor(String.class, boolean.class, boolean.class, String.class, long.class,
            long.class);
        InstanceMethod<String, RuntimeException> lookupTable = lookups.method("lookupTable", String.class,
            String.class, String.class);
        String rows = "SELECT toString(arraySort(groupArray(tuple(rowid, time, `user`, wid, x, y, z, type, action,"
            + " rolled_back, _key_time, _key_wid, _key_x, _key_z)))) FROM ";
        for (String table : List.of("block", "container", "entity_container", "item", "entity_interaction")) {
            String view = server.table(prefix, table);
            String all = lookupTable.call(lookup.create(prefix, false, true, "", 0L, 0L), table, "");
            assertNotEquals(prefix + table, all, table + " lookups don't read the index");
            assertEquals(fixture.expected.get(table).size(), server.queryLong("SELECT count() FROM " + view), table);
            assertEquals(server.queryString(rows + view), server.queryString(rows + all), table);

            long user = server.queryLong("SELECT min(`user`) FROM " + view);
            String by = lookupTable.call(lookup.create(prefix, false, true, String.valueOf(user), 0L, 0L), table, "");
            assertEquals(server.queryString(rows + view + " WHERE `user` = " + user),
                server.queryString(rows + by), table + " of user " + user);
        }
    }

    private ClickHouseRowSink sink() throws SQLException {
        ClickHouseRowSink sink = new ClickHouseRowSink(api, server.config(), prefix, controlDirectory, CORE_VERSION,
            assignments, new PublishDeadline(ClickHouseRowSink.PUBLISH_LIMIT, () -> false));
        closeables.add(sink);
        return sink;
    }

    /**
     * @return CoreProtect's {@code ClickHouseEventBatch}, for logging events
     *         the way CoreProtect does, with row IDs it allocates
     */
    private static UpstreamClass events() throws Exception {
        return Upstream.coreProtect().type(Names.CLICKHOUSE_EVENT_BATCH);
    }

    /**
     * @return the row ID that CoreProtect allocated for a chat message it logged
     */
    private static long addChat(WriteBatch batch, int time, String message) throws Exception {
        return (long) events().method("addChat", long.class, int.class, int.class, int.class, int.class, int.class,
            int.class, String.class).throwing(SQLException.class)
            .call(batch.events().upstream(), time, 1, 1, 0, 64, 0, message);
    }

    /**
     * What a migration does with the target, up to activation
     */
    private ClickHouseRowSink migrate() throws SQLException {
        ClickHouseRowSink sink = sink();
        assertEquals(Optional.empty(), sink.nonEmptyReason());
        sink.prepare(fixture.highWater);
        sink.markIncomplete();
        for (Map.Entry<String, List<Row>> entry : fixture.written.entrySet()) {
            String table = entry.getKey();
            List<String> columns = fixture.columns.get(table);
            List<Row> rows = entry.getValue();
            if (table.equals("block")) {
                // In the source's column order, which may differ
                List<String> reversed = new ArrayList<>(columns);
                Collections.reverse(reversed);
                List<Row> reversedRows = new ArrayList<>();
                for (Row row : rows) {
                    List<Object> values = new ArrayList<>(Arrays.asList(row.values()));
                    Collections.reverse(values);
                    reversedRows.add(new Row(row.rowId(), values.toArray()));
                }
                sink.write(table, reversed, reversedRows);
                continue;
            }
            // In two batches
            int half = rows.size() / 2;
            sink.write(table, columns, rows.subList(0, half));
            sink.write(table, columns, rows.subList(half, rows.size()));
        }
        sink.finish(fixture.highWater);
        return sink;
    }

    private static void assertRows(String table, List<Row> expected, List<Row> actual) {
        assertEquals(expected.size(), actual.size(), table + " rows");
        for (int index = 0; index < expected.size(); index++) {
            Row want = expected.get(index);
            Row got = actual.get(index);
            assertEquals(want.rowId(), got.rowId(), table + " row IDs");
            assertTrue(Arrays.deepEquals(want.values(), got.values()),
                table + " row " + want.rowId() + ": expected " + want + " but was " + got);
        }
    }
}
