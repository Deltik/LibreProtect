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
import net.deltik.mc.libreprotect.extension.migration.TableStats;
import net.deltik.mc.libreprotect.extension.upstream.Names;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Target;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;

import static net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseTestServer.located;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Reading CoreProtect's ClickHouse tables, from rows laid out in the event
 * table the way CoreProtect's writer lays them out, with only what
 * {@link ClickHouseApi#READS} offers.
 */
class ClickHouseRowSourceTest {

    private static final List<String> BLOCK_COLUMNS = List.of("time", "user", "wid", "x", "y", "z", "type", "data",
        "meta", "blockdata", "action", "rolled_back");

    @TempDir
    Path controlDirectory;

    private ClickHouseTestServer server;
    private ClickHouseApi reads;
    private String prefix;
    private ClickHouseRowSource source;

    @BeforeEach
    void setUp() throws Exception {
        reads = ClickHouseTestServer.reads();
        server = ClickHouseTestServer.connect();
        prefix = server.newPrefix();
        server.createSchema(prefix, controlDirectory);
        source = new ClickHouseRowSource(reads, server.config(), prefix);
    }

    @AfterEach
    void tearDown() throws SQLException {
        if (source != null) {
            source.close();
        }
        if (server != null) {
            server.close();
        }
    }

    @Nested
    @DisplayName("Tables and columns")
    class Tables {

        @Test
        @DisplayName("should list CoreProtect's 21 tables")
        void tables() throws Exception {
            // CoreProtect's own list, not the facade's
            Class<?> families = Class.forName(Names.CLICKHOUSE_FAMILY);
            List<String> expected = new ArrayList<>();
            for (Object family : families.getEnumConstants()) {
                expected.add((String) families.getMethod("getTableName").invoke(family));
            }
            assertEquals(expected, source.tables());
            assertEquals(21, expected.size());
        }

        @Test
        @DisplayName("should list a table's CoreProtect columns without the row ID or lookup keys")
        void columns() throws SQLException {
            assertEquals(BLOCK_COLUMNS, source.columns("block"));
            assertEquals(List.of("time", "block_rowid", "kill_rowid", "uuid", "wid", "current_wid", "origin_x",
                "origin_y", "origin_z", "x", "y", "z", "yaw", "pitch", "data", "removed"), source.columns("entity_spawn"));
            assertEquals(List.of("time", "user", "uuid"), source.columns("user"));
            assertEquals(List.of("id", "data"), source.columns("blockdata_map"));
        }

        @Test
        @DisplayName("should refuse tables that don't exist")
        void missing() throws Exception {
            assertThrows(SQLException.class, () -> source.columns("nonsense"));
            try (ClickHouseRowSource empty = new ClickHouseRowSource(reads, server.config(), server.newPrefix())) {
                assertEquals(List.of(), empty.tables());
                assertThrows(SQLException.class, () -> empty.columns("block"));
            }
        }
    }

    @Nested
    @DisplayName("Rows")
    class Rows {

        @Test
        @DisplayName("should read the current version of each row, with exact binary data and normalized values")
        void currentVersion() throws SQLException {
            byte[] meta = {0, -1, 65};
            Map<String, Object> rolledBack = block(1_700_000_000L, 3L, 1, -5, 64, 7, meta, "1,2".getBytes());
            server.insertEvent(prefix, "block", 2, rolledBack);
            Map<String, Object> high = block(1_700_000_100L, 4L, 1, 10, null, 11, null, new byte[0]);
            server.insertEvent(prefix, "block", 5_000_000_000L, high);
            // A rollback, as CoreProtect records it: the same key, only rolled_back set
            Map<String, Object> rollback = new LinkedHashMap<>();
            rollback.put("time", 1_700_000_000L);
            rollback.put("wid", 1);
            rollback.put("x", -5);
            rollback.put("z", 7);
            rollback.put("rolled_back", 1);
            server.insertEvent(prefix, "block", 2, rollback);

            List<Row> rows = source.read("block", BLOCK_COLUMNS, 0, 10);

            assertEquals(2, rows.size());
            assertEquals(2, rows.get(0).rowId());
            assertArrayEquals(new Object[]{1_700_000_000L, 3L, 1L, -5L, 64L, 7L, 12L, -9L, meta, "1,2".getBytes(),
                1L, 1L}, rows.get(0).values());
            assertEquals(5_000_000_000L, rows.get(1).rowId());
            assertArrayEquals(new Object[]{1_700_000_100L, 4L, 1L, 10L, null, 11L, 12L, -9L, null, new byte[0],
                1L, 0L}, rows.get(1).values());
            assertEquals(new TableStats(2, 2, 5_000_000_000L), source.stats("block"));
        }

        @Test
        @DisplayName("should read locations CoreProtect didn't record as NULL")
        void noLocation() throws SQLException {
            Map<String, Object> command = located(1_700_000_000L, 9L, null, null, null, null);
            command.put("message", "/say \"hi\" 'there' \\ ☃");
            server.insertEvent(prefix, "command", 4, command);

            Row row = source.read("command", source.columns("command"), 0, 10).get(0);

            assertArrayEquals(new Object[]{1_700_000_000L, 9L, null, null, null, null, "/say \"hi\" 'there' \\ ☃"},
                row.values());
        }

        @Test
        @DisplayName("should read the current user version, and a missing UUID as none")
        void users() throws SQLException {
            server.insertEvent(prefix, "user", 1, user(1_600_000_000L, "Notch", "069a79f4-44e9-4726-a5be-fca90e38aaf5"));
            server.insertEvent(prefix, "user", 2, user(1_600_000_001L, "#fire", null));
            server.insertEvent(prefix, "user", 1, user(1_600_000_002L, "Nötch", null));

            List<Row> rows = source.read("user", List.of("time", "user", "uuid"), 0, 10);

            assertEquals(2, rows.size());
            assertArrayEquals(new Object[]{1_600_000_002L, "Nötch", "069a79f4-44e9-4726-a5be-fca90e38aaf5"},
                rows.get(0).values());
            assertArrayEquals(new Object[]{1_600_000_001L, "#fire", null}, rows.get(1).values());
        }

        @Test
        @DisplayName("should read entity spawns with Float32 widened like the other engines' floats")
        void entitySpawns() throws Exception {
            byte[] data = new UpstreamCodecs().encodeEntity("ENTITY_SPAWN", List.of("minecraft:cow", 7));
            server.insertEvent(prefix, "entity_spawn", 3, spawn(3L, 7L, "uuid-a", data, 0.1));
            server.insertEvent(prefix, "entity_spawn", 4, spawn(null, null, "uuid-b", null, -12.25));

            List<Row> rows = source.read("entity_spawn", source.columns("entity_spawn"), 0, 10);

            assertArrayEquals(new Object[]{1_700_000_000L, 3L, 7L, "uuid-a", 1L, 2L, 1.5, 64.0, -3.5, 1.25, 65.0,
                -3.75, (double) 0.1f, (double) 0.1f, data, 0L}, rows.get(0).values());
            assertArrayEquals(new Object[]{1_700_000_000L, null, null, "uuid-b", 1L, 2L, 1.5, 64.0, -3.5, 1.25, 65.0,
                -3.75, -12.25, -12.25, null, 0L}, rows.get(1).values());
        }

        @Test
        @DisplayName("should read the singleton version and lock rows")
        void singletons() throws SQLException {
            server.insertEvent(prefix, "version", 1, Map.of("time", 1_600_000_000L, "version", "2.24.1"));
            server.insertEvent(prefix, "database_lock", 1, Map.of("time", 5L, "status", 2, "database_lock_time", 5L));

            assertArrayEquals(new Object[]{1_600_000_000L, "2.24.1"},
                source.read("version", List.of("time", "version"), 0, 10).get(0).values());
            assertArrayEquals(new Object[]{2L, 5L},
                source.read("database_lock", source.columns("database_lock"), 0, 10).get(0).values());
        }

        @Test
        @DisplayName("should report an empty table")
        void empty() throws SQLException {
            assertEquals(new TableStats(0, 0, 0), source.stats("art_map"));
            assertEquals(List.of(), source.read("art_map", List.of("id", "art"), 0, 10));
            assertEquals(OptionalLong.of(0), source.highWater("art_map"));
        }
    }

    @Nested
    @DisplayName("Reading in row ID order")
    class Order {

        @Test
        @DisplayName("should continue one query across calls, and read ranges and other starts separately")
        void paging() throws SQLException {
            for (long rowId = 1; rowId <= 25; rowId++) {
                // Scattered over locations, so ClickHouse's order isn't row ID order
                Map<String, Object> chat = located(1_700_000_000L + (rowId % 7), 1L, 1, (int) (rowId * 37 % 11), 64, 0);
                chat.put("message", "message " + rowId);
                server.insertEvent(prefix, "chat", rowId * 2, chat);
            }
            List<String> columns = source.columns("chat");

            List<Row> first = source.read("chat", columns, 0, 10);
            List<Row> range = source.readRange("chat", columns, 11, 20);
            List<Row> second = source.read("chat", columns, first.get(9).rowId(), 10);
            List<Row> restart = source.read("chat", columns, 30, 10);
            List<Row> third = source.read("chat", columns, second.get(9).rowId(), 10);

            assertEquals(List.of(12L, 14L, 16L, 18L, 20L), rowIds(range));
            List<Long> all = new ArrayList<>(rowIds(first));
            all.addAll(rowIds(second));
            all.addAll(rowIds(third));
            List<Long> expected = new ArrayList<>();
            for (long rowId = 1; rowId <= 25; rowId++) {
                expected.add(rowId * 2);
            }
            assertEquals(expected, all);
            assertEquals(List.of(32L, 34L, 36L, 38L, 40L, 42L, 44L, 46L, 48L, 50L), rowIds(restart));
            assertEquals("message 1", first.get(0).values()[6]);
            server.execute("SYSTEM FLUSH LOGS");
            assertEquals(3, server.queryLong("SELECT count() FROM system.query_log WHERE type = 'QueryStart'"
                + " AND query LIKE '%" + prefix + "chat` WHERE rowid >= %ORDER BY rowid' AND query NOT LIKE '%system.%'"),
                "one query for the first two pages, and one each for the other starts");
            assertEquals(List.of(), source.read("chat", columns, 50, 10));
        }

        @Test
        @DisplayName("should read many ranges with one scan of the table per thousand ranges")
        void ranges() throws SQLException {
            for (long rowId = 1; rowId <= 25; rowId++) {
                Map<String, Object> chat = located(1_700_000_000L + (rowId % 7), 1L, 1, (int) (rowId * 37 % 11), 64, 0);
                chat.put("message", "message " + rowId);
                server.insertEvent(prefix, "chat", rowId * 2, chat);
            }
            List<String> columns = source.columns("chat");
            List<long[]> single = new ArrayList<>();
            List<Long> all = new ArrayList<>();
            for (long rowId = 1; rowId <= 1500; rowId++) {
                single.add(new long[]{rowId, rowId});
                if (rowId % 2 == 0 && rowId <= 50) {
                    all.add(rowId);
                }
            }
            String ranges = "query LIKE '%" + prefix + "chat%rowid >= %' AND query NOT LIKE '%system.%'";

            assertEquals(List.of(2L, 4L, 12L, 14L, 16L, 18L, 20L, 46L, 48L, 50L), rowIds(source.readRanges("chat",
                columns, List.of(new long[]{1, 4}, new long[]{11, 20}, new long[]{45, 1000}))));
            assertEquals(all, rowIds(source.readRanges("chat", columns, single)));
            assertEquals(List.of(), source.readRanges("chat", columns, List.of()));
            server.execute("SYSTEM FLUSH LOGS");
            assertEquals(3, server.queryLong("SELECT count() FROM system.query_log WHERE type = 'QueryStart' AND "
                + ranges), "one query for three ranges, two for 1,500");
        }

        @Test
        @DisplayName("should pick up where it was when the server ends the query")
        void resume() throws Exception {
            // Incompressible, so the server is still sending when the query is killed
            server.insertRandomChat(prefix, 200_000);
            List<String> columns = source.columns("chat");
            String streaming = "query LIKE '%" + prefix + "chat` WHERE rowid >= %ORDER BY rowid'"
                + " AND query NOT LIKE '%system.%' AND query NOT LIKE '%KILL%'";

            List<Row> rows = new ArrayList<>(source.read("chat", columns, 0, 1000));
            assertEquals(1, server.queryLong("SELECT count() FROM system.processes WHERE " + streaming),
                "the query streaming the table is running");
            // The kill only takes effect as the server gets to send again, so keep reading meanwhile
            List<Exception> killFailures = new ArrayList<>();
            Thread kill = new Thread(() -> {
                try {
                    server.execute("KILL QUERY WHERE " + streaming + " SYNC");
                } catch (SQLException e) {
                    killFailures.add(e);
                }
            });
            kill.start();
            Thread.sleep(500);
            long last = rows.get(rows.size() - 1).rowId();
            List<Row> page;
            while (!(page = source.read("chat", columns, last, 50_000)).isEmpty()) {
                rows.addAll(page);
                last = page.get(page.size() - 1).rowId();
            }
            kill.join();

            assertEquals(List.of(), killFailures);
            assertEquals(200_000, rows.size());
            for (int index = 0; index < rows.size(); index++) {
                assertEquals(index + 1, rows.get(index).rowId());
            }
            server.execute("SYSTEM FLUSH LOGS");
            // The killed query, the one resuming it, and the one finding nothing after the last row
            assertEquals(3, server.queryLong("SELECT count() FROM system.query_log WHERE type = 'QueryStart' AND "
                + streaming), "the source resumed the killed query once");
        }

        @Test
        @DisplayName("should refuse a table where rows share a row ID")
        void duplicateRowIds() throws SQLException {
            Map<String, Object> chat = located(1_700_000_000L, 1L, 1, 0, 64, 0);
            chat.put("message", "one");
            server.insertEvent(prefix, "chat", 5, chat);
            chat = located(1_700_000_001L, 1L, 1, 0, 64, 0);
            chat.put("message", "two");
            server.insertEvent(prefix, "chat", 5, chat);

            SQLException e = assertThrows(SQLIntegrityConstraintViolationException.class,
                () -> source.read("chat", source.columns("chat"), 0, 10));
            assertTrue(e.getMessage().contains("row ID 5"), e.getMessage());
            assertThrows(SQLIntegrityConstraintViolationException.class,
                () -> source.readRange("chat", source.columns("chat"), 1, 10));
        }

        @Test
        @DisplayName("should not skip a row that failed to read when asked for the same rows again")
        void retryAfterBadRow() throws SQLException {
            chats(new Object[][]{{1L, "a"}, {5L, "one"}, {5L, "two"}, {7L, "b"}});
            List<String> columns = source.columns("chat");
            List<Row> first = source.read("chat", columns, 0, 2);
            assertEquals(5, first.get(1).rowId());

            assertThrows(SQLIntegrityConstraintViolationException.class, () -> source.read("chat", columns, 5, 10));
            assertThrows(SQLIntegrityConstraintViolationException.class, () -> source.read("chat", columns, 5, 10),
                "the retry read on past the second row with row ID 5");
        }

        @Test
        @DisplayName("should refuse rows sharing the row ID where a page ends, even in a new query")
        void duplicateAtPageEnd() throws SQLException {
            chats(new Object[][]{{1L, "a"}, {5L, "one"}, {5L, "two"}, {7L, "b"}});
            List<String> columns = source.columns("chat");
            assertEquals(5, source.read("chat", columns, 0, 2).get(1).rowId());

            try (ClickHouseRowSource other = new ClickHouseRowSource(reads, server.config(), prefix)) {
                SQLException e = assertThrows(SQLIntegrityConstraintViolationException.class,
                    () -> other.read("chat", columns, 5, 10));
                assertTrue(e.getMessage().contains("row ID 5"), e.getMessage());
            }
        }

        private void chats(Object[][] chats) throws SQLException {
            int second = 0;
            for (Object[] chat : chats) {
                Map<String, Object> row = located(1_700_000_000L + second++, 1L, 1, 0, 64, 0);
                row.put("message", chat[1]);
                server.insertEvent(prefix, "chat", (Long) chat[0], row);
            }
        }
    }


    @Nested
    @DisplayName("Entity spawns the other engines can't store")
    class Uniqueness {

        @Test
        @DisplayName("should name duplicate UUIDs and kill row IDs before copying")
        void duplicates() throws SQLException {
            server.insertEvent(prefix, "entity_spawn", 3, spawn(null, 7L, "uuid-a", null, 0));
            server.insertEvent(prefix, "entity_spawn", 9, spawn(null, 8L, "uuid-a", null, 0));
            server.insertEvent(prefix, "entity_spawn", 11, spawn(null, 8L, "uuid-c", null, 0));
            server.insertEvent(prefix, "entity_spawn", 12, spawn(null, null, "uuid-d", null, 0));
            server.insertEvent(prefix, "entity_spawn", 13, spawn(null, null, "uuid-e", null, 0));

            SQLException e = assertThrows(SQLIntegrityConstraintViolationException.class,
                () -> source.stats("entity_spawn"));
            assertEquals("ClickHouse table entity_spawn can't be copied: SQLite, MySQL and DuckDB require each"
                + " entity's UUID and kill row ID to be unique, but 1 UUID appears in more than one row (e.g. uuid-a"
                + " in rows 3, 9) and 1 kill row ID appears in more than one row (e.g. 8 in rows 9, 11). Resolve the"
                + " duplicates in ClickHouse before migrating.", e.getMessage());
            assertThrows(SQLIntegrityConstraintViolationException.class,
                () -> source.read("entity_spawn", source.columns("entity_spawn"), 0, 10));
            assertThrows(SQLIntegrityConstraintViolationException.class,
                () -> source.readRange("entity_spawn", source.columns("entity_spawn"), 0, 10));
        }

        @Test
        @DisplayName("should allow any number of entities without a kill row")
        void unique() throws SQLException {
            server.insertEvent(prefix, "entity_spawn", 3, spawn(null, null, "uuid-a", null, 0));
            server.insertEvent(prefix, "entity_spawn", 4, spawn(null, null, "uuid-b", null, 0));

            assertEquals(new TableStats(2, 3, 4), source.stats("entity_spawn"));
        }
    }

    @Nested
    @DisplayName("High-water marks")
    class HighWater {

        @Test
        @DisplayName("should include row IDs of purged rows that ClickHouse recorded")
        void purged() throws SQLException {
            Map<String, Object> chat = located(1_700_000_000L, 1L, 1, 0, 64, 0);
            chat.put("message", "kept");
            server.insertEvent(prefix, "chat", 7, chat);
            server.insertEvent(prefix, "block", 5_000_000_000L, block(1L, 1L, 1, 0, 0, 0, null, null));
            server.execute("INSERT INTO " + server.table(prefix, "retention_high_water")
                + " (batch_sequence, family, rowid, recorded_at) VALUES (5, 'chat', 900, now64(3))");

            assertEquals(OptionalLong.of(900), source.highWater("chat"));
            assertEquals(OptionalLong.of(5_000_000_000L), source.highWater("block"));
            assertEquals(OptionalLong.of(0), source.highWater("sign"));
            assertThrows(SQLException.class, () -> source.highWater("nonsense"));
        }
    }

    @Test
    @DisplayName("should read the database while CoreProtect's writer has it open")
    void besideWriter(@TempDir Path writerDirectory) throws SQLException {
        server.insertEvent(prefix, "world", 1, Map.of("time", 0L, "id", 1, "name", "world"));
        try (Target writer = server.api().initialize(server.config(), prefix, writerDirectory)) {
            assertNotNull(writer);
            assertArrayEquals(new Object[]{1L, "world"},
                source.read("world", List.of("id", "world"), 0, 10).get(0).values());
        }
    }

    private static List<Long> rowIds(List<Row> rows) {
        List<Long> rowIds = new ArrayList<>();
        for (Row row : rows) {
            rowIds.add(row.rowId());
        }
        return rowIds;
    }

    static Map<String, Object> block(long time, Long user, Integer wid, Integer x, Integer y, Integer z, byte[] meta,
                                     byte[] blockdata) {
        Map<String, Object> row = located(time, user, wid, x, y, z);
        row.put("type", 12);
        row.put("data", -9);
        row.put("meta", meta);
        row.put("blockdata", blockdata);
        row.put("action", 1);
        row.put("rolled_back", 0);
        return row;
    }

    private static Map<String, Object> user(long time, String name, String uuid) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("time", time);
        row.put("data", time);
        row.put("user_name", name);
        row.put("uuid", uuid);
        return row;
    }

    private static Map<String, Object> spawn(Long blockRowId, Long killRowId, String uuid, byte[] data, double angle) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("time", 1_700_000_000L);
        row.put("block_rowid", blockRowId);
        row.put("block_rowid_present", blockRowId == null ? 0 : 1);
        row.put("kill_rowid", killRowId);
        row.put("kill_rowid_present", killRowId == null ? 0 : 1);
        row.put("uuid", uuid);
        row.put("wid", 1);
        row.put("wid_present", 1);
        row.put("x", 1);
        row.put("x_present", 1);
        row.put("z", -4);
        row.put("z_present", 1);
        row.put("current_wid", 2);
        row.put("origin_x", 1.5);
        row.put("origin_y", 64.0);
        row.put("origin_z", -3.5);
        row.put("current_x", 1.25);
        row.put("current_y", 65.0);
        row.put("current_z", -3.75);
        row.put("yaw", angle);
        row.put("pitch", angle);
        row.put("entity_data", data);
        row.put("entity_data_present", data == null ? 0 : 1);
        row.put("removed", 0);
        return row;
    }
}
