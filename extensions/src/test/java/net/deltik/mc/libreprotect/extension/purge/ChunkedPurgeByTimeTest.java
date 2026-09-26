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

package net.deltik.mc.libreprotect.extension.purge;

import net.deltik.mc.libreprotect.extension.common.Engine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.LongStream;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ChunkedPurge: deleting by time")
class ChunkedPurgeByTimeTest extends ChunkedPurgeFixture {

    @ParameterizedTest
    @EnumSource(value = Engine.class, names = {"SQLITE", "DUCKDB"})
    @DisplayName("should delete rows older than the cutoff and keep the rest, across rowid gaps")
    void deletesOlderRows(Engine engine) throws SQLException {
        setUp(engine);
        long[] rowids = new long[3000];
        long[] times = new long[3000];
        for (int i = 0; i < rowids.length; i++) {
            rowids[i] = 1 + 3L * i;
            times[i] = CUTOFF - 2_000_000 + 1000L * i;
        }
        insert("block", rowids, times);
        insert("chat", new long[]{10, 11}, new long[]{CUTOFF, CUTOFF + 5});

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed(), () -> String.valueOf(result.stopReason()));
        assertEquals(2000, result.removed());
        assertEquals(2000, bridge.rowsPurged.get());
        assertEquals(0, count("SELECT COUNT(*) FROM co_block WHERE time < " + CUTOFF));
        assertEquals(1000, count("SELECT COUNT(*) FROM co_block WHERE time >= " + CUTOFF));
        assertEquals(List.of(10L, 11L), database.rowids("chat"));
        assertEquals(1, bridge.purgedCalls.get());
    }

    @ParameterizedTest
    @EnumSource(value = Engine.class, names = {"SQLITE", "DUCKDB"})
    @DisplayName("should keep every row at or after the cutoff, even among older ones")
    void keepsNewerAmongOutliers(Engine engine) throws SQLException {
        setUp(engine);
        int rows = 4000;
        long[] rowids = range(1, rows);
        long[] times = new long[rows];
        for (int i = 0; i < rows; i++) {
            // Seconds either side of the cutoff, in no particular order
            times[i] = CUTOFF + ((i * 7919L) % 61) - 30;
        }
        insert("block", rowids, times);
        List<Long> expected = new ArrayList<>();
        for (int i = 0; i < rows; i++) {
            if (times[i] >= CUTOFF || (engine == Engine.SQLITE && rowids[i] == rows)) {
                expected.add(rowids[i]);
            }
        }

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals(expected, database.rowids("block"));
        assertEquals(rows - expected.size(), result.removed());
    }

    @ParameterizedTest
    @EnumSource(value = Engine.class, names = {"SQLITE", "DUCKDB"})
    @DisplayName("should finish a table at a range a day past the cutoff, without reading the rest")
    void finishesPastCutoff(Engine engine) throws SQLException {
        setUp(engine);
        database.insertRange("block", 1, 100, CUTOFF - 10 * DAY);
        database.insertRange("block", 101, 20_100, CUTOFF + 2 * DAY);
        // Rows logged out of order, after the table's newer rows: left for a later run
        insert("block", range(20_101, 20_110), repeat(CUTOFF - DAY, 10));
        insert("block", new long[]{20_111}, new long[]{CUTOFF + 3 * DAY});

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals(100, result.removed());
        assertEquals(0, count("SELECT COUNT(*) FROM co_block WHERE rowid <= 100"));
        assertEquals(20_000, count("SELECT COUNT(*) FROM co_block WHERE time = " + (CUTOFF + 2 * DAY)));
        assertEquals(10, count("SELECT COUNT(*) FROM co_block WHERE rowid BETWEEN 20101 AND 20110"));
        // block: bounds and two ranges; chat: empty
        assertTrue(bridge.leases.get() <= 5, "leases: " + bridge.leases.get());
    }

    @ParameterizedTest
    @EnumSource(value = Engine.class, names = {"SQLITE", "DUCKDB"})
    @DisplayName("should keep the newest row of a table whose rowids others keep on SQLite, which would reuse it, and not on DuckDB")
    void newestRow(Engine engine) throws SQLException {
        setUp(engine);
        bridge.tables = List.of("block", "entity");
        insert("block", range(1, 50), repeat(CUTOFF - 100 * DAY, 50));
        insert("entity", range(1, 5), repeat(CUTOFF - 100 * DAY, 5));

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        if (engine == Engine.SQLITE) {
            assertEquals(53, result.removed());
            assertEquals(List.of(50L), database.rowids("block"));
            assertEquals(List.of(5L), database.rowids("entity"));
        } else {
            assertEquals(55, result.removed());
            assertEquals(List.of(), database.rowids("block"));
            assertEquals(List.of(), database.rowids("entity"));
        }
    }

    @ParameterizedTest
    @EnumSource(value = Engine.class, names = {"SQLITE", "DUCKDB"})
    @DisplayName("should purge every old row of tables nothing refers to, such as a player's last chat message")
    void lastChatMessage(Engine engine) throws SQLException {
        setUp(engine);
        database.insertRange("chat", 1, 5, CUTOFF - 400 * DAY);

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals(5, result.removed());
        assertEquals(List.of(), database.rowids("chat"));
    }

    @Test
    @DisplayName("should keep newest rows only of block, entity, skull and entity_spawn, whose rowids CoreProtect keeps elsewhere")
    void referencedTables() {
        assertEquals(java.util.Set.of("block", "entity", "skull", "entity_spawn"), ChunkedPurge.REFERENCED_TABLES);
    }

    @ParameterizedTest
    @EnumSource(value = Engine.class, names = {"SQLITE", "DUCKDB"})
    @DisplayName("should walk past rows a clock that ran ahead wrote, and purge the old rows after them, run after run")
    void futureDatedRows(Engine engine) throws SQLException {
        setUp(engine);
        // Logged 40 days before the cutoff, normally
        database.insertRange("block", 1, 1_000, CUTOFF - 40 * DAY);
        // 20 minutes with the clock a year ahead
        database.insertRange("block", 1_001, 21_000, CUTOFF - 39 * DAY + 365 * DAY);
        // The clock is right again
        database.insertRange("block", 21_001, 60_000, CUTOFF - 20 * DAY);
        // Newer than any of the three cutoffs, so SQLite's kept newest row isn't one of the above
        database.insertRange("block", 60_001, 60_001, CUTOFF + 10 * DAY);

        // Three daily runs, each with the cutoff a day later
        for (int run = 0; run < 3; run++) {
            PurgeResult result = purge(CUTOFF + run * DAY);
            assertTrue(result.completed());
        }

        assertEquals(0, count("SELECT COUNT(*) FROM co_block WHERE time < " + (CUTOFF + 2 * DAY)));
        assertEquals(20_000, count("SELECT COUNT(*) FROM co_block WHERE time > " + (CUTOFF + 300 * DAY)));
    }

    @ParameterizedTest
    @EnumSource(value = Engine.class, names = {"SQLITE", "DUCKDB"})
    @DisplayName("should still finish a table at the first range a day past the cutoff that isn't in the future")
    void finishesAfterFutureRows(Engine engine) throws SQLException {
        setUp(engine);
        database.insertRange("block", 1, 100, CUTOFF - 10 * DAY);
        database.insertRange("block", 101, 10_100, CUTOFF + 365 * DAY);
        database.insertRange("block", 10_101, 40_100, CUTOFF + 2 * DAY);
        // Out of order after the table ended: left for a later run
        database.insertRange("block", 40_101, 40_110, CUTOFF - DAY);
        database.insertRange("block", 40_111, 40_111, CUTOFF + 3 * DAY);

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals(100, result.removed());
        assertEquals(10, count("SELECT COUNT(*) FROM co_block WHERE time < " + CUTOFF));
        // chat's bounds; block's bounds, then ranges up to the first one past the cutoff and not in the future
        assertTrue(bridge.leases.get() <= 6, "leases: " + bridge.leases.get());
    }

    @ParameterizedTest
    @EnumSource(value = Engine.class, names = {"SQLITE", "DUCKDB"})
    @DisplayName("should never purge rows with a negative time, as a manual purge doesn't")
    void negativeTimes(Engine engine) throws SQLException {
        setUp(engine);
        insert("block", new long[]{1, 2, 3, 4}, new long[]{-1, 0, CUTOFF - 1, CUTOFF});
        insert("chat", new long[]{1, 2}, new long[]{-5, CUTOFF - 1});

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals(3, result.removed());
        assertEquals(List.of(1L, 4L), database.rowids("block"));
        assertEquals(List.of(1L), database.rowids("chat"));
    }

    @ParameterizedTest
    @EnumSource(value = Engine.class, names = {"SQLITE", "DUCKDB"})
    @DisplayName("should jump over large rowid gaps")
    void jumpsGaps(Engine engine) throws SQLException {
        setUp(engine);
        insert("block", range(1, 10), repeat(CUTOFF - DAY, 10));
        insert("block", range(50_000_001, 50_000_010), repeat(CUTOFF - DAY, 10));
        insert("block", new long[]{90_000_000}, new long[]{CUTOFF + DAY});

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals(20, result.removed());
        assertEquals(List.of(90_000_000L), database.rowids("block"));
        assertTrue(bridge.leases.get() <= 10, "leases: " + bridge.leases.get());
    }

    @ParameterizedTest
    @EnumSource(value = Engine.class, names = {"SQLITE", "DUCKDB"})
    @DisplayName("should narrow a range that holds too many rows before deleting from it")
    void narrowsDenseRanges(Engine engine) throws SQLException {
        setUp(engine);
        long[] sparse = LongStream.range(0, 10).map(i -> 1 + 1000 * i).toArray();
        insert("block", sparse, repeat(CUTOFF - DAY, sparse.length));
        database.insertRange("block", 1_000_001, 1_150_000, CUTOFF - DAY);
        insert("block", new long[]{2_000_000}, new long[]{CUTOFF + DAY});
        List<long[]> deletes = new CopyOnWriteArrayList<>();
        bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> {
            if (sql.startsWith("DELETE FROM co_block")) {
                deletes.add(new long[]{(Long) parameters.get(0), (Long) parameters.get(1)});
            }
        });

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals(150_010, result.removed());
        long largest = 0;
        for (long[] delete : deletes) {
            long from = delete[0];
            long to = delete[1];
            long rows = LongStream.of(sparse).filter(rowid -> rowid > from && rowid <= to).count()
                + Math.max(0, Math.min(to, 1_150_000) - Math.max(from, 1_000_000));
            largest = Math.max(largest, rows);
        }
        assertTrue(largest <= 2L * ChunkSizer.MAXIMUM_ROWS, "largest delete: " + largest + " rows");
    }

    @Test
    @DisplayName("should bound how long a MySQL statement waits on the network")
    void networkTimeout() throws SQLException {
        setUp(Engine.SQLITE);
        insert("block", range(1, 10), repeat(CUTOFF - DAY, 10));
        insert("block", new long[]{11}, new long[]{CUTOFF});
        bridge.engine = Engine.MYSQL;
        List<Object> timeouts = new CopyOnWriteArrayList<>();
        bridge.connections = connection -> StatementHooks.wrap(connection, new StatementHooks.Hook() {
            @Override
            public void before(String sql, List<Object> parameters) {
            }

            @Override
            public void connection(String method, Object[] arguments) {
                if (method.equals("setNetworkTimeout")) {
                    timeouts.add(arguments[1]);
                }
            }
        });

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals(10, result.removed());
        assertEquals(bridge.leases.get(), timeouts.size(), "every MySQL lease");
        assertTrue(timeouts.stream().allMatch(timeout -> timeout.equals(ChunkedPurge.NETWORK_TIMEOUT_MILLIS)), timeouts::toString);
    }

    @ParameterizedTest
    @EnumSource(value = Engine.class, names = {"SQLITE", "DUCKDB"})
    @DisplayName("should do nothing without a positive cutoff")
    void noCutoff(Engine engine) throws SQLException {
        setUp(engine);
        insert("block", range(1, 10), repeat(0, 10));

        PurgeResult result = purge(0);

        assertTrue(result.completed());
        assertEquals(0, result.removed());
        assertEquals(10, database.rowids("block").size());
        assertEquals(0, bridge.purgedCalls.get());
    }
}
