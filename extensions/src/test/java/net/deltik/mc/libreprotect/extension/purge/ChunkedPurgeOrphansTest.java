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

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.UnaryOperator;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ChunkedPurge: orphan cleanup")
class ChunkedPurgeOrphansTest extends ChunkedPurgeFixture {

    /**
     * Rows linked the way CoreProtect 25 links them, where the old block
     * and entity rows are due for purging. Interactions and container
     * changes aren't purged by time here, so the orphan cleanup's own
     * handling of them shows.
     */
    private void seed() throws SQLException {
        long old = CUTOFF - DAY;
        long recent = CUTOFF + DAY;
        database.execute(
            "INSERT INTO co_block (rowid, time) VALUES (1, " + old + "), (2, " + recent + ")",
            "INSERT INTO co_entity (rowid, time) VALUES (1, " + old + "), (2, " + recent + "), (3, " + recent + ")",
            // 1: its kill is purged; 2: its kill and block stay; 3: its block is purged and it's gone;
            // 4: gone, but interactions refer to it; 5: gone and unreferenced; 6: the same, but recent;
            // 7: alive and newest
            "INSERT INTO co_entity_spawn (rowid, time, block_rowid, kill_rowid, uuid, removed) VALUES"
                + " (1, " + old + ", NULL, 1, 'a', 0), (2, " + old + ", 2, 2, 'b', 1), (3, " + old + ", 1, NULL, 'c', 1),"
                + " (4, " + old + ", NULL, NULL, 'd', 1), (5, " + old + ", NULL, NULL, 'e', 1),"
                + " (6, " + CUTOFF + ", NULL, NULL, 'f', 1), (7, " + recent + ", NULL, NULL, 'g', 0)",
            // 1: refers to spawn 4; 2: refers to a spawn that doesn't exist; 3: the same, but recent; 4: refers to spawn 4
            "INSERT INTO co_entity_interaction (rowid, time, entity_spawn_rowid) VALUES"
                + " (1, " + old + ", 4), (2, " + old + ", 99), (3, " + CUTOFF + ", 98), (4, " + recent + ", 4)",
            // 1: refers to a spawn that doesn't exist; 2: refers to spawn 2
            "INSERT INTO co_entity_container (rowid, time, entity_spawn_rowid) VALUES"
                + " (1, " + old + ", 97), (2, " + recent + ", 2)");
        bridge.tables = List.of("entity", "block");
        bridge.entitySpawns = true;
    }

    @ParameterizedTest
    @EnumSource(value = Engine.class, names = {"SQLITE", "DUCKDB"})
    @DisplayName("should clean up what purged rows leave behind, and only remove orphans older than the cutoff")
    void cleansUp(Engine engine) throws SQLException {
        setUp(engine);
        seed();

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed(), () -> result.stopReason() + ": " + result.detail());
        assertTrue(result.orphansCleaned());
        assertEquals(List.of(2L), database.rowids("block"));
        assertEquals(List.of(2L, 3L), database.rowids("entity"));
        assertEquals(List.of(1L, 2L, 4L, 6L, 7L), database.rowids("entity_spawn"));
        assertEquals(Arrays.asList(null, 2L, null, null, null),
            database.longs("SELECT kill_rowid FROM co_entity_spawn ORDER BY rowid"));
        assertEquals(Arrays.asList(null, 2L, null, null, null),
            database.longs("SELECT block_rowid FROM co_entity_spawn ORDER BY rowid"));
        assertEquals(List.of(1L, 3L, 4L), database.rowids("entity_interaction"));
        assertEquals(List.of(2L), database.rowids("entity_container"));
        // block 1 and entity 1 by time; interaction 2, container 1, spawns 3 and 5 as orphans
        assertEquals(6, result.removed());
        assertEquals(6, bridge.rowsPurged.get());
        assertTrue(bridge.exclusiveLeases.get() > 0, "orphan cleanup is exclusive");
        // Once for the chunk that removed spawns, under its lease, and once at the end
        assertEquals(1, bridge.purgedCallsUnderLease.get());
        assertEquals(2, bridge.purgedCalls.get());
    }

    @Test
    @DisplayName("should clean up an earlier run's orphans even when nothing expired")
    void pending() throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        // As if an earlier run removed block 1 and entity 1, then stopped
        database.execute("DELETE FROM co_block WHERE rowid = 1", "DELETE FROM co_entity WHERE rowid = 1");

        PurgeResult nothingPending = purge(CUTOFF, false);
        assertEquals(0, nothingPending.removed());
        assertEquals(0, bridge.exclusiveLeases.get());

        PurgeResult result = purge(CUTOFF, true);
        assertTrue(result.completed());
        assertEquals(List.of(1L, 2L, 4L, 6L, 7L), database.rowids("entity_spawn"));
        assertEquals(Arrays.asList(null, 2L, null, null, null),
            database.longs("SELECT kill_rowid FROM co_entity_spawn ORDER BY rowid"));
        assertEquals(List.of(1L, 3L, 4L), database.rowids("entity_interaction"));
        assertEquals(List.of(2L), database.rowids("entity_container"));
        assertEquals(4, result.removed());
    }

    @Test
    @DisplayName("should leave orphan cleanup to a later run while the bridge can't tell whether there are any")
    void unknown() throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        bridge.entitySpawnsUnknown = true;

        PurgeResult result = purge(CUTOFF, true);

        assertTrue(result.completed(), () -> result.stopReason() + ": " + result.detail());
        assertFalse(result.orphansCleaned(), "a later run looks again");
        assertEquals(2, result.removed(), "block 1 and entity 1 by time");
        assertEquals(0, bridge.exclusiveLeases.get());
        assertEquals(List.of(1L, 2L, 3L, 4L, 5L, 6L, 7L), database.rowids("entity_spawn"));

        bridge.entitySpawnsUnknown = false;
        PurgeResult later = purge(CUTOFF, true);
        assertTrue(later.orphansCleaned());
        assertEquals(List.of(1L, 2L, 4L, 6L, 7L), database.rowids("entity_spawn"));
    }

    /** Deletes run on entity_spawn, counted by {@link #seedDespawned} */
    private final AtomicInteger spawnDeletes = new AtomicInteger();

    /**
     * Old despawned entities that nothing refers to, which the orphan
     * cleanup's last walk removes, then a newer one that is alive
     */
    private int seedDespawned(int rows) throws SQLException {
        database.insertRange("entity_spawn", 1, rows, CUTOFF - DAY);
        database.execute("UPDATE co_entity_spawn SET removed = 1",
            "INSERT INTO co_entity_spawn (rowid, time, removed) VALUES (" + (rows + 1) + ", " + (CUTOFF + DAY) + ", 0)");
        bridge.tables = List.of();
        bridge.entitySpawns = true;
        bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> {
            if (sql.startsWith("DELETE FROM co_entity_spawn")) {
                spawnDeletes.incrementAndGet();
            }
        });
        return rows;
    }

    @ParameterizedTest
    @EnumSource(value = Engine.class, names = {"SQLITE", "DUCKDB"})
    @DisplayName("should have CoreProtect recheck its tracked entities a bounded number of times, however many chunks remove them")
    void boundedRechecks(Engine engine) throws SQLException {
        setUp(engine);
        // At least four chunks, however large they grow
        int rows = seedDespawned(4 * ChunkSizer.MAXIMUM_ROWS);
        // However long the chunks take on a busy machine, they all come within 30 s
        AtomicLong nanoTime = new AtomicLong();

        PurgeResult result = purger(CUTOFF).timing(0, 1, 60_000).invalidationClock(nanoTime::get).run(true);

        assertTrue(result.completed());
        assertEquals(rows, result.removed());
        assertTrue(spawnDeletes.get() >= 4, "chunks that removed spawns: " + spawnDeletes.get());
        // After the first chunk, and after the last; the ones between came within 30 s
        assertEquals(2, bridge.purgedCallsUnderLease.get());
        // And once at the end of the run
        assertEquals(3, bridge.purgedCalls.get());
    }

    @Test
    @DisplayName("should have CoreProtect recheck once more when 30 seconds pass between chunks that remove spawns")
    void recheckAfter30Seconds() throws SQLException {
        setUp(Engine.SQLITE);
        seedDespawned(4 * ChunkSizer.MAXIMUM_ROWS);
        AtomicLong nanoTime = new AtomicLong();
        UnaryOperator<Connection> counting = bridge.connections;
        // The third chunk's delete takes 30 s: two have been counted as it starts
        bridge.connections = connection -> StatementHooks.wrap(counting.apply(connection), (sql, parameters) -> {
            if (sql.startsWith("DELETE FROM co_entity_spawn") && spawnDeletes.get() == 2) {
                nanoTime.addAndGet(ChunkedPurge.INVALIDATION_INTERVAL_NANOS);
            }
        });

        PurgeResult result = purger(CUTOFF).timing(0, 1, 60_000).invalidationClock(nanoTime::get).run(true);

        assertTrue(result.completed());
        assertTrue(spawnDeletes.get() >= 4, "chunks that removed spawns: " + spawnDeletes.get());
        // After the first chunk, after the third, which took 30 s, and after the last
        assertEquals(3, bridge.purgedCallsUnderLease.get());
        assertEquals(4, bridge.purgedCalls.get());
    }

    @Test
    @DisplayName("should have CoreProtect recheck after chunks that removed spawns once the interval has passed")
    void rechecksAfterInterval() throws SQLException {
        setUp(Engine.SQLITE);
        seedDespawned(4 * ChunkSizer.MAXIMUM_ROWS);

        PurgeResult result = purger(CUTOFF).timing(0, 1, 60_000).invalidationInterval(0).run(true);

        assertTrue(result.completed());
        assertTrue(spawnDeletes.get() >= 4, "chunks that removed spawns: " + spawnDeletes.get());
        assertEquals(spawnDeletes.get(), bridge.purgedCallsUnderLease.get());
    }

    @Test
    @DisplayName("should leave orphan cleanup for the next run when stopped before it")
    void stoppedBefore() throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> {
            if (sql.startsWith("DELETE FROM co_block")) {
                bridge.stopReason = StopReason.MANUAL_PURGE;
            }
        });

        PurgeResult result = purge(CUTOFF);

        assertEquals(StopReason.MANUAL_PURGE, result.stopReason());
        assertFalse(result.orphansCleaned());
        assertEquals(0, bridge.exclusiveLeases.get());
    }

    @Test
    @DisplayName("should not look for orphans without entity tracking (CoreProtect 24)")
    void coreProtect24() throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        bridge.entitySpawns = false;

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals(0, bridge.exclusiveLeases.get());
        assertEquals(7, database.rowids("entity_spawn").size());
    }
}
