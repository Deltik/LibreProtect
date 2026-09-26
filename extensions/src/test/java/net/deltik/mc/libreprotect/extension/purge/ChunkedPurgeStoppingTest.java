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
import net.deltik.mc.libreprotect.extension.common.PurgeChunkLock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ChunkedPurge: stopping")
class ChunkedPurgeStoppingTest extends ChunkedPurgeFixture {

    private void seed() throws SQLException {
        database.insertRange("block", 1, 30_000, CUTOFF - DAY);
        insert("block", new long[]{30_001}, new long[]{CUTOFF + DAY});
    }

    private void assertNothingNewerDeleted() throws SQLException {
        assertEquals(List.of(30_001L), database.longs("SELECT rowid FROM co_block WHERE time >= " + CUTOFF));
    }

    @ParameterizedTest
    @EnumSource(value = StopReason.class, names = {"MANUAL_PURGE", "MIGRATION", "CONVERSION", "CONSUMER_PAUSED",
        "PERSISTENCE_HALTED", "SHUTDOWN"})
    @DisplayName("should stop when a lease is refused for a reason to stop")
    void refusedLease(StopReason reason) throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        bridge.leasePolicy = number -> number > 3 ? Lease.stop(reason) : null;

        PurgeResult result = purge(CUTOFF);

        assertEquals(reason, result.stopReason());
        assertTrue(result.removed() > 0 && result.removed() < 30_000, "removed " + result.removed());
        assertEquals(result.removed(), bridge.rowsPurged.get());
        assertEquals(4, bridge.leases.get());
        assertNothingNewerDeleted();
    }

    @Test
    @DisplayName("should stop between chunks when the bridge reports a reason, before taking another lease")
    void bridgeReason() throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        AtomicInteger deletes = new AtomicInteger();
        bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> {
            if (sql.startsWith("DELETE") && deletes.incrementAndGet() == 1) {
                bridge.stopReason = StopReason.MANUAL_PURGE;
            }
        });

        PurgeResult result = purge(CUTOFF);

        assertEquals(StopReason.MANUAL_PURGE, result.stopReason());
        assertEquals(1, deletes.get());
        assertEquals(2, bridge.leases.get());
        assertEquals(1, bridge.purgedCalls.get());
        assertNothingNewerDeleted();
    }

    @Test
    @DisplayName("should stop when auto-purge's settings change")
    void settingsChange() throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        AtomicInteger checks = new AtomicInteger();
        runChecks = () -> checks.incrementAndGet() > 2 ? StopReason.SETTINGS_CHANGED : null;

        PurgeResult result = purge(CUTOFF);

        assertEquals(StopReason.SETTINGS_CHANGED, result.stopReason());
        assertNothingNewerDeleted();
    }

    @Test
    @DisplayName("should stop when the database is replaced, such as by a manual purge's file swap")
    void databaseReplaced() throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> {
            if (sql.startsWith("DELETE")) {
                bridge.identity = "another file";
            }
        });

        PurgeResult result = purge(CUTOFF);

        assertEquals(StopReason.DATABASE_CHANGED, result.stopReason());
        assertEquals(5000, result.removed());
    }

    @Test
    @DisplayName("should stop when CoreProtect switches engines or table prefixes")
    void engineChanged() throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        bridge.leasePolicy = number -> {
            if (number == 3) {
                bridge.engine = Engine.MYSQL;
            }
            return null;
        };

        PurgeResult result = purge(CUTOFF);

        assertEquals(StopReason.DATABASE_CHANGED, result.stopReason());
        assertNothingNewerDeleted();
    }

    @Test
    @DisplayName("should cancel a running statement and stop when asked to, from another thread")
    void cancelsStatement() throws Exception {
        setUp(Engine.SQLITE);
        seed();
        CountDownLatch running = new CountDownLatch(1);
        CountDownLatch canceled = new CountDownLatch(1);
        bridge.connections = connection -> StatementHooks.wrap(connection, new StatementHooks.Hook() {
            @Override
            public void before(String sql, List<Object> parameters) throws SQLException {
                if (sql.startsWith("DELETE")) {
                    running.countDown();
                    try {
                        if (!canceled.await(30, TimeUnit.SECONDS)) {
                            throw new SQLException("never canceled");
                        }
                    } catch (InterruptedException e) {
                        throw new SQLException("interrupted", e);
                    }
                    throw new SQLException("[SQLITE_INTERRUPT] statement canceled");
                }
            }

            @Override
            public void canceled(String sql) {
                canceled.countDown();
            }
        });
        Thread stopper = new Thread(() -> {
            try {
                running.await();
                context.requestStop();
            } catch (InterruptedException ignored) {
            }
        });
        stopper.start();

        long started = System.nanoTime();
        PurgeResult result = purge(CUTOFF);

        assertEquals(StopReason.SHUTDOWN, result.stopReason());
        assertEquals(0, canceled.getCount(), "the statement was canceled");
        assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(10));
        assertEquals(0, bridge.purgedCalls.get(), "no follow-up work while shutting down");
        assertEquals(30_001, database.rowids("block").size());
    }

    @Test
    @DisplayName("should stop during the pause after a lease as soon as asked to")
    void stopsDuringPause() throws Exception {
        setUp(Engine.SQLITE);
        seed();
        CountDownLatch read = new CountDownLatch(1);
        bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> {
            if (sql.startsWith("SELECT MIN(rowid), MAX(rowid)")) {
                read.countDown();
            }
        });
        Thread stopper = new Thread(() -> {
            try {
                read.await();
                Thread.sleep(200);
                context.requestStop();
            } catch (InterruptedException ignored) {
            }
        });
        stopper.start();

        long started = System.nanoTime();
        PurgeResult result = purger(CUTOFF).timing(60_000, 1, 60_000).run(false);

        assertEquals(StopReason.SHUTDOWN, result.stopReason());
        assertEquals(0, result.removed());
        assertEquals(1, bridge.leases.get());
        assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(10));
    }

    @Test
    @DisplayName("should pause after every lease at least four times as long as it held the lease")
    void pacing() throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        List<long[]> leases = new CopyOnWriteArrayList<>();
        bridge.leasePolicy = number -> {
            leases.add(new long[]{System.nanoTime(), 0});
            return null;
        };
        bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> {
            // Every statement holds the lease for at least 20 ms
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                throw new SQLException(e);
            }
        });

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        for (int i = 1; i < leases.size(); i++) {
            long gap = leases.get(i)[0] - leases.get(i - 1)[0];
            // A lease runs at least one 20 ms statement, then pauses at least 4 times that
            assertTrue(gap >= TimeUnit.MILLISECONDS.toNanos(5 * 20), "lease " + i + " followed after " + gap / 1_000_000 + " ms");
        }
    }

    @Test
    @DisplayName("should wait while the database is busy, then go on")
    void waitsWhileBusy() throws SQLException {
        setUp(Engine.SQLITE);
        insert("block", range(1, 10), repeat(CUTOFF - DAY, 10));
        insert("block", new long[]{11}, new long[]{CUTOFF});
        bridge.leasePolicy = number -> number <= 3 ? Lease.busy("a rollback is running") : null;

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals(10, result.removed());
    }

    @Test
    @DisplayName("should give up when the database stays busy")
    void givesUpWhenBusy() throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        bridge.leasePolicy = number -> Lease.busy("a rollback is running");

        PurgeResult result = purger(CUTOFF).timing(0, 1, 300).run(false);

        assertEquals(StopReason.DATABASE_BUSY, result.stopReason());
        assertEquals("a rollback is running", result.detail());
        assertEquals(0, result.removed());
    }

    @Test
    @DisplayName("should let a migration wait for the chunk that is running, and for no other")
    void migrationWaitsForChunk() throws Exception {
        setUp(Engine.SQLITE);
        seed();
        CountDownLatch deleting = new CountDownLatch(1);
        CountDownLatch finish = new CountDownLatch(1);
        bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> {
            if (sql.startsWith("DELETE") && deleting.getCount() > 0) {
                deleting.countDown();
                try {
                    finish.await(10, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    throw new SQLException(e);
                }
            }
        });
        AtomicReference<PurgeResult> result = new AtomicReference<>();
        PurgeContext purgeContext = new PurgeContext();
        Thread worker = new Thread(() -> result.set(new ChunkedPurge(bridge, purgeContext, log, () -> runChecks.get(),
            CUTOFF, CUTOFF + 30 * DAY).timing(0, 1, 60_000).run(false)));
        purgeContext.bind(worker);
        worker.start();
        assertTrue(deleting.await(10, TimeUnit.SECONDS));

        // A migration begins: auto-purge stops before its next chunk, but this one is deleting
        bridge.stopReason = StopReason.MIGRATION;
        assertFalse(PurgeChunkLock.awaitNoChunk(200), "the migration went on while the chunk was deleting");
        finish.countDown();
        assertTrue(PurgeChunkLock.awaitNoChunk(5000));
        worker.join(5000);

        assertEquals(StopReason.MIGRATION, result.get().stopReason());
        assertEquals(5000, result.get().removed());
        assertEquals(2, bridge.leases.get());
    }

    @Test
    @DisplayName("should stop while a migration holds the chunk lock")
    void stopsWhileLocked() throws Exception {
        setUp(Engine.SQLITE);
        seed();
        CountDownLatch holding = new CountDownLatch(1);
        CountDownLatch finish = new CountDownLatch(1);
        Thread migration = new Thread(() -> {
            try {
                assertTrue(PurgeChunkLock.tryHold(1000));
                holding.countDown();
                finish.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                PurgeChunkLock.release();
            }
        });
        migration.start();
        assertTrue(holding.await(5, TimeUnit.SECONDS));
        new Thread(() -> {
            try {
                Thread.sleep(300);
            } catch (InterruptedException e) {
                return;
            }
            context.requestStop();
        }).start();

        long started = System.nanoTime();
        PurgeResult result = purge(CUTOFF);

        assertEquals(StopReason.SHUTDOWN, result.stopReason());
        assertEquals(0, bridge.leases.get());
        assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(3));
        finish.countDown();
        migration.join(5000);
    }

    @Test
    @DisplayName("should retry a chunk after a failure")
    void retries() throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        AtomicInteger failures = new AtomicInteger();
        bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> {
            if (sql.startsWith("DELETE") && failures.getAndIncrement() < 2) {
                throw new SQLException("[SQLITE_BUSY] The database file is locked (database is locked)");
            }
        });

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals(30_000, result.removed());
        assertEquals(2, bridge.recoveryRequests.size(), "failures offered to recovery first");
    }

    @Test
    @DisplayName("should stop after repeated failures of the same chunk")
    void stopsAfterFailures() throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> {
            if (sql.startsWith("DELETE")) {
                throw new SQLException("no such table: co_block");
            }
        });

        PurgeResult result = purge(CUTOFF);

        assertEquals(StopReason.ERROR, result.stopReason());
        assertEquals("no such table: co_block", result.detail());
        assertEquals(ChunkedPurge.MAXIMUM_ATTEMPTS, bridge.recoveryRequests.size());
        assertEquals(30_001, database.rowids("block").size());
    }

    @Test
    @DisplayName("should stop at once for a failure that needs the database reopened")
    void recovery() throws SQLException {
        setUp(Engine.DUCKDB);
        seed();
        bridge.recoverFailures = true;
        bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> {
            if (sql.startsWith("DELETE")) {
                throw new SQLException("FATAL Error: database has been invalidated");
            }
        });

        PurgeResult result = purge(CUTOFF);

        assertEquals(StopReason.DATABASE_RECOVERY, result.stopReason());
        assertEquals(1, bridge.recoveryRequests.size());
    }

    @Test
    @DisplayName("should stop before any lease when the bridge can't purge the database, saying why")
    void unsupportedDatabase() throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        bridge.stopReason = StopReason.UNSUPPORTED_DATABASE;
        bridge.unavailable = "auto-purge.coordination is unavailable: CoreProtect has no"
            + " Consumer.claimBackgroundPurge(boolean)";

        PurgeResult result = purge(CUTOFF);

        assertEquals(StopReason.UNSUPPORTED_DATABASE, result.stopReason());
        assertEquals(bridge.unavailable, result.detail());
        assertEquals(0, bridge.leases.get());
        assertEquals(30_001, database.rowids("block").size());
    }

    @Test
    @DisplayName("should never run a statement on a database engine it doesn't know")
    void unknownEngine() throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        bridge.engine = null;
        bridge.entitySpawns = true;
        AtomicInteger statements = new AtomicInteger();
        bridge.connections = connection -> StatementHooks.wrap(connection,
            (sql, parameters) -> statements.incrementAndGet());

        PurgeResult result = purge(CUTOFF, true);

        assertEquals(StopReason.UNSUPPORTED_DATABASE, result.stopReason());
        assertEquals(0, bridge.leases.get());
        assertEquals(0, statements.get());
        assertEquals(30_001, database.rowids("block").size());
    }

    @Test
    @DisplayName("should say why a lease was refused, such as with an answer of CoreProtect's it doesn't know")
    void refusalDetail() throws SQLException {
        setUp(Engine.SQLITE);
        seed();
        bridge.leasePolicy = number -> Lease.stop(StopReason.DATABASE_BUSY,
            "CoreProtect refused a purge claim with SOMETHING_NEW");

        PurgeResult result = purge(CUTOFF);

        assertEquals(StopReason.DATABASE_BUSY, result.stopReason());
        assertEquals("CoreProtect refused a purge claim with SOMETHING_NEW", result.detail());
        assertEquals(1, bridge.leases.get());
    }
}
