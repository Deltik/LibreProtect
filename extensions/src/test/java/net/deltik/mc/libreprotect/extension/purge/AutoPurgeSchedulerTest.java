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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

class AutoPurgeSchedulerTest {

    /** 2026-09-24 12:00 UTC */
    private static final Instant NOW = Instant.parse("2026-09-24T12:00:00Z");
    private static final long DAY = 86400;

    @TempDir
    Path directory;

    private final RecordingLog log = new RecordingLog();
    private final MutableClock clock = new MutableClock(NOW);
    private TestDatabase database;
    private FakeBridge bridge;
    private AutoPurgeScheduler scheduler;

    @AfterEach
    void tearDown() throws SQLException {
        if (scheduler != null) {
            scheduler.stop();
            awaitTrue(() -> !scheduler.isAlive(), "the thread ends");
        }
        if (bridge != null) {
            assertEquals(List.of(), bridge.problems());
            assertEquals(0, bridge.openLeases.get());
        }
        if (database != null) {
            database.close();
        }
    }

    private void useDatabase() throws SQLException {
        database = TestDatabase.create(Engine.SQLITE, directory);
        bridge = new FakeBridge(database);
    }

    private AutoPurgeScheduler start() {
        scheduler = new AutoPurgeScheduler(bridge, log, clock, () -> ZoneId.of("UTC"), 20);
        scheduler.start();
        return scheduler;
    }

    private static void awaitTrue(BooleanSupplier condition, String what) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                fail("timed out waiting until " + what);
            }
            try {
                Thread.sleep(5);
            } catch (InterruptedException e) {
                throw new AssertionError(e);
            }
        }
    }

    private void awaitMessage(String text) {
        awaitTrue(() -> !log.containing(text).isEmpty(), "a message containing '" + text + "'\n" + log);
    }

    @Nested
    @DisplayName("announcing")
    class Announcing {

        @Test
        @DisplayName("should log the retention and next run when auto-purge is on")
        void enabled() throws SQLException {
            useDatabase();
            bridge.retention = "180d";

            start();

            assertEquals(List.of("INFO: Auto-purge keeps 180 days of data. Next run: 2026-09-25 00:00 (server time)."),
                log.messages);
        }

        @Test
        @DisplayName("should use auto-purge-time, later today if it hasn't passed")
        void time() throws SQLException {
            useDatabase();
            bridge.time = "13:05";

            start();

            assertEquals(List.of("INFO: Auto-purge keeps 30 days of data. Next run: 2026-09-24 13:05 (server time)."),
                log.messages);
        }

        @Test
        @DisplayName("should say nothing when auto-purge is off")
        void disabled() throws SQLException {
            useDatabase();
            bridge.retention = "false";

            start();

            assertEquals(List.of(), log.messages);
        }

        @Test
        @DisplayName("should warn once about an invalid setting, and again when it changes")
        void warnsOnce() throws Exception {
            useDatabase();
            bridge.retention = "7d";
            start();
            Thread.sleep(100);
            assertEquals(1, log.warnings().size(), log::toString);
            assertTrue(log.warnings().get(0).contains("auto-purge in CoreProtect's config.yml: '7d' keeps less than the"
                + " minimum of 30 days"));

            bridge.retention = "7days";
            awaitMessage("'7days' isn't a retention time");
            Thread.sleep(100);
            assertEquals(2, log.warnings().size(), log::toString);
        }

        @Test
        @DisplayName("should warn about an invalid time and run at midnight")
        void invalidTime() throws SQLException {
            useDatabase();
            bridge.time = "3pm";

            start();

            assertEquals(List.of(
                "WARNING: auto-purge-time in CoreProtect's config.yml: '3pm' isn't a time. Use 24-hour HH:mm server time,"
                    + " such as 03:30. Auto-purge runs at midnight.",
                "INFO: Auto-purge keeps 30 days of data. Next run: 2026-09-25 00:00 (server time)."), log.messages);
        }

        @Test
        @DisplayName("should pick up changed settings, such as from /co reload, and log the new schedule")
        void reload() throws SQLException {
            useDatabase();
            start();

            // Written in this order, a read of the new retention sees the new time too
            bridge.time = "3:30";
            bridge.retention = "12w";
            awaitMessage("keeps 84 days");
            assertTrue(log.messages.contains("INFO: Auto-purge keeps 84 days of data. Next run: 2026-09-25 03:30 (server time)."),
                log::toString);

            bridge.retention = "false";
            awaitMessage("Auto-purge is off.");
        }

        @Test
        @DisplayName("should warn when ClickHouse's database-lock is off")
        void clickHouse() {
            bridge = new FakeBridge(null);
            bridge.databaseLock = false;

            start();

            String warning = "Auto-purge can't run on ClickHouse while database-lock is disabled in CoreProtect's"
                + " config.yml. Set database-lock: true there, then restart the server or use /co reload.";
            assertEquals(1, log.containing(warning).size(), log::toString);
        }

        @Test
        @DisplayName("should warn once when this CoreProtect build lacks what auto-purge needs, and again for another"
            + " reason, without announcing a run that can't happen")
        void unavailable() throws Exception {
            useDatabase();
            bridge.unavailable = "CoreProtect has no ConfigHandler.sqlite, which purging SQLite needs";
            start();
            // A change of settings announces again, and only a new reason is worth a warning
            bridge.unavailable = "CoreProtect uses a database engine that LibreProtect doesn't know";
            bridge.retention = "12w";
            awaitMessage("CoreProtect uses a database engine");
            bridge.unavailable = null;
            bridge.retention = "13w";
            awaitMessage("keeps 91 days");

            assertEquals(List.of(
                "WARNING: Auto-purge won't work with this CoreProtect build: CoreProtect has no ConfigHandler.sqlite,"
                    + " which purging SQLite needs.",
                "WARNING: Auto-purge won't work with this CoreProtect build: CoreProtect uses a database engine that"
                    + " LibreProtect doesn't know."), log.warnings());
            assertEquals(1, log.containing("Next run").size(), log::toString);
        }

        @Test
        @DisplayName("should warn once that it can't read auto-purge, since it can't tell whether it's on")
        void settingsUnreadable() throws Exception {
            useDatabase();
            bridge.retention = null;
            bridge.settingsUnavailable = "CoreProtect has no Config.AUTO_PURGE";
            bridge.unavailable = bridge.settingsUnavailable;

            start();
            Thread.sleep(100);

            assertEquals(List.of("WARNING: Auto-purge can't read its settings with this CoreProtect build:"
                + " CoreProtect has no Config.AUTO_PURGE."), log.messages);
        }

        @Test
        @DisplayName("should not blame ClickHouse's database-lock when auto-purge can't run anyway")
        void clickHouseUnavailable() {
            bridge = new FakeBridge(null);
            bridge.databaseLock = false;
            bridge.unavailable = "CoreProtect has no Config.DATABASE_LOCK, which purging ClickHouse needs";

            start();

            assertEquals(List.of("WARNING: Auto-purge won't work with this CoreProtect build: CoreProtect has no"
                + " Config.DATABASE_LOCK, which purging ClickHouse needs."), log.messages);
        }

        @Test
        @DisplayName("should say nothing about what this CoreProtect build lacks when auto-purge is off")
        void unavailableButOff() throws SQLException {
            useDatabase();
            bridge.unavailable = "CoreProtect has no Consumer.isPaused";
            bridge.retention = "false";

            start();

            assertEquals(List.of(), log.messages);
        }
    }

    @Nested
    @DisplayName("running")
    class Running {

        @Test
        @DisplayName("should purge at the scheduled time, with the cutoff from auto-purge, then schedule the next day")
        void scheduled() throws Exception {
            useDatabase();
            long cutoff = NOW.plus(Duration.ofHours(12)).getEpochSecond() - 30 * DAY;
            database.insert("block", new long[]{1, 2, 3}, new long[]{cutoff - 1, cutoff, cutoff + 1});
            start();
            Thread.sleep(100);
            assertEquals(3, database.rowids("block").size(), "nothing runs before the scheduled time");

            clock.set(NOW.plus(Duration.ofHours(12)));

            awaitMessage("Auto-purge removed");
            assertEquals(List.of(2L, 3L), database.rowids("block"));
            assertEquals(1, bridge.rowsPurged.get());
            assertTrue(log.messages.stream().anyMatch(message -> message.matches(
                "INFO: Auto-purge removed 1 row in (less than a second|\\d+ s)\\. Next run: 2026-09-26 00:00 \\(server time\\)\\.")),
                log::toString);
        }

        @Test
        @DisplayName("should run a requested purge with any cutoff, and return the rows removed")
        void runNow() throws Exception {
            useDatabase();
            long cutoff = NOW.getEpochSecond() - 10;
            database.insert("block", new long[]{1, 2, 3}, new long[]{cutoff - 5, cutoff - 1, cutoff});
            start();

            assertEquals(2, scheduler.runNow(cutoff, 10_000));

            assertEquals(List.of(3L), database.rowids("block"));
            assertEquals(2, bridge.rowsPurged.get());
        }

        @Test
        @DisplayName("should start a requested purge promptly, even if the request arrives while the thread rereads its settings")
        void runNowWhileRereading() throws Exception {
            useDatabase();
            bridge.tables = List.of("block");
            long cutoff = NOW.getEpochSecond() - 10;
            database.insertRange("block", 1, 10, cutoff - DAY);
            database.insertRange("block", 11, 11, cutoff + DAY);
            CountDownLatch rereading = new CountDownLatch(1);
            CountDownLatch requested = new CountDownLatch(1);
            int[] reads = {0};
            PurgeBridge slowSettings = (PurgeBridge) Proxy.newProxyInstance(PurgeBridge.class.getClassLoader(),
                new Class<?>[]{PurgeBridge.class}, (proxy, method, arguments) -> {
                    // 1: start(); 2: the thread's first reread, held until the request has woken the thread
                    if (method.getName().equals("retentionSetting") && ++reads[0] == 2) {
                        rereading.countDown();
                        requested.await(5, TimeUnit.SECONDS);
                        Thread.sleep(200);
                    }
                    try {
                        return method.invoke(bridge, arguments);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
            // Long enough that a busy machine's delays can't pass for a missed wake-up, which waits a whole interval
            long pollMillis = 20_000;
            scheduler = new AutoPurgeScheduler(slowSettings, log, clock, () -> ZoneId.of("UTC"), pollMillis);
            scheduler.start();
            assertTrue(rereading.await(5, TimeUnit.SECONDS));
            new Thread(() -> {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    return;
                }
                requested.countDown();
            }).start();

            long started = System.nanoTime();
            long removed = scheduler.runNow(cutoff, 2 * pollMillis);
            long elapsedMillis = (System.nanoTime() - started) / 1_000_000;

            assertEquals(10, removed);
            assertTrue(elapsedMillis < pollMillis / 2, "runNow took " + elapsedMillis + " ms, about a poll interval");
        }

        @Test
        @DisplayName("should report a requested purge that stopped early")
        void runNowStopped() throws Exception {
            useDatabase();
            database.insert("block", new long[]{1, 2}, new long[]{1, 2});
            bridge.leasePolicy = number -> Lease.stop(StopReason.MANUAL_PURGE);
            start();

            IllegalStateException thrown = assertThrows(IllegalStateException.class, () -> scheduler.runNow(10, 10_000));

            assertEquals("Auto-purge stopped because a manual purge started after removing 0 rows", thrown.getMessage());
            awaitMessage("Auto-purge stopped because a manual purge started. It continues at the next run: "
                + "2026-09-25 00:00 (server time).");
        }

        @Test
        @DisplayName("should clean up orphans at the next run after one that couldn't tell whether there were any")
        void orphansUnknown() throws Exception {
            useDatabase();
            database.insert("block", new long[]{1, 2}, new long[]{1, NOW.getEpochSecond()});
            bridge.entitySpawns = true;
            bridge.entitySpawnsUnknown = true;
            start();

            assertEquals(1, scheduler.runNow(10, 10_000));
            assertEquals(0, bridge.exclusiveLeases.get(), "no orphan cleanup while it can't tell");

            bridge.entitySpawnsUnknown = false;
            assertEquals(0, scheduler.runNow(10, 10_000));
            assertTrue(bridge.exclusiveLeases.get() > 0, "the orphan cleanup ran, though nothing expired");
        }

        @Test
        @DisplayName("should warn when a purge stops because this CoreProtect build can't purge the database, saying why")
        void runNowUnsupported() throws Exception {
            useDatabase();
            database.insert("block", new long[]{1, 2}, new long[]{1, 2});
            bridge.stopReason = StopReason.UNSUPPORTED_DATABASE;
            bridge.unavailable = "CoreProtect uses a database engine that LibreProtect doesn't know";
            start();

            assertThrows(IllegalStateException.class, () -> scheduler.runNow(10, 10_000));

            awaitMessage("WARNING: Auto-purge stopped because LibreProtect can't purge this database with this"
                + " CoreProtect build (CoreProtect uses a database engine that LibreProtect doesn't know). It continues"
                + " at the next run: 2026-09-25 00:00 (server time).");
            assertEquals(0, bridge.leases.get());
        }

        @Test
        @DisplayName("should stop the purge when auto-purge's retention changes during it")
        void settingsChange() throws Exception {
            useDatabase();
            database.insertRange("block", 1, 30_000, 1);
            database.insert("block", new long[]{30_001}, new long[]{NOW.getEpochSecond()});
            bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> {
                if (sql.startsWith("DELETE")) {
                    bridge.retention = "90d";
                }
            });
            start();

            IllegalStateException thrown = assertThrows(IllegalStateException.class, () -> scheduler.runNow(100, 10_000));

            assertTrue(thrown.getMessage().startsWith("Auto-purge stopped because its settings changed"), thrown.getMessage());
        }

        @Test
        @DisplayName("should refuse to run once stopped")
        void runNowAfterStop() throws SQLException {
            useDatabase();
            start();
            scheduler.stop();

            assertThrows(IllegalStateException.class, () -> scheduler.runNow(10, 1_000));
        }
    }

    @Nested
    @DisplayName("stopping")
    class Stopping {

        @Test
        @DisplayName("should end the thread promptly while it waits")
        void promptly() throws SQLException {
            useDatabase();
            start();

            long started = System.nanoTime();
            scheduler.stop();
            awaitTrue(() -> !scheduler.isAlive(), "the thread ends");

            assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2));
            assertEquals(0, bridge.abandoned.get());
        }

        @Test
        @DisplayName("should wait up to the bridge's timeout for a stuck purge, then give up the gate (CoreProtect 24)")
        void abandonsStuckPurge() throws Exception {
            useDatabase();
            database.insert("block", new long[]{1, 2}, new long[]{1, NOW.getEpochSecond()});
            bridge.stopTimeoutMillis = 300;
            CountDownLatch stuck = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> {
                if (sql.startsWith("DELETE")) {
                    stuck.countDown();
                    // Like a statement that ignores cancellation
                    try {
                        release.await();
                    } catch (InterruptedException ignored) {
                    }
                }
            });
            start();
            Thread requester = new Thread(() -> {
                try {
                    scheduler.runNow(10, 30_000);
                } catch (Exception ignored) {
                }
            });
            requester.start();
            assertTrue(stuck.await(10, TimeUnit.SECONDS));

            long started = System.nanoTime();
            scheduler.stop();
            long waited = System.nanoTime() - started;

            assertTrue(waited >= TimeUnit.MILLISECONDS.toNanos(250) && waited < TimeUnit.SECONDS.toNanos(5), "waited " + waited);
            assertEquals(1, bridge.abandoned.get());
            assertEquals(List.of("WARNING: Auto-purge didn't stop within 1 second. Shutdown goes on without it."),
                log.containing("didn't stop"));
            release.countDown();
            requester.join(10_000);
        }

        @Test
        @DisplayName("should not wait for a purge when CoreProtect waits for its claims (CoreProtect 25)")
        void doesNotWait() throws Exception {
            useDatabase();
            database.insert("block", new long[]{1, 2}, new long[]{1, NOW.getEpochSecond()});
            CountDownLatch stuck = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> {
                if (sql.startsWith("DELETE")) {
                    stuck.countDown();
                    try {
                        release.await();
                    } catch (InterruptedException ignored) {
                    }
                }
            });
            start();
            Thread requester = new Thread(() -> {
                try {
                    scheduler.runNow(10, 30_000);
                } catch (Exception ignored) {
                }
            });
            requester.start();
            assertTrue(stuck.await(10, TimeUnit.SECONDS));

            long started = System.nanoTime();
            scheduler.stop();

            assertTrue(System.nanoTime() - started < TimeUnit.MILLISECONDS.toNanos(200));
            assertTrue(scheduler.isAlive());
            release.countDown();
            awaitTrue(() -> !scheduler.isAlive(), "the purge notices the stop");
            awaitMessage("Auto-purge stopped because the server is shutting down");
            assertEquals(0, bridge.abandoned.get());
            requester.join(10_000);
        }
    }

    @Test
    @DisplayName("describeDuration should round to seconds, minutes or hours")
    void durations() {
        assertEquals("less than a second", AutoPurgeScheduler.describeDuration(999));
        assertEquals("1 s", AutoPurgeScheduler.describeDuration(1_000));
        assertEquals("42 s", AutoPurgeScheduler.describeDuration(42_000));
        assertEquals("3 min 5 s", AutoPurgeScheduler.describeDuration(185_000));
        assertEquals("2 h 4 min", AutoPurgeScheduler.describeDuration(7_445_000));
        assertEquals("1,234 rows", AutoPurgeScheduler.rows(1234));
        assertEquals("1 row", AutoPurgeScheduler.rows(1));
    }
}
