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

package net.deltik.mc.libreprotect.extension.upstream;

import net.coreprotect.config.ConfigHandler;
import net.coreprotect.consumer.Consumer;
import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.ForwardingSink;
import net.deltik.mc.libreprotect.extension.migration.MigrationException;
import net.deltik.mc.libreprotect.extension.migration.MigrationSession;
import net.deltik.mc.libreprotect.extension.migration.RowSink;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.testutil.AssumeCapability;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The claim, pause and release of a migration on a CoreProtect with a
 * database reload lifecycle, such as CoreProtect 25, on its real lifecycle,
 * each on the thread the migration uses.
 */
class ReloadLifecyclePauseTest extends MigrationSessionContract {

    private static final String PURGE_RUNNING = "A purge is running, perhaps an automatic one. Try again once it has"
        + " finished.";

    @BeforeAll
    static void assumeReloadLifecycle() {
        AssumeCapability.strategy("migrate-db.protocol", "reload-lifecycle");
    }

    @Override
    String selecting(Engine engine) {
        return "database-type: " + engine.configName();
    }

    @Override
    String markedAgain() {
        return "The target is marked as an unfinished migration again, so CoreProtect refuses to use it.";
    }

    @Override
    boolean markedUnfinished(File target) throws Exception {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + target);
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("SELECT status FROM co_database_lock WHERE rowid = 1")) {
            assertTrue(result.next());
            return result.getInt(1) == Lifecycle.incompleteStatus();
        }
    }

    @Override
    boolean held() {
        return Lifecycle.isDatabaseReloadPaused();
    }

    @AfterEach
    void tearDown() {
        Consumer.initialize();
    }

    @FunctionalInterface
    private interface Work {
        void run() throws Exception;
    }

    /** Run on a new thread, the way MigrationCommand runs the migration */
    private static Throwable onWorker(Work work) throws InterruptedException {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread worker = new Thread(() -> {
            try {
                work.run();
            } catch (Throwable e) {
                failure.set(e);
            }
        }, "LibreProtect migration");
        worker.start();
        worker.join(30_000);
        assertFalse(worker.isAlive());
        return failure.get();
    }

    /** What /co reload needs: a reload can begin and the lifecycle lock can be taken */
    private static void assertReloadPossible() throws Exception {
        assertFalse(ConfigHandler.migrationRunning);
        assertFalse(Lifecycle.isDatabaseReloadRunning());
        assertFalse(Lifecycle.isDatabaseReloadPaused());
        assertEquals("STARTED", Lifecycle.beginDatabaseReload());
        assertTrue(Lifecycle.lockDatabaseReload(1_000L));
        Lifecycle.endDatabaseReload(true);
    }

    @Test
    @DisplayName("should pause persistence only once the migration's thread pauses, and resume it from there")
    void pauseAndCloseOnWorker() throws Exception {
        MigrationSession session = bridge().claim(Engine.MYSQL);
        assertTrue(ConfigHandler.migrationRunning);
        assertFalse(Lifecycle.isDatabaseReloadPaused(), "persistence paused before the target was checked");
        AtomicReference<Boolean> paused = new AtomicReference<>();

        assertNull(onWorker(() -> {
            session.pause();
            paused.set(Lifecycle.isDatabaseReloadPaused());
            session.close();
        }));

        assertTrue(paused.get());
        assertReloadPossible();
    }

    @Test
    @DisplayName("should wait for an auto-purge chunk and then pause")
    void waitsForAutoPurgeChunk() throws Exception {
        CountDownLatch claimed = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Thread autoPurge = new Thread(() -> {
            assertEquals("STARTED", Lifecycle.claimBackgroundPurge(false));
            claimed.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            Lifecycle.releaseBackgroundPurge();
        }, "LibreProtect auto-purge");
        autoPurge.start();
        assertTrue(claimed.await(5, TimeUnit.SECONDS));
        MigrationSession session = bridge().claim(Engine.MYSQL);
        new Thread(() -> {
            try {
                Thread.sleep(1_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            release.countDown();
        }).start();

        assertNull(onWorker(() -> {
            session.pause();
            session.close();
        }));

        autoPurge.join(5_000);
        assertReloadPossible();
    }

    @Test
    @DisplayName("should give up on an auto-purge that doesn't let go, leaving nothing held")
    void givesUpOnAutoPurge() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch claimed = new CountDownLatch(1);
        Thread autoPurge = new Thread(() -> {
            Lifecycle.claimBackgroundPurge(false);
            claimed.countDown();
            try {
                release.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            Lifecycle.releaseBackgroundPurge();
        }, "LibreProtect auto-purge");
        autoPurge.start();
        assertTrue(claimed.await(5, TimeUnit.SECONDS));
        MigrationSession session = bridge().claim(Engine.MYSQL);

        Throwable failure = onWorker(() -> {
            try {
                session.pause();
            } finally {
                session.close();
            }
        });

        release.countDown();
        autoPurge.join(5_000);
        assertInstanceOf(MigrationException.class, failure);
        assertReloadPossible();
    }

    @Test
    @DisplayName("should refuse a manual purge rather than wait for it")
    void refusesManualPurge() {
        ConfigHandler.purgeRunning = true;
        try {
            MigrationException refusal = assertThrows(MigrationException.class, () -> bridge().claim(Engine.MYSQL));
            assertEquals(PURGE_RUNNING, refusal.getMessage());
            assertFalse(ConfigHandler.migrationRunning);
        } finally {
            ConfigHandler.purgeRunning = false;
        }
    }

    @Test
    @DisplayName("should refuse while an automatic ClickHouse purge holds the purge claim, suggesting to try again")
    void refusesAutomaticClickHousePurge() throws Exception {
        // What auto-purge's ClickHouse lease takes for its whole run
        assertEquals("STARTED", Lifecycle.claimPurge());
        try {
            MigrationException refusal = assertThrows(MigrationException.class, () -> bridge().claim(Engine.MYSQL));
            assertEquals(PURGE_RUNNING, refusal.getMessage());
            assertFalse(ConfigHandler.migrationRunning);
        } finally {
            Lifecycle.releasePurge();
        }
        assertReloadPossible();
    }

    @Test
    @DisplayName("should refuse, holding nothing, when a purge claims the database between the claim and the pause")
    void purgeClaimBeforePause() throws Exception {
        MigrationSession session = bridge().claim(Engine.MYSQL);
        // Auto-purge's ClickHouse lease, which checked migrationRunning just before the claim set it
        assertEquals("STARTED", Lifecycle.claimPurge());
        Throwable failure;
        try {
            failure = onWorker(() -> {
                try {
                    session.pause();
                } finally {
                    session.close();
                }
            });
        } finally {
            Lifecycle.releasePurge();
        }

        assertInstanceOf(MigrationException.class, failure);
        assertEquals(PURGE_RUNNING, failure.getMessage());
        assertReloadPossible();
    }

    @Test
    @DisplayName("should refuse to copy once a reload before the pause changed the target's settings")
    void reloadChangedTarget() throws Exception {
        coreProtect.set("ConfigHandler.prefixConfig", "co_").set("ConfigHandler.host", "old-mysql.example")
            .set("ConfigHandler.port", 3306).set("ConfigHandler.database", "coreprotect");
        MigrationSession session = bridge().claim(Engine.MYSQL);
        // /co reload meanwhile, as performReload does (ReloadCommand.java:67-114); its performInitialization loads
        // config.yml's edited mysql-host (ConfigHandler.java:413), which the switch would connect to
        reload(() -> ConfigHandler.host = "new-mysql.example");

        Throwable failure = onWorker(() -> {
            try {
                session.pause();
            } finally {
                session.close();
            }
        });

        assertInstanceOf(MigrationException.class, failure);
        assertTrue(failure.getMessage().contains("they now point to the MySQL database 'coreprotect' on"
            + " new-mysql.example:3306"), failure.getMessage());
        assertReloadPossible();
    }

    @Test
    @DisplayName("should refuse to copy once a reload before the pause switched CoreProtect to another database")
    void reloadSwitchedDatabase() throws Exception {
        MigrationSession session = bridge().claim(Engine.DUCKDB);
        // The docs' workflow selects the target in config.yml first, which a reload loads
        reload(() -> coreProtect.useEngine(Engine.DUCKDB));

        Throwable failure = onWorker(() -> {
            try {
                session.pause();
            } finally {
                session.close();
            }
        });

        assertInstanceOf(MigrationException.class, failure);
        assertTrue(failure.getMessage().startsWith("CoreProtect switched to its DuckDB database after the migration"
            + " began"), failure.getMessage());
        assertReloadPossible();
    }

    /** A {@code /co reload} on its own thread, through the lifecycle, that changes what {@code change} changes */
    private static void reload(Runnable change) throws InterruptedException {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread reload = new Thread(() -> {
            try {
                assertEquals("STARTED", Lifecycle.beginDatabaseReload());
                assertTrue(Lifecycle.lockDatabaseReload(1_000));
                change.run();
            } catch (Throwable e) {
                failure.set(e);
            } finally {
                Lifecycle.endDatabaseReload(true);
            }
        }, "CoreProtect reload");
        reload.start();
        reload.join(10_000);
        assertNull(failure.get());
    }

    @Test
    @DisplayName("should stop pausing when the server begins to stop, leaving nothing held")
    void shutdownDuringPause() throws Exception {
        // A consumer batch holds the lifecycle's read lock, so the migration waits for the write lock
        CountDownLatch reading = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(1);
        Thread batch = new Thread(() -> {
            Lifecycle.lockDatabaseAccess();
            reading.countDown();
            try {
                done.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            Lifecycle.unlockDatabaseAccess();
        });
        batch.start();
        assertTrue(reading.await(5, TimeUnit.SECONDS));
        MigrationSession session = bridge().claim(Engine.MYSQL);
        new Thread(() -> {
            try {
                Thread.sleep(1_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            Lifecycle.blockDatabaseReloadForShutdown();
        }).start();
        long started = System.nanoTime();

        Throwable failure = onWorker(() -> {
            try {
                session.pause();
            } finally {
                session.close();
            }
        });

        long waited = (System.nanoTime() - started) / 1_000_000;
        done.countDown();
        batch.join(5_000);
        assertInstanceOf(MigrationException.class, failure);
        assertTrue(waited < 5_000, "stopped after " + waited + " ms");
        assertFalse(ConfigHandler.migrationRunning);
        assertFalse(Lifecycle.isDatabaseReloadRunning());
    }

    @Test
    @DisplayName("should say that the server is stopping once its shutdown blocks reloads, before serverRunning clears")
    void stopsWhenShutdownBegins() throws Exception {
        MigrationSession session = bridge().claim(Engine.MYSQL);
        try {
            Lifecycle.blockDatabaseReloadForShutdown();

            assertTrue(ConfigHandler.serverRunning);
            assertEquals("the server is stopping", session.stopReason());
        } finally {
            session.close();
        }
    }

    @Test
    @DisplayName("should refuse while CoreProtect reloads its database")
    void refusesReload() {
        assertEquals("STARTED", Lifecycle.beginDatabaseReload());
        try {
            MigrationException refusal = assertThrows(MigrationException.class, () -> bridge().claim(Engine.MYSQL));

            assertEquals("CoreProtect is reloading or recovering its database. Wait for it to finish.",
                refusal.getMessage());
            assertFalse(ConfigHandler.migrationRunning);
        } finally {
            Lifecycle.endDatabaseReload(true);
        }
    }

    @Test
    @DisplayName("should switch without a hook that tidies up after it, saying what CoreProtect wasn't told")
    void switchesWithoutAHook() throws Exception {
        useMySQL();
        CoreProtectMigration bridge = new CoreProtectMigration(Capabilities.probe(Upstream.coreProtect()
            .hiding(Names.ENTITY_SPAWN_TRACKING + "#invalidateDatabaseVerification")), Runnable::run);
        MigrationSession session = bridge.claim(Engine.SQLITE);
        List<String> notes;
        try {
            DatabaseSettings settings = session.targetSettings();
            notes = session.activate(markedTarget(session, settings), settings);
        } finally {
            session.close();
        }

        assertEquals(Engine.SQLITE, bridge.activeEngine());
        assertTrue(notes.contains("CoreProtect couldn't be told to check its tracked entities against the target:"
            + " CoreProtect has no EntitySpawnTracking.invalidateDatabaseVerification()"), notes.toString());
        assertTrue(log.hasMessageContaining("check its tracked entities"), log.getMessages().toString());
    }

    @Test
    @DisplayName("should refuse after CoreProtect stopped saving events")
    void refusesHaltedPersistence() {
        coreProtect.set("Consumer.persistenceHalted", true);

        MigrationException refusal = assertThrows(MigrationException.class, () -> bridge().claim(Engine.MYSQL));

        assertEquals("CoreProtect stopped saving events after a database failure. Restart the server before"
            + " migrating.", refusal.getMessage());
        assertFalse(ConfigHandler.migrationRunning);
    }

    @Test
    @DisplayName("should stop CoreProtect saving events when it can use neither the target nor the source")
    void haltsWithoutADatabase() throws Exception {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            closedPort = socket.getLocalPort();
        }
        useMySQL();
        coreProtect.set("ConfigHandler.host", "127.0.0.1").set("ConfigHandler.port", closedPort);
        MigrationSession session = bridge().claim(Engine.SQLITE);
        DatabaseSettings settings = session.targetSettings();
        RowSink sink = markedTarget(session, settings);
        // Clearing the mark goes nowhere, so CoreProtect refuses the target; the source's server is gone
        RowSink stillMarked = new ForwardingSink(sink) {
            @Override
            public void markComplete() {
            }
        };

        MigrationException failure;
        try {
            failure = assertThrows(MigrationException.class, () -> session.activate(stillMarked, settings));
        } finally {
            sink.close();
            session.close();
        }

        assertTrue(failure.getMessage().contains("incomplete CoreProtect migration"), failure.getMessage());
        assertTrue(failure.details().get(0).startsWith("CoreProtect couldn't switch back to the MySQL database"
            + " 'coreprotect' on 127.0.0.1:" + closedPort), failure.details().toString());
        assertTrue(failure.details().get(0).contains("so it stopped saving events"), failure.details().toString());
        assertTrue(Lifecycle.isPersistenceHalted());
        assertTrue(markedUnfinished(settings.file()));
    }
}
