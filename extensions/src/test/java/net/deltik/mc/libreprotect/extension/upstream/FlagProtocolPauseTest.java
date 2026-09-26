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

import net.coreprotect.config.Config;
import net.coreprotect.config.ConfigHandler;
import net.coreprotect.consumer.Consumer;
import net.coreprotect.consumer.process.Process;
import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.MigrationException;
import net.deltik.mc.libreprotect.extension.migration.MigrationSession;
import net.deltik.mc.libreprotect.testutil.AssumeCapability;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The flag protocol of a CoreProtect without a database reload lifecycle,
 * such as CoreProtect 24, against CoreProtect's real consumer thread, flags
 * and startup lock check.
 */
class FlagProtocolPauseTest extends MigrationSessionContract {

    private File source;

    @BeforeAll
    static void assumeFlagProtocol() {
        AssumeCapability.strategy("migrate-db.protocol", "flag-protocol");
    }

    @Override
    String selecting(Engine engine) {
        return "use-mysql: " + (engine == Engine.MYSQL);
    }

    @Override
    String markedAgain() {
        return "The target is marked as an unfinished migration again, so CoreProtect refuses to start on it.";
    }

    /**
     * @return whether CoreProtect's startup check (ConfigHandler.java:538) refuses the database; it refuses it after
     *         15 seconds while it finds such a row, and the check itself needs a server to print its messages
     */
    @Override
    boolean markedUnfinished(File target) throws SQLException {
        return lockedAt(target, (int) (System.currentTimeMillis() / 1000L) - 15);
    }

    @Override
    boolean held() {
        return Consumer.isPaused && ConfigHandler.purgeRunning;
    }

    private static boolean lockedAt(File target, int checkTime) throws SQLException {
        try (Connection connection = open(target); Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("SELECT * FROM co_database_lock WHERE rowid='1' AND"
                 + " status='1' AND time >= '" + checkTime + "' LIMIT 1")) {
            return result.next();
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        source = directory.resolve("database.db").toFile();
        try (Connection connection = open(source); Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE TABLE co_database_lock (status INTEGER, time INTEGER)");
            statement.executeUpdate("INSERT INTO co_database_lock (rowid, status, time) VALUES (1, 0, 0)");
        }
    }

    @AfterEach
    void tearDown() throws Exception {
        // Let the consumer thread end, as it does when the server stops
        ConfigHandler.serverRunning = false;
        ConfigHandler.purgeRunning = false;
        ConfigHandler.migrationRunning = false;
        ConfigHandler.pauseConsumer = false;
        Consumer.isPaused = false;
        long deadline = System.nanoTime() + 10_000_000_000L;
        while (Consumer.isRunning() && System.nanoTime() < deadline) {
            Thread.sleep(50);
        }
        ConfigHandler.serverRunning = true;
    }

    private static Connection open(File file) throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:" + file.getPath());
    }

    /** @return the time CoreProtect's consumer last wrote to the source's lock row, 0 if it didn't since {@link #resetLock()} */
    private long lockTime() throws SQLException {
        try (Connection connection = open(source); Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("SELECT time FROM co_database_lock WHERE rowid = 1")) {
            result.next();
            return result.getLong(1);
        }
    }

    /** Make the consumer's next pass write the lock row, as it does at least every 15 seconds */
    private void resetLock() throws SQLException {
        try (Connection connection = open(source); Statement statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE co_database_lock SET status = 0, time = 0 WHERE rowid = 1");
        }
        Process.lastLockUpdate = 0;
    }

    private void startConsumer() throws Exception {
        Consumer.startConsumer();
        long deadline = System.nanoTime() + 10_000_000_000L;
        while (lockTime() == 0 && System.nanoTime() < deadline) {
            Thread.sleep(50);
        }
        assertNotEquals(0, lockTime(), "CoreProtect's consumer writes to the source");
    }

    /** ShutdownService.safeShutdown, lines 60 and 71-72, on the main thread */
    private static void beginShutdown() {
        ConfigHandler.serverRunning = false;
        if (ConfigHandler.migrationRunning) {
            ConfigHandler.purgeRunning = false;
        }
    }

    @Nested
    @DisplayName("holding the consumer")
    class Holding {

        @Test
        @DisplayName("should keep the consumer from writing to the source until the migration stops, once shutdown begins")
        void shutdownWaitsForTheMigration() throws Exception {
            startConsumer();
            MigrationSession session = bridge().claim(Engine.MYSQL);
            session.pause();
            resetLock();

            beginShutdown();
            Thread.sleep(2_000);
            assertEquals(0, lockTime(), "the consumer wrote to the source while the migration still ran");

            session.close();
            Thread.sleep(2_000);
            assertNotEquals(0, lockTime(), "the consumer saves its queue to the source once the migration stops");
        }

        @Test
        @DisplayName("should keep the consumer from writing after shutdown begins, even once a lookup let go of the gate")
        void shutdownWaitsForTheMigrationAfterALookup() throws Exception {
            startConsumer();
            MigrationSession session = bridge().claim(Engine.MYSQL);
            session.pause();
            resetLock();

            // Lookups, reloads and auto-purge's SQLite chunks all clear the gate they share with the migration
            Consumer.isPaused = false;
            Thread.sleep(1_000);
            assertEquals(0, lockTime(), "the consumer wrote to the source during the migration");

            beginShutdown();
            Thread.sleep(2_000);
            long written = lockTime();
            session.close();
            assertEquals(0, written, "the consumer wrote to the source while the migration still ran, and could still"
                + " switch CoreProtect to the target");
            assertFalse(ConfigHandler.pauseConsumer, "the consumer's own pause setting wasn't restored");
        }

        @Test
        @DisplayName("should wait for work that holds CoreProtect's database gate before copying the source")
        void pauseWaitsForGateHolders() throws Exception {
            startConsumer();
            // Auto-purge's chunk on SQLite, like a lookup or a reload, holds the gate while it works
            CountDownLatch holding = new CountDownLatch(1);
            Thread chunk = new Thread(() -> {
                try (Connection connection = open(source); Statement statement = connection.createStatement()) {
                    while (Consumer.isPaused) {
                        Thread.sleep(1);
                    }
                    Consumer.isPaused = true;
                    holding.countDown();
                    connection.setAutoCommit(false);
                    statement.executeUpdate("UPDATE co_database_lock SET status = status WHERE rowid = 1");
                    Thread.sleep(2_000);
                    connection.commit();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                } finally {
                    Consumer.isPaused = false;
                }
            }, "LibreProtect auto-purge");
            chunk.start();
            assertTrue(holding.await(5, TimeUnit.SECONDS));
            MigrationSession session = bridge().claim(Engine.MYSQL);
            long started = System.nanoTime();
            session.pause();
            long waited = (System.nanoTime() - started) / 1_000_000;
            boolean chunkRunning = chunk.isAlive();
            boolean gateHeld = Consumer.isPaused;
            chunk.join();
            session.close();
            assertFalse(chunkRunning, "the pause returned after " + waited + " ms while a chunk that holds the gate"
                + " still wrote to the source");
            assertTrue(gateHeld, "the migration didn't take the gate");
            assertFalse(Consumer.isPaused, "the migration didn't release the gate");
        }

        @Test
        @DisplayName("should hold purges only from the server's thread, and release everything it held")
        void holdsAndReleases() throws Exception {
            ConfigHandler.pauseConsumer = true;
            List<String> threads = new ArrayList<>();
            CoreProtectMigration bridge = new CoreProtectMigration(Capabilities.current(), task -> {
                threads.add(Thread.currentThread().getName());
                task.run();
            });

            MigrationSession session = bridge.claim(Engine.MYSQL);
            assertTrue(ConfigHandler.migrationRunning);
            assertFalse(ConfigHandler.purgeRunning, "lookups stopped before the migration checked its target");
            session.pause();
            assertTrue(ConfigHandler.purgeRunning);
            assertTrue(Consumer.isPaused);
            assertEquals(1, threads.size());
            session.close();

            assertFalse(ConfigHandler.purgeRunning);
            assertFalse(ConfigHandler.migrationRunning);
            assertFalse(Consumer.isPaused);
            assertTrue(ConfigHandler.pauseConsumer, "the consumer's own pause setting wasn't restored");
        }

        @Test
        @DisplayName("should let a rollback that began before the pause finish its lookups before taking the gate")
        void waitsForRollbackBeforeTheGate() throws Exception {
            MigrationSession session = bridge().claim(Engine.MYSQL);
            // /co rollback, accepted before the pause: the main thread registers it (RollbackRestoreCommand.java:346),
            // and its thread looks up blocks, then items, each through the gate (Lookup.java:24-27)
            ConfigHandler.activeRollbacks.put("Staff", true);
            AtomicBoolean lookedUp = new AtomicBoolean();
            Thread rollback = new Thread(() -> {
                try {
                    // Its next lookup comes once the migration is pausing
                    while (!ConfigHandler.purgeRunning) {
                        Thread.sleep(1);
                    }
                    Thread.sleep(1_000);
                    while (Consumer.isPaused) {
                        Thread.sleep(1);
                    }
                    Consumer.isPaused = true;
                    lookedUp.set(true);
                    Consumer.isPaused = false;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    ConfigHandler.activeRollbacks.remove("Staff");
                }
            }, "CoreProtect rollback");
            rollback.start();
            AtomicReference<Throwable> failure = new AtomicReference<>();
            AtomicBoolean gateHeld = new AtomicBoolean();
            // The migration's thread releases what it held itself
            Thread worker = new Thread(() -> {
                try {
                    session.pause();
                    gateHeld.set(Consumer.isPaused);
                } catch (Throwable e) {
                    failure.set(e);
                } finally {
                    session.close();
                }
            }, "LibreProtect migration");

            worker.start();
            worker.join(10_000);
            boolean stillPausing = worker.isAlive();
            if (stillPausing) {
                // End the wait, as the pause's own timeout would after 2 minutes
                beginShutdown();
                worker.join(5_000);
            }
            rollback.join(5_000);

            assertFalse(stillPausing, "the migration still waits for the rollback, which waits for the gate it holds");
            assertNull(failure.get());
            assertTrue(lookedUp.get(), "the rollback's lookup didn't run");
            assertTrue(gateHeld.get(), "the migration didn't take the gate after the rollback");
        }

        @Test
        @DisplayName("should refuse to copy once a reload before the pause switched CoreProtect to another database")
        void reloadSwitchedDatabase() throws Exception {
            String selected = "use-mysql: true\nmysql-host: 127.0.0.1\ndatabase-lock: true\n";
            Files.writeString(config, selected);
            MigrationSession session = bridge().claim(Engine.MYSQL);
            // /co reload, accepted before the pause, on its own thread: it takes the gate (ReloadCommand.java:40-43),
            // and its performInitialization reads use-mysql: true and loads MySQL (ConfigHandler.java:236-252,
            // 261-329), then lets go of the gate (:55)
            CountDownLatch reloading = new CountDownLatch(1);
            Thread reload = new Thread(() -> {
                try {
                    while (Consumer.isPaused) {
                        Thread.sleep(1);
                    }
                    Consumer.isPaused = true;
                    reloading.countDown();
                    Thread.sleep(500);
                    Config.getGlobal().MYSQL = true;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    Consumer.isPaused = false;
                }
            }, "CoreProtect reload");
            reload.start();
            assertTrue(reloading.await(5, TimeUnit.SECONDS));

            MigrationException refusal;
            try {
                refusal = assertThrows(MigrationException.class, session::pause);
            } finally {
                reload.join();
                session.close();
            }

            assertTrue(refusal.getMessage().startsWith("CoreProtect switched to its MySQL database after the migration"
                + " began"), refusal.getMessage());
            assertEquals(selected, Files.readString(config), "the pause changed config.yml");
            assertFalse(ConfigHandler.purgeRunning);
            assertFalse(ConfigHandler.migrationRunning);
            assertFalse(Consumer.isPaused);
        }

        @Test
        @DisplayName("should refuse to copy once a reload before the pause changed the source's settings")
        void reloadChangedSettings() throws Exception {
            coreProtect.useEngine(Engine.MYSQL).set("ConfigHandler.host", "mysql-a.example")
                .set("ConfigHandler.port", 3306).set("ConfigHandler.database", "coreprotect")
                .set("ConfigHandler.username", "coreprotect").set("ConfigHandler.password", "secret");
            MigrationSession session = bridge().claim(Engine.SQLITE);
            // What /co reload's loadConfig does after mysql-host was edited (ConfigHandler.java:245)
            ConfigHandler.host = "mysql-b.example";

            MigrationException refusal;
            try {
                refusal = assertThrows(MigrationException.class, session::pause);
            } finally {
                session.close();
            }

            assertTrue(refusal.getMessage().contains("it now uses the MySQL database 'coreprotect' on"
                + " mysql-b.example:3306"), refusal.getMessage());
            assertFalse(ConfigHandler.purgeRunning);
            assertFalse(ConfigHandler.migrationRunning);
        }

        @Test
        @DisplayName("should refuse to copy once config.yml's target changed after the migration began")
        void targetChangedBeforePause() throws Exception {
            Files.writeString(config, "use-mysql: false\nmysql-host: mysql-a.example\ndatabase-lock: true\n");
            MigrationSession session = bridge().claim(Engine.MYSQL);
            DatabaseSettings target = session.targetSettings();
            Files.writeString(config, "use-mysql: false\nmysql-host: mysql-b.example\ndatabase-lock: true\n");

            MigrationException refusal;
            try {
                refusal = assertThrows(MigrationException.class, session::pause);
            } finally {
                session.close();
            }

            assertEquals("mysql-a.example", target.host());
            assertTrue(refusal.getMessage().startsWith("config.yml's MySQL settings changed after the migration"
                + " began: they now point to the MySQL database 'database' on mysql-b.example:3306"),
                refusal.getMessage());
            assertFalse(ConfigHandler.purgeRunning);
        }

        @Test
        @DisplayName("should refuse while a purge runs, suggesting to try again, and hold nothing")
        void refusesPurge() {
            ConfigHandler.purgeRunning = true;

            MigrationException refusal = assertThrows(MigrationException.class, () -> bridge().claim(Engine.MYSQL));

            assertEquals("A purge is running. Try again once it has finished.", refusal.getMessage());
            assertFalse(ConfigHandler.migrationRunning);
            assertFalse(ConfigHandler.pauseConsumer);
            assertFalse(Consumer.isPaused);
        }

        @Test
        @DisplayName("should never hold purges once shutdown begins, even if the server's thread runs its task late")
        void noHoldAfterShutdown() throws Exception {
            AtomicReference<Runnable> deferred = new AtomicReference<>();
            MigrationSession session = new CoreProtectMigration(Capabilities.current(), deferred::set)
                .claim(Engine.MYSQL);
            AtomicReference<Throwable> failure = new AtomicReference<>();
            Thread worker = new Thread(() -> {
                try {
                    session.pause();
                } catch (Throwable e) {
                    failure.set(e);
                } finally {
                    session.close();
                }
            }, "LibreProtect migration");
            worker.start();
            Thread.sleep(500);

            beginShutdown();
            worker.join(5_000);
            deferred.get().run();

            assertInstanceOf(MigrationException.class, failure.get());
            assertFalse(ConfigHandler.purgeRunning, "a purge flag set after shutdown began ends its wait for the queue");
            assertFalse(ConfigHandler.migrationRunning);
        }
    }

    @Nested
    @DisplayName("the unfinished target")
    class UnfinishedTarget {

        @Test
        @DisplayName("should mark the target so that CoreProtect 24 refuses to start on it")
        void startupRefusesMarkedTarget() throws Exception {
            useMySQL();
            MigrationSession session = bridge().claim(Engine.SQLITE);
            File target = directory.resolve("target.db").toFile();
            try {
                markedTarget(session, DatabaseSettings.embedded(Engine.SQLITE, target)).close();
            } finally {
                session.close();
            }

            assertTrue(markedUnfinished(target), "CoreProtect 24 would start on the unfinished target");
            // The same query 100 years from now
            int later = (int) (System.currentTimeMillis() / 1000L) - 15 + 100 * 365 * 24 * 3600;
            assertTrue(lockedAt(target, later), "the mark expires");
        }
    }

    @Nested
    @DisplayName("config.yml")
    class ConfigYml {

        @Test
        @DisplayName("should select the source while copying, when the docs' workflow selected the target already")
        void selectsSourceWhileCopying() throws Exception {
            Files.writeString(config, "# Selected as the docs say\nuse-mysql: true\ndatabase-lock: true\n");
            MigrationSession session = bridge().claim(Engine.MYSQL);
            try {
                List<String> notes = session.pause();

                assertEquals("# Selected as the docs say\nuse-mysql: false\ndatabase-lock: true\n",
                    Files.readString(config));
                assertEquals(1, notes.size());
                assertTrue(notes.get(0).startsWith("config.yml selects SQLite (use-mysql: false) while the migration"
                    + " runs"), notes.get(0));
            } finally {
                session.close();
            }
        }

        @Test
        @DisplayName("should select the database CoreProtect uses again after a failure")
        void selectsSourceAfterFailure() throws Exception {
            Files.writeString(config, "use-mysql: true\r\ndatabase-lock: true\r\n");
            MigrationSession session = bridge().claim(Engine.MYSQL);

            List<String> notes = session.afterFailure();
            session.close();

            assertEquals("use-mysql: false\r\ndatabase-lock: true\r\n", Files.readString(config));
            assertEquals(List.of("config.yml selects SQLite again (use-mysql: false), the database CoreProtect uses."),
                notes);
        }

        @Test
        @DisplayName("should refuse to start when config.yml can't be replaced, such as a symbolic link")
        void preflightRefusesSymbolicLink() throws Exception {
            Path real = Files.writeString(directory.resolve("real.yml"), "use-mysql: false\n", StandardCharsets.UTF_8);
            Files.delete(config);
            Files.createSymbolicLink(config, real);
            MigrationSession session = bridge().claim(Engine.MYSQL);
            try {
                MigrationException refusal = assertThrows(MigrationException.class, session::preflight);
                assertTrue(refusal.getMessage().contains("is not a regular file"), refusal.getMessage());
            } finally {
                session.close();
            }
        }
    }
}
