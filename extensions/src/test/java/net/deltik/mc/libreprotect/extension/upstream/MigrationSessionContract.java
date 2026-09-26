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
import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.ForwardingSink;
import net.deltik.mc.libreprotect.extension.migration.MigrationException;
import net.deltik.mc.libreprotect.extension.migration.MigrationSession;
import net.deltik.mc.libreprotect.extension.migration.RowSink;
import net.deltik.mc.libreprotect.testutil.CoreProtectFixture;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.SQLRecoverableException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import static org.junit.jupiter.api.Assertions.*;

/**
 * What a migration does alike on every CoreProtect, whichever protocol it
 * follows, against CoreProtect's real classes, set up as a server would have
 * them. Only CoreProtect members that every CoreProtect has are named here;
 * each protocol's subclass, which runs only on a CoreProtect that follows
 * it, sets up the rest and adds its own scenarios.
 */
abstract class MigrationSessionContract {

    @TempDir
    Path directory;

    @RegisterExtension
    final CoreProtectFixture coreProtect = new CoreProtectFixture();

    final TestLogger log = new TestLogger();

    Path config;

    /**
     * @return the line of config.yml that selects an engine on this
     *         CoreProtect, such as {@code use-mysql: true}
     */
    abstract String selecting(Engine engine);

    /**
     * @return the note that a target whose switch failed is marked unfinished again
     */
    abstract String markedAgain();

    /**
     * @return whether CoreProtect refuses a target as an unfinished migration
     */
    abstract boolean markedUnfinished(File target) throws Exception;

    /**
     * @return whether CoreProtect's database work is held, the way the protocol holds it
     */
    abstract boolean held();

    /** A migration whose tasks for the server's thread run on the calling thread */
    static CoreProtectMigration bridge() {
        return new CoreProtectMigration(Capabilities.current(), Runnable::run);
    }

    @BeforeEach
    void setUpCoreProtect() throws Exception {
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(log);
        Config.getGlobal().ERROR_REPORTING = false;
        Config.getGlobal().DATABASE_LOCK = true;
        ConfigHandler.path = directory + File.separator;
        ConfigHandler.sqlite = "database.db";
        ConfigHandler.prefix = "co_";
        ConfigHandler.prefixConfig = "co_";
        ConfigHandler.serverRunning = true;
        ConfigHandler.purgeRunning = false;
        ConfigHandler.migrationRunning = false;
        ConfigHandler.converterRunning = false;
        ConfigHandler.pauseConsumer = false;
        ConfigHandler.activeRollbacks.clear();
        Consumer.isPaused = false;
        Consumer.initialize();
        coreProtect.useEngine(Engine.SQLITE).set("Process.lastLockUpdate", 0);
        // CoreProtect's own schema code lists the tables of this CoreProtect as it creates them
        try (Connection scratch = DriverManager.getConnection("jdbc:sqlite:" + directory.resolve("scratch.db"))) {
            Capabilities.current().require(Schema.CAPABILITY).creator(Engine.SQLITE).create(scratch, "co_");
        }
        config = directory.resolve("config.yml");
        Files.writeString(config, selecting(Engine.SQLITE) + "\ndatabase-lock: true\n");
    }

    @AfterEach
    void tearDownCoreProtect() {
        ConfigHandler.serverRunning = true;
        ConfigHandler.purgeRunning = false;
        ConfigHandler.migrationRunning = false;
        ConfigHandler.converterRunning = false;
        ConfigHandler.pauseConsumer = false;
        ConfigHandler.activeRollbacks.clear();
        Consumer.isPaused = false;
        LibreProtectLogger.reset();
    }

    /**
     * Make CoreProtect use MySQL, as it would with config.yml selecting it,
     * without connecting to it.
     */
    void useMySQL() throws IOException {
        coreProtect.useEngine(Engine.MYSQL).set("ConfigHandler.host", "mysql.example").set("ConfigHandler.port", 3306)
            .set("ConfigHandler.database", "coreprotect").set("ConfigHandler.username", "coreprotect")
            .set("ConfigHandler.password", "secret");
        Files.writeString(config, selecting(Engine.MYSQL) + "\ndatabase-lock: true\n");
    }

    /**
     * @return a target, prepared and marked unfinished like the copy leaves it
     */
    static RowSink markedTarget(MigrationSession session, DatabaseSettings settings) throws SQLException {
        RowSink sink = session.openSink(settings);
        Map<String, Long> highWater = new HashMap<>();
        for (String table : ConfigHandler.databaseTables) {
            highWater.put(table, 0L);
        }
        sink.prepare(highWater);
        sink.markIncomplete();
        return sink;
    }

    @Test
    @DisplayName("should refuse while CoreProtect isn't running, holding nothing")
    void refusesWhileStopped() {
        ConfigHandler.serverRunning = false;

        MigrationException refusal = assertThrows(MigrationException.class, () -> bridge().claim(Engine.MYSQL));

        assertEquals("CoreProtect isn't running: it didn't start, or the server is stopping.", refusal.getMessage());
        assertFalse(ConfigHandler.migrationRunning);
    }

    @Test
    @DisplayName("should refuse while another migration runs, leaving its claim alone")
    void refusesSecondMigration() {
        ConfigHandler.migrationRunning = true;

        MigrationException refusal = assertThrows(MigrationException.class, () -> bridge().claim(Engine.MYSQL));

        assertEquals("A migration is already running.", refusal.getMessage());
        assertTrue(ConfigHandler.migrationRunning);
    }

    @Test
    @DisplayName("should refuse while CoreProtect upgrades its database")
    void refusesConversion() {
        ConfigHandler.converterRunning = true;

        MigrationException refusal = assertThrows(MigrationException.class, () -> bridge().claim(Engine.MYSQL));

        assertEquals("CoreProtect is upgrading its database. Wait for it to finish.", refusal.getMessage());
        assertFalse(ConfigHandler.migrationRunning);
    }

    @Test
    @DisplayName("should refuse while a rollback or restore runs")
    void refusesRollback() {
        ConfigHandler.activeRollbacks.put("Staff", true);

        MigrationException refusal = assertThrows(MigrationException.class, () -> bridge().claim(Engine.MYSQL));

        assertEquals("A rollback or restore is running. Wait for it to finish.", refusal.getMessage());
        assertFalse(ConfigHandler.migrationRunning);
    }

    @Test
    @DisplayName("should refuse to migrate when CoreProtect wouldn't check the target's mark")
    void refusesWithoutDatabaseLock() {
        Config.getGlobal().DATABASE_LOCK = false;

        MigrationException refusal = assertThrows(MigrationException.class, () -> bridge().claim(Engine.MYSQL));

        assertTrue(refusal.getMessage().startsWith("Migrations need database-lock: true in config.yml"),
            refusal.getMessage());
        assertFalse(ConfigHandler.migrationRunning);
    }

    @Test
    @DisplayName("should refuse the engine CoreProtect already uses")
    void refusesSameEngine() {
        MigrationException refusal = assertThrows(MigrationException.class, () -> bridge().claim(Engine.SQLITE));

        assertEquals("CoreProtect already uses SQLite.", refusal.getMessage());
        assertFalse(ConfigHandler.migrationRunning);
    }

    @Test
    @DisplayName("should release its claim once, however often it's closed")
    void closesOnce() throws Exception {
        MigrationSession session = bridge().claim(Engine.MYSQL);
        assertTrue(ConfigHandler.migrationRunning);

        session.close();
        assertFalse(ConfigHandler.migrationRunning);
        // Another migration's claim, which closing this one again must not release
        ConfigHandler.migrationRunning = true;
        session.close();

        assertTrue(ConfigHandler.migrationRunning);
    }

    @Test
    @DisplayName("should say that the server is stopping once CoreProtect stops")
    void stopsWithTheServer() throws Exception {
        MigrationSession session = bridge().claim(Engine.MYSQL);
        try {
            assertNull(session.stopReason());
            ConfigHandler.serverRunning = false;

            assertEquals("the server is stopping", session.stopReason());
        } finally {
            ConfigHandler.serverRunning = true;
            session.close();
        }
    }

    @Test
    @DisplayName("should refuse to release CoreProtect from a thread other than the one that paused it")
    void releasesOnlyOnItsThread() throws Exception {
        MigrationSession session = bridge().claim(Engine.MYSQL);
        ExecutorService migration = Executors.newSingleThreadExecutor(task -> new Thread(task,
            "LibreProtect migration"));
        try {
            migration.submit(() -> session.pause()).get(30, TimeUnit.SECONDS);
            assertTrue(held(), "the pause didn't hold CoreProtect");

            session.close();
            boolean heldAfterWrongThread = held();
            boolean claimedAfterWrongThread = ConfigHandler.migrationRunning;
            migration.submit(session::close).get(30, TimeUnit.SECONDS);

            assertTrue(heldAfterWrongThread, "another thread released CoreProtect");
            assertTrue(claimedAfterWrongThread, "another thread released the claim while CoreProtect was held");
            assertTrue(log.hasMessageContaining(Level.SEVERE, "only the migration's thread may"),
                log.getMessages().toString());
            assertFalse(held(), "the migration's thread didn't release CoreProtect");
            assertFalse(ConfigHandler.migrationRunning);
        } finally {
            migration.shutdownNow();
        }
    }

    @Test
    @DisplayName("should refuse to pause or switch once closed, even from another thread, holding nothing")
    void refusesOnceClosed() throws Exception {
        MigrationSession session = bridge().claim(Engine.MYSQL);
        DatabaseSettings settings = session.targetSettings();
        ExecutorService command = Executors.newSingleThreadExecutor(task -> new Thread(task, "Server thread"));
        try {
            // Such as the command's thread releasing a claim whose migration never started
            command.submit(session::close).get(30, TimeUnit.SECONDS);
        } finally {
            command.shutdownNow();
        }

        MigrationException refusal = assertThrows(MigrationException.class, session::pause);
        assertThrows(MigrationException.class, () -> session.activate(null, settings));
        session.close();

        assertTrue(refusal.getMessage().startsWith("The migration ended already"), refusal.getMessage());
        assertFalse(held(), "a closed migration held CoreProtect, and nothing would release it");
        assertFalse(ConfigHandler.migrationRunning);
    }

    @Test
    @DisplayName("should switch back to the source when CoreProtect can't connect to the target")
    void switchesBackFromAnUnreachableTarget() throws Exception {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            closedPort = socket.getLocalPort();
        }
        // The target's settings, loaded or in config.yml, whichever this CoreProtect switches to
        coreProtect.set("ConfigHandler.host", "127.0.0.1").set("ConfigHandler.port", closedPort)
            .set("ConfigHandler.database", "coreprotect").set("ConfigHandler.username", "coreprotect")
            .set("ConfigHandler.password", "secret");
        String selected = selecting(Engine.SQLITE) + "\nmysql-host: 127.0.0.1\nmysql-port: " + closedPort
            + "\nmysql-database: coreprotect\nmysql-username: coreprotect\nmysql-password: secret\n"
            + "database-lock: true\n";
        Files.writeString(config, selected);
        CoreProtectMigration bridge = bridge();
        MigrationSession session = bridge.claim(Engine.MYSQL);
        DatabaseSettings settings = session.targetSettings();
        RowSink sink = session.openSink(settings);
        // The copy isn't what's being tested; the target never answers
        RowSink copied = new ForwardingSink(sink) {
            @Override
            public void markComplete() {
            }

            @Override
            public void close() {
            }
        };

        MigrationException failure;
        try {
            failure = assertThrows(MigrationException.class, () -> session.activate(copied, settings));
        } finally {
            sink.close();
            session.close();
        }

        assertTrue(failure.getMessage().startsWith("CoreProtect couldn't switch to the MySQL database 'coreprotect' on"
            + " 127.0.0.1:" + closedPort), failure.getMessage());
        assertEquals("CoreProtect switched back to the SQLite database " + directory.resolve("database.db") + ".",
            failure.details().get(0), failure.details().toString());
        assertTrue(failure.details().get(1).startsWith("The target couldn't be marked as an unfinished migration"
            + " again ("), failure.details().toString());
        assertEquals(Engine.SQLITE, bridge.activeEngine());
        assertEquals(selected, Files.readString(config), "the failed switch changed config.yml");
        assertFalse(ConfigHandler.migrationRunning);
    }

    @Test
    @DisplayName("should leave a target whose switch failed marked unfinished, even if clearing the mark went through")
    void failedSwitchLeavesTargetMarked() throws Exception {
        useMySQL();
        MigrationSession session = bridge().claim(Engine.SQLITE);
        DatabaseSettings settings = session.targetSettings();
        RowSink sink = markedTarget(session, settings);
        // Clearing commits, but its answer is lost, as when the watchdog aborts the connection mid-call
        RowSink answerLost = new ForwardingSink(sink) {
            @Override
            public void markComplete() throws SQLException {
                super.markComplete();
                throw new SQLRecoverableException("Communications link failure", "08S01");
            }
        };

        MigrationException failure;
        try {
            failure = assertThrows(MigrationException.class, () -> session.activate(answerLost, settings));
        } finally {
            sink.close();
            session.close();
        }

        assertTrue(markedUnfinished(settings.file()), "the migration failed, but CoreProtect would use its target");
        assertTrue(failure.details().contains(markedAgain()), failure.details().toString());
        assertEquals(Engine.MYSQL, bridge().activeEngine(), "the failed switch changed CoreProtect's database");
    }

    @Test
    @DisplayName("should refuse to switch once CoreProtect no longer uses the source, leaving the target marked")
    void switchRefusedWhenSourceNotInUse() throws Exception {
        useMySQL();
        MigrationSession session = bridge().claim(Engine.SQLITE);
        DatabaseSettings settings = session.targetSettings();
        RowSink sink = markedTarget(session, settings);
        // Such as after a reload that raced the migration
        coreProtect.useEngine(Engine.SQLITE);

        MigrationException refusal;
        try {
            refusal = assertThrows(MigrationException.class, () -> session.activate(sink, settings));
        } finally {
            sink.close();
            session.close();
        }

        assertTrue(refusal.getMessage().contains("CoreProtect didn't switch to the target."), refusal.getMessage());
        assertTrue(markedUnfinished(settings.file()));
        assertEquals(Engine.SQLITE, bridge().activeEngine());
        assertEquals(selecting(Engine.MYSQL) + "\ndatabase-lock: true\n", Files.readString(config),
            "the refused switch changed config.yml");
    }

    @Test
    @DisplayName("should switch CoreProtect to the target, and select it in config.yml once CoreProtect uses it")
    void switches() throws Exception {
        useMySQL();
        CoreProtectMigration bridge = bridge();
        MigrationSession session = bridge.claim(Engine.SQLITE);
        List<String> notes;
        DatabaseSettings settings;
        try {
            settings = session.targetSettings();
            RowSink sink = markedTarget(session, settings);
            coreProtect.set("Process.lastLockUpdate", 12345);

            notes = session.activate(sink, settings);
        } finally {
            session.close();
        }

        assertEquals(Engine.SQLITE, bridge.activeEngine());
        assertEquals(DatabaseSettings.embedded(Engine.SQLITE, directory.resolve("database.db").toFile()).describe(),
            settings.describe());
        assertFalse(markedUnfinished(settings.file()), "CoreProtect uses a target that is marked unfinished");
        assertTrue(Files.readString(config).contains(selecting(Engine.SQLITE) + "\n"), Files.readString(config));
        assertTrue(notes.get(0).startsWith("config.yml now selects SQLite ("), notes.toString());
        assertEquals(0, coreProtect.get("Process.lastLockUpdate"), "the consumer won't write the target's lock soon");
        assertFalse(ConfigHandler.migrationRunning);
    }
}
