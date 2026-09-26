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
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.MigrationCommand;
import net.deltik.mc.libreprotect.testutil.AssumeCapability;
import net.deltik.mc.libreprotect.testutil.CoreProtectFixture;
import net.deltik.mc.libreprotect.testutil.RecordingSender;
import net.deltik.mc.libreprotect.testutil.SilentServer;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.bukkit.command.ConsoleCommandSender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;

import static org.junit.jupiter.api.Assertions.*;

/**
 * CoreProtect's shutdown with a migration running, on a CoreProtect with a
 * database reload lifecycle, such as CoreProtect 25, against its real
 * consumer lifecycle and shutdown waits.
 */
class MigrationShutdownTest {

    @TempDir
    Path directory;

    @RegisterExtension
    final CoreProtectFixture coreProtect = new CoreProtectFixture();

    private RecordingSender console;

    @BeforeAll
    static void assumeReloadLifecycle() {
        AssumeCapability.strategy("migrate-db.protocol", "reload-lifecycle");
    }

    @BeforeEach
    void setUp() throws Exception {
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(new TestLogger());
        console = new RecordingSender(ConsoleCommandSender.class);
        Consumer.initialize();
        ConfigHandler.path = directory + File.separator;
        ConfigHandler.sqlite = "database.db";
        ConfigHandler.prefix = "co_";
        ConfigHandler.prefixConfig = "co_";
        ConfigHandler.serverRunning = true;
        ConfigHandler.purgeRunning = false;
        ConfigHandler.migrationRunning = false;
        ConfigHandler.converterRunning = false;
        ConfigHandler.activeRollbacks.clear();
        coreProtect.useEngine(Engine.SQLITE);
        Config.getGlobal().DATABASE_LOCK = true;
        Config.getGlobal().ENABLE_SSL = false;
        // CoreProtect's own schema code lists the tables of this CoreProtect as it creates them
        try (Connection scratch = DriverManager.getConnection("jdbc:sqlite:" + directory.resolve("scratch.db"))) {
            Capabilities.current().require(Schema.CAPABILITY).creator(Engine.SQLITE).create(scratch, "co_");
        }
        Files.writeString(directory.resolve("config.yml"), "database-type: sqlite\n");
    }

    @AfterEach
    void tearDown() {
        ConfigHandler.serverRunning = true;
        Consumer.initialize();
        LibreProtectLogger.reset();
    }

    /** ShutdownService's wait for maintenance, as if {@code remaining} milliseconds were left of its 15 minutes */
    private static void waitForMaintenance(long remaining) throws Exception {
        Class<?> shutdownService = Class.forName(Names.SHUTDOWN_SERVICE);
        Method wait = shutdownService.getDeclaredMethod("waitForMaintenanceCompletion", long.class);
        wait.setAccessible(true);
        wait.invoke(null, System.currentTimeMillis() - 15 * 60_000L + remaining);
    }

    @Test
    @DisplayName("should let CoreProtect's shutdown go on within seconds while the target doesn't answer")
    void shutdownWhileTargetIsSilent() throws Exception {
        try (SilentServer silent = new SilentServer()) {
            coreProtect.set("ConfigHandler.host", "127.0.0.1").set("ConfigHandler.port", silent.port())
                .set("ConfigHandler.database", "coreprotect").set("ConfigHandler.username", "coreprotect")
                .set("ConfigHandler.password", "secret");

            // The console runs the command on the main thread; the migration continues on its own
            MigrationCommand.run(console.sender(), new String[]{"migrate-db", "mysql"}, CoreProtectMigration.create());
            assertTrue(ConfigHandler.migrationRunning, console.text());
            assertTrue(silent.awaitConnection(10), "the migration connects to the target");
            assertFalse(Lifecycle.isDatabaseReloadPaused(), "CoreProtect paused for a target that doesn't answer");

            // ShutdownService.safeShutdown: block reloads, wait for maintenance, then for migrationRunning
            Lifecycle.blockDatabaseReloadForShutdown();
            long started = System.nanoTime();
            waitForMaintenance(20_000);
            long deadline = System.nanoTime() + 5_000_000_000L;
            while (ConfigHandler.migrationRunning && System.nanoTime() < deadline) {
                Thread.sleep(50);
            }
            long waited = (System.nanoTime() - started) / 1_000_000;

            assertFalse(ConfigHandler.migrationRunning, "after " + waited + " ms of CoreProtect's shutdown, the"
                + " migration still runs; at 15 minutes CoreProtect disables itself with the queue unsaved. Console: "
                + console.text());
            assertFalse(Lifecycle.isDatabaseReloadRunning());
            assertFalse(Lifecycle.isDatabaseReloadPaused());
            assertTrue(console.text().contains("The migration stopped because the server is stopping."),
                console.text());
        }
    }
}
