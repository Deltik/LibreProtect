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

package net.deltik.mc.libreprotect.extension.migration;

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.extension.common.Console;
import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.FakeBridge.FakeSession;
import net.deltik.mc.libreprotect.testutil.RecordingSender;
import net.deltik.mc.libreprotect.testutil.SilentServer;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.bukkit.command.ConsoleCommandSender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * A migration must notice a stop request, such as the server shutting down,
 * within seconds, even while a database doesn't answer: CoreProtect's
 * shutdown waits for the migration, and its queue with it.
 */
class MigrationStallTest {

    @TempDir
    Path folder;

    private RecordingSender console;

    @BeforeEach
    void setUp() {
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(new TestLogger());
        console = new RecordingSender(ConsoleCommandSender.class);
    }

    @AfterEach
    void tearDown() {
        LibreProtectLogger.reset();
    }

    @Test
    @DisplayName("should stop within seconds of a stop request while a MySQL target doesn't answer")
    void stopsWhileTargetIsSilent() throws Exception {
        File source = folder.resolve("database.db").toFile();
        TestDatabases.createLegacySqlite(source, 100);
        try (SilentServer silent = new SilentServer()) {
            FakeSession session = new FakeSession(DatabaseSettings.embedded(Engine.SQLITE, source),
                DatabaseSettings.server(Engine.MYSQL, "127.0.0.1", silent.port(), "coreprotect", "coreprotect",
                    "secret", false, "co_"));
            Migration migration = new Migration(new FakeBridge(session), session, new Console(console.sender()),
                Engine.MYSQL, false, System::nanoTime, new Random(1));
            Thread worker = new Thread(migration, "LibreProtect migration");
            worker.start();
            assertTrue(silent.awaitConnection(10), "the migration connects to the target");
            Thread.sleep(1_000);

            // What the bridges' stopReason() says once CoreProtect's shutdown begins
            session.stopReason = "the server is stopping";
            long stopped = System.nanoTime();
            worker.join(5_000);
            long waited = (System.nanoTime() - stopped) / 1_000_000;

            assertFalse(worker.isAlive(), "the migration still waited for the target " + waited + " ms after the stop"
                + " request. Console: " + console.text());
            assertTrue(console.text().contains("Migration failed. The migration stopped because the server is"
                + " stopping."), console.text());
            assertEquals(0, session.pauses.get(), "CoreProtect was paused for a target that doesn't answer");
            assertEquals(1, session.closes.get());
        }
    }
}
