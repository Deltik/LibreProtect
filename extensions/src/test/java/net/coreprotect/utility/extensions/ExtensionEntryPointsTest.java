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

package net.coreprotect.utility.extensions;

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.PrivacyConstants;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.junit.jupiter.api.*;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.*;

class ExtensionEntryPointsTest {

    private TestLogger testLogger;

    @BeforeEach
    void setUp() {
        LibreProtectLogger.reset();
        testLogger = new TestLogger();
        LibreProtectLogger.initialize(testLogger);
    }

    @AfterEach
    void tearDown() {
        LibreProtectLogger.reset();
    }

    /**
     * A minimal {@link CommandSender} that records what is done to it.
     */
    private static final class RecordingSender {
        final List<String> messages = new ArrayList<>();
        final Set<String> methodsCalled = new TreeSet<>();
        final CommandSender sender;

        RecordingSender(Class<? extends CommandSender> type) {
            sender = type.cast(Proxy.newProxyInstance(
                ExtensionEntryPointsTest.class.getClassLoader(),
                new Class<?>[]{type},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "equals":
                            return proxy == args[0];
                        case "hashCode":
                            return System.identityHashCode(proxy);
                        case "toString":
                            return "RecordingSender";
                        default:
                            break;
                    }
                    methodsCalled.add(method.getName());
                    if (method.getName().equals("sendMessage")
                        && method.getParameterCount() == 1
                        && method.getParameterTypes()[0] == String.class) {
                        messages.add((String) args[0]);
                        return null;
                    }
                    if (method.getName().equals("getName")) {
                        return "CONSOLE";
                    }
                    throw new UnsupportedOperationException(method.toString());
                }));
        }

        List<String> plainMessages() {
            List<String> plain = new ArrayList<>();
            for (String message : messages) {
                plain.add(ChatColor.stripColor(message));
            }
            return plain;
        }
    }

    @Nested
    @DisplayName("DatabaseMigration.runCommand")
    class DatabaseMigrationEntryPoint {

        @Test
        @DisplayName("should keep the signature that upstream calls reflectively")
        void signature() throws NoSuchMethodException {
            Method method = DatabaseMigration.class.getMethod("runCommand", CommandSender.class, String[].class);
            assertTrue(Modifier.isStatic(method.getModifiers()));
            assertTrue(Modifier.isPublic(method.getModifiers()));
            assertEquals(void.class, method.getReturnType());
        }

        @Test
        @DisplayName("should show the console its usage")
        void usage() {
            RecordingSender recorder = new RecordingSender(ConsoleCommandSender.class);

            DatabaseMigration.runCommand(recorder.sender, new String[]{"migrate-db"});

            List<String> plain = recorder.plainMessages();
            assertTrue(plain.get(0).startsWith(PrivacyConstants.FORK_NAME + " - Usage: /co migrate-db <"),
                plain.toString());
            assertTrue(plain.get(0).endsWith("> [--full-validation]"), plain.toString());
        }

        @Test
        @DisplayName("should use CoreProtect's chat prefix style with LibreProtect's name")
        void usesChatColors() {
            RecordingSender recorder = new RecordingSender(ConsoleCommandSender.class);

            DatabaseMigration.runCommand(recorder.sender, new String[]{"migrate-db"});

            assertTrue(recorder.messages.get(0).startsWith(
                ChatColor.DARK_AQUA + PrivacyConstants.FORK_NAME + " " + ChatColor.WHITE + "- "));
        }

        @Test
        @DisplayName("should only take the command from the console, and only send messages to anyone else")
        void consoleOnly() {
            for (String[] args : new String[][]{
                {"migrate-db", "sqlite"},
                {"migrate-db", "mysql"},
                {"migrate-db"},
                {}
            }) {
                RecordingSender recorder = new RecordingSender(CommandSender.class);

                assertDoesNotThrow(() -> DatabaseMigration.runCommand(recorder.sender, args));

                assertEquals(Set.of("sendMessage"), recorder.methodsCalled, String.join(" ", args));
                assertEquals(List.of(PrivacyConstants.FORK_NAME + " - Only the server console can run /co migrate-db."),
                    recorder.plainMessages());
            }
        }

        @Test
        @DisplayName("should never throw, even where CoreProtect isn't running")
        void neverThrows() {
            boolean running = net.coreprotect.config.ConfigHandler.serverRunning;
            net.coreprotect.config.ConfigHandler.serverRunning = false;
            try {
                for (String[] args : new String[][]{{"migrate-db", "sqlite"}, {"migrate-db", "mysql", "--full-validation"}}) {
                    RecordingSender recorder = new RecordingSender(ConsoleCommandSender.class);

                    assertDoesNotThrow(() -> DatabaseMigration.runCommand(recorder.sender, args));

                    assertFalse(recorder.messages.isEmpty(), String.join(" ", args));
                }
            } finally {
                net.coreprotect.config.ConfigHandler.serverRunning = running;
            }
        }

        @Test
        @DisplayName("should not log anything for its usage")
        void logsNothing() {
            DatabaseMigration.runCommand(new RecordingSender(ConsoleCommandSender.class).sender, new String[]{"migrate-db"});
            assertTrue(testLogger.getRecords().isEmpty());
        }

        @Test
        @DisplayName("should not be instantiable")
        void notInstantiable() throws NoSuchMethodException {
            assertTrue(Modifier.isPrivate(DatabaseMigration.class.getDeclaredConstructor().getModifiers()));
            assertTrue(Modifier.isFinal(DatabaseMigration.class.getModifiers()));
        }
    }

    @Nested
    @DisplayName("BackgroundService")
    class BackgroundServiceEntryPoint {

        @Test
        @DisplayName("should keep the signatures that upstream calls reflectively")
        void signatures() throws NoSuchMethodException {
            for (String name : new String[]{"start", "stop"}) {
                Method method = BackgroundService.class.getMethod(name);
                assertTrue(Modifier.isStatic(method.getModifiers()), name);
                assertTrue(Modifier.isPublic(method.getModifiers()), name);
                assertEquals(void.class, method.getReturnType(), name);
            }
        }

        @Test
        @DisplayName("stop() should be safe without start(), and more than once")
        void stopWithoutStart() {
            assertDoesNotThrow(BackgroundService::stop);
            assertDoesNotThrow(BackgroundService::stop);
            assertTrue(testLogger.getRecords().isEmpty(), () -> testLogger.getMessages().toString());
        }

        @Test
        @DisplayName("start() and stop() should not throw, and stay silent while auto-purge isn't configured")
        void startAndStop() throws InterruptedException {
            try {
                assertDoesNotThrow(BackgroundService::start);
                assertDoesNotThrow(BackgroundService::start);
            } finally {
                assertDoesNotThrow(BackgroundService::stop);
            }
            long deadline = System.nanoTime() + 10_000_000_000L;
            while (autoPurgeThreads() > 0 && System.nanoTime() < deadline) {
                Thread.sleep(5);
            }
            assertEquals(0, autoPurgeThreads(), "stop() ends the auto-purge thread");
            assertTrue(testLogger.getRecords().isEmpty(), () -> testLogger.getMessages().toString());
        }

        private long autoPurgeThreads() {
            return Thread.getAllStackTraces().keySet().stream()
                .filter(thread -> thread.getName().equals("LibreProtect auto-purge") && thread.isAlive())
                .count();
        }

        @Test
        @DisplayName("should not be instantiable")
        void notInstantiable() throws NoSuchMethodException {
            assertTrue(Modifier.isPrivate(BackgroundService.class.getDeclaredConstructor().getModifiers()));
            assertTrue(Modifier.isFinal(BackgroundService.class.getModifiers()));
        }
    }
}
