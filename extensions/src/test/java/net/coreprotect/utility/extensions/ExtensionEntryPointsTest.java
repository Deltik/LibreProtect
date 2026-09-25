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
        @DisplayName("should tell the sender that migration is unavailable")
        void explainsUnavailable() {
            RecordingSender recorder = new RecordingSender(ConsoleCommandSender.class);

            DatabaseMigration.runCommand(recorder.sender, new String[]{"migrate-db", "mysql"});

            List<String> plain = recorder.plainMessages();
            assertEquals(3, plain.size(), plain::toString);
            assertEquals(PrivacyConstants.FORK_NAME + " - Database migration is not available in "
                + PrivacyConstants.FORK_NAME + ".", plain.get(0));
            assertTrue(plain.get(1).contains("No free implementation of /co migrate-db"), plain.get(1));
            assertTrue(plain.get(2).contains(PrivacyConstants.FORK_URL), plain.get(2));
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
        @DisplayName("should only send messages, whatever the arguments")
        void onlySendsMessages() {
            for (String[] args : new String[][]{
                {"migrate-db", "sqlite"},
                {"migrate-db", "mysql"},
                {"migrate-db"},
                {}
            }) {
                RecordingSender recorder = new RecordingSender(CommandSender.class);

                assertDoesNotThrow(() -> DatabaseMigration.runCommand(recorder.sender, args));

                assertEquals(Set.of("sendMessage"), recorder.methodsCalled, String.join(" ", args));
                assertEquals(3, recorder.messages.size());
            }
        }

        @Test
        @DisplayName("should not log anything")
        void logsNothing() {
            DatabaseMigration.runCommand(new RecordingSender(CommandSender.class).sender, new String[]{"migrate-db"});
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
        @DisplayName("stop() should be a no-op")
        void stopIsNoOp() {
            assertDoesNotThrow(BackgroundService::stop);
            assertDoesNotThrow(BackgroundService::stop);
            assertTrue(testLogger.getRecords().isEmpty());
        }

        @Test
        @DisplayName("stop() should be safe without start()")
        void stopWithoutStart() {
            assertDoesNotThrow(BackgroundService::stop);
        }

        @Test
        @DisplayName("start() should stay silent and not throw outside a plugin class loader")
        void startOutsidePlugin() {
            assertDoesNotThrow(BackgroundService::start);
            assertTrue(testLogger.getRecords().isEmpty(), () -> testLogger.getMessages().toString());
        }

        @Test
        @DisplayName("should not be instantiable")
        void notInstantiable() throws NoSuchMethodException {
            assertTrue(Modifier.isPrivate(BackgroundService.class.getDeclaredConstructor().getModifiers()));
            assertTrue(Modifier.isFinal(BackgroundService.class.getModifiers()));
        }
    }
}
