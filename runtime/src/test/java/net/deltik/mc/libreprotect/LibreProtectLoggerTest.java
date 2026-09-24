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

package net.deltik.mc.libreprotect;

import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.junit.jupiter.api.*;

import java.util.List;
import java.util.logging.Level;

import static org.junit.jupiter.api.Assertions.*;

class LibreProtectLoggerTest {

    @BeforeEach
    void setUp() {
        LibreProtectLogger.reset();
    }

    @AfterEach
    void tearDown() {
        LibreProtectLogger.reset();
    }

    @Nested
    @DisplayName("Initialization")
    class Initialization {

        @Test
        @DisplayName("isInitialized() should return false before initialization")
        void notInitializedByDefault() {
            assertFalse(LibreProtectLogger.isInitialized());
        }

        @Test
        @DisplayName("isInitialized() should return true after initialization")
        void initializedAfterSetup() {
            LibreProtectLogger.initialize(new TestLogger());
            assertTrue(LibreProtectLogger.isInitialized());
        }
    }

    @Nested
    @DisplayName("Message Buffering")
    class MessageBuffering {

        @Test
        @DisplayName("should buffer messages before initialization")
        void buffersMessagesBeforeInit() {
            LibreProtectLogger.info("Buffered message 1");
            LibreProtectLogger.warning("Buffered message 2");

            assertFalse(LibreProtectLogger.isInitialized());

            TestLogger testLogger = new TestLogger();
            LibreProtectLogger.initialize(testLogger);

            assertEquals(2, testLogger.getRecords().size());
        }

        @Test
        @DisplayName("should flush buffered messages on initialization")
        void flushesBufferedMessages() {
            LibreProtectLogger.info("Buffered 1");
            LibreProtectLogger.warning("Buffered 2");

            TestLogger testLogger = new TestLogger();
            LibreProtectLogger.initialize(testLogger);

            var records = testLogger.getRecords();
            assertEquals(2, records.size());
            assertTrue(testLogger.hasMessageContaining(Level.INFO, "Buffered 1"));
            assertTrue(testLogger.hasMessageContaining(Level.WARNING, "Buffered 2"));
        }

        @Test
        @DisplayName("should preserve message order when flushing")
        void preservesMessageOrder() {
            LibreProtectLogger.info("First");
            LibreProtectLogger.info("Second");
            LibreProtectLogger.info("Third");

            TestLogger testLogger = new TestLogger();
            LibreProtectLogger.initialize(testLogger);

            List<String> messages = testLogger.getMessages();
            assertEquals(3, messages.size());
            assertEquals(LibreProtectLogger.PREFIX + "First", messages.get(0));
            assertEquals(LibreProtectLogger.PREFIX + "Second", messages.get(1));
            assertEquals(LibreProtectLogger.PREFIX + "Third", messages.get(2));
        }

        @Test
        @DisplayName("should flush buffered messages only once")
        void flushesOnlyOnce() {
            LibreProtectLogger.info("Buffered");

            TestLogger first = new TestLogger();
            LibreProtectLogger.initialize(first);
            TestLogger second = new TestLogger();
            LibreProtectLogger.initialize(second);

            assertEquals(1, first.getRecords().size());
            assertTrue(second.getRecords().isEmpty());
        }

        @Test
        @DisplayName("should buffer debug messages only when verbose")
        void buffersDebugOnlyWhenVerbose() {
            LibreProtectLogger.debug("Quiet debug");
            LibreProtectLogger.setVerbose(true);
            LibreProtectLogger.debug("Loud debug");

            TestLogger testLogger = new TestLogger();
            LibreProtectLogger.initialize(testLogger);

            assertFalse(testLogger.hasMessageContaining("Quiet debug"));
            assertTrue(testLogger.hasMessageContaining("Loud debug"));
        }
    }

    @Nested
    @DisplayName("Logging Methods")
    class LoggingMethods {

        private TestLogger testLogger;

        @BeforeEach
        void initLogger() {
            testLogger = new TestLogger();
            LibreProtectLogger.initialize(testLogger);
        }

        @Test
        @DisplayName("info() should log at INFO level")
        void infoLogsAtInfoLevel() {
            LibreProtectLogger.info("Info message");
            assertTrue(testLogger.hasLevel(Level.INFO));
            assertTrue(testLogger.hasMessageContaining("Info message"));
        }

        @Test
        @DisplayName("warning() should log at WARNING level")
        void warningLogsAtWarningLevel() {
            LibreProtectLogger.warning("Warning message");
            assertTrue(testLogger.hasLevel(Level.WARNING));
            assertTrue(testLogger.hasMessageContaining("Warning message"));
        }

        @Test
        @DisplayName("severe() should log at SEVERE level")
        void severeLogsAtSevereLevel() {
            LibreProtectLogger.severe("Severe message");
            assertTrue(testLogger.hasLevel(Level.SEVERE));
            assertTrue(testLogger.hasMessageContaining("Severe message"));
        }

        @Test
        @DisplayName("log() should log at specified level")
        void logAtSpecifiedLevel() {
            LibreProtectLogger.log(Level.FINE, "Fine message");
            assertTrue(testLogger.hasLevel(Level.FINE));
            assertTrue(testLogger.hasMessageContaining("Fine message"));
        }
    }

    @Nested
    @DisplayName("Prefix")
    class Prefix {

        private TestLogger testLogger;

        @BeforeEach
        void initLogger() {
            testLogger = new TestLogger();
            LibreProtectLogger.initialize(testLogger);
        }

        @Test
        @DisplayName("PREFIX should name LibreProtect")
        void prefixNamesFork() {
            assertEquals("[" + PrivacyConstants.FORK_NAME + "] ", LibreProtectLogger.PREFIX);
        }

        @Test
        @DisplayName("every level should carry the prefix")
        void everyLevelIsPrefixed() {
            LibreProtectLogger.info("i");
            LibreProtectLogger.warning("w");
            LibreProtectLogger.severe("s");
            LibreProtectLogger.log(Level.FINE, "f");

            assertEquals(
                List.of(LibreProtectLogger.PREFIX + "i", LibreProtectLogger.PREFIX + "w",
                    LibreProtectLogger.PREFIX + "s", LibreProtectLogger.PREFIX + "f"),
                testLogger.getMessages());
        }

        @Test
        @DisplayName("debug messages should carry the prefix and a [DEBUG] marker")
        void debugIsPrefixed() {
            LibreProtectLogger.setVerbose(true);
            LibreProtectLogger.debug("d");

            assertEquals(List.of(LibreProtectLogger.PREFIX + "[DEBUG] d"), testLogger.getMessages());
            assertEquals(Level.INFO, testLogger.getRecords().get(0).getLevel());
        }
    }

    @Nested
    @DisplayName("Verbose Logging")
    class VerboseLogging {

        private TestLogger testLogger;

        @BeforeEach
        void initLogger() {
            testLogger = new TestLogger();
            LibreProtectLogger.initialize(testLogger);
            LibreProtectLogger.setVerbose(false);
        }

        @Test
        @DisplayName("debug() should not log when verbose is disabled")
        void debugSuppressedWhenNotVerbose() {
            LibreProtectLogger.debug("Debug message");
            assertTrue(testLogger.getRecords().isEmpty());
        }

        @Test
        @DisplayName("debug() should log when verbose is enabled")
        void debugLogsWhenVerbose() {
            LibreProtectLogger.setVerbose(true);
            LibreProtectLogger.debug("Debug message");
            assertFalse(testLogger.getRecords().isEmpty());
            assertTrue(testLogger.hasMessageContaining("Debug message"));
        }

        @Test
        @DisplayName("setVerbose should change verbose state")
        void setVerboseChangesState() {
            LibreProtectLogger.setVerbose(true);

            // Now debug should log
            LibreProtectLogger.debug("Should appear");
            assertTrue(testLogger.hasMessageContaining("Should appear"));

            // Turn off verbose
            LibreProtectLogger.setVerbose(false);
            testLogger.clear();

            // Now debug should not log
            LibreProtectLogger.debug("Should not appear");
            assertFalse(testLogger.hasMessageContaining("Should not appear"));
        }

        @Test
        @DisplayName("verbose should not affect non-debug messages")
        void verboseDoesNotAffectOtherLevels() {
            LibreProtectLogger.info("Always shown");
            assertTrue(testLogger.hasMessageContaining("Always shown"));
        }
    }

    @Nested
    @DisplayName("reset")
    class Reset {

        @Test
        @DisplayName("should forget the logger")
        void forgetsLogger() {
            TestLogger testLogger = new TestLogger();
            LibreProtectLogger.initialize(testLogger);

            LibreProtectLogger.reset();

            assertFalse(LibreProtectLogger.isInitialized());
            LibreProtectLogger.info("After reset");
            assertTrue(testLogger.getRecords().isEmpty());
        }

        @Test
        @DisplayName("should discard buffered messages")
        void discardsBuffer() {
            LibreProtectLogger.info("Discarded");

            LibreProtectLogger.reset();
            TestLogger testLogger = new TestLogger();
            LibreProtectLogger.initialize(testLogger);

            assertTrue(testLogger.getRecords().isEmpty());
        }

        @Test
        @DisplayName("should turn verbose logging off")
        void turnsVerboseOff() {
            LibreProtectLogger.setVerbose(true);

            LibreProtectLogger.reset();
            TestLogger testLogger = new TestLogger();
            LibreProtectLogger.initialize(testLogger);
            LibreProtectLogger.debug("Debug message");

            assertTrue(testLogger.getRecords().isEmpty());
        }
    }

    @Nested
    @DisplayName("Direct logging after initialization")
    class DirectLogging {

        @Test
        @DisplayName("messages should go directly to logger when initialized")
        void messagesGoDirectlyToLogger() {
            TestLogger testLogger = new TestLogger();
            LibreProtectLogger.initialize(testLogger);

            LibreProtectLogger.info("Direct message");

            assertEquals(1, testLogger.getRecords().size());
            assertEquals(LibreProtectLogger.PREFIX + "Direct message", testLogger.getRecords().get(0).getMessage());
        }
    }
}
