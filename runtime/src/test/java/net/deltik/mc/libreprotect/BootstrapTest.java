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

import net.deltik.mc.libreprotect.routing.Route;
import net.deltik.mc.libreprotect.routing.RouteActionType;
import net.deltik.mc.libreprotect.routing.RoutePreset;
import net.deltik.mc.libreprotect.routing.RouteRegistry;
import net.deltik.mc.libreprotect.routing.RouteResolver;
import net.deltik.mc.libreprotect.testutil.LocalHttpServer;
import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import static org.junit.jupiter.api.Assertions.*;

class BootstrapTest {

    @TempDir
    Path dataFolder;

    private TestLogger testLogger;

    @BeforeEach
    void setUp() {
        LibreProtectLogger.reset();
        Egress.uninstall();
        testLogger = new TestLogger();
    }

    @AfterEach
    void tearDown() {
        LibreProtectLogger.reset();
        Egress.uninstall();
    }

    private File configFile() {
        return dataFolder.resolve(PrivacyConfig.FILE_NAME).toFile();
    }

    private void writeConfig(String yaml) throws IOException {
        Files.writeString(configFile().toPath(), yaml, StandardCharsets.UTF_8);
    }

    private static void assertPrivacyFirstInstalled() {
        RouteResolver resolver = Egress.getResolver();
        assertNotNull(resolver, "no resolver installed");
        RouteRegistry registry = resolver.getRegistry();
        assertEquals(RoutePreset.PRIVACY_FIRST.getRoutes(), registry.getRoutes());
        assertEquals(RouteActionType.BLOCK, registry.getDefaultAction());
    }

    @Nested
    @DisplayName("init with a missing config file")
    class MissingFile {

        @Test
        @DisplayName("should install the privacy-first policy")
        void installsPrivacyFirst() {
            Bootstrap.init(testLogger, dataFolder.toFile());

            assertPrivacyFirstInstalled();
            assertEquals(RoutePreset.PRIVACY_FIRST, Bootstrap.getActiveConfig().getPreset());
        }

        @Test
        @DisplayName("should block CoreProtect's endpoints through Egress")
        void blocksThroughEgress() {
            Bootstrap.init(testLogger, dataFolder.toFile());

            EgressBlockedException ex = assertThrows(EgressBlockedException.class,
                () -> Egress.openConnection(MockUrlFactory.statsUrl()));
            assertTrue(ex.getReason().startsWith("route "), ex.getReason());
        }

        @Test
        @DisplayName("should not write the config file")
        void doesNotWriteFile() {
            Bootstrap.init(testLogger, dataFolder.toFile());
            assertFalse(configFile().exists());
        }

        @Test
        @DisplayName("should log nothing at WARNING or above")
        void quiet() {
            Bootstrap.init(testLogger, dataFolder.toFile());

            for (LogRecord record : testLogger.getRecords()) {
                assertTrue(record.getLevel().intValue() < Level.WARNING.intValue(), record.getMessage());
            }
        }

        @Test
        @DisplayName("should work when the data folder does not exist yet")
        void dataFolderMissing() {
            Bootstrap.init(testLogger, dataFolder.resolve("not-created-yet").toFile());

            assertPrivacyFirstInstalled();
            assertFalse(dataFolder.resolve("not-created-yet").toFile().exists());
        }
    }

    @Nested
    @DisplayName("init with a custom config file")
    class CustomFile {

        @Test
        @DisplayName("should install the configured preset and routes")
        void honorsFile() throws IOException {
            writeConfig(String.join("\n",
                "preset: passthrough",
                "routes:",
                "  - pattern: \"https://blocked\\\\.example/.*\"",
                "    action: BLOCK",
                ""));

            Bootstrap.init(testLogger, dataFolder.toFile());

            PrivacyConfig active = Bootstrap.getActiveConfig();
            assertEquals(RoutePreset.PASSTHROUGH, active.getPreset());
            assertEquals(1, active.getCustomRoutes().size());

            RouteRegistry registry = Egress.getResolver().getRegistry();
            assertEquals(RouteActionType.PASSTHROUGH, registry.getDefaultAction());
            assertEquals(1, registry.size());
        }

        @Test
        @DisplayName("should route requests through the configured policy")
        void routesThroughPolicy() throws IOException {
            writeConfig(String.join("\n",
                "preset: passthrough",
                "routes:",
                "  - pattern: \"https://blocked\\\\.example/.*\"",
                "    action: BLOCK",
                ""));
            Bootstrap.init(testLogger, dataFolder.toFile());

            EgressBlockedException ex = assertThrows(EgressBlockedException.class,
                () -> Egress.openConnection(MockUrlFactory.createUrl("https://blocked.example/x")));
            assertEquals("route https://blocked\\.example/.*", ex.getReason());

            try (LocalHttpServer server = new LocalHttpServer()) {
                assertEquals("direct /allowed", LocalHttpServer.read(Egress.openConnection(server.url("/allowed"))));
            }
        }

        @Test
        @DisplayName("should replace a previously installed policy")
        void replacesPreviousPolicy() throws IOException {
            Bootstrap.init(testLogger, dataFolder.toFile());
            RouteResolver first = Egress.getResolver();

            writeConfig("preset: allow-updates\n");
            Bootstrap.init(testLogger, dataFolder.toFile());

            assertNotSame(first, Egress.getResolver());
            assertEquals(RoutePreset.ALLOW_UPDATES, Bootstrap.getActiveConfig().getPreset());
            assertEquals(RoutePreset.ALLOW_UPDATES.getRoutes(), Egress.getResolver().getRegistry().getRoutes());
        }
    }

    @Nested
    @DisplayName("init with an invalid config file")
    class InvalidFile {

        @Test
        @DisplayName("should install the defaults and log SEVERE")
        void installsDefaults() throws IOException {
            writeConfig("preset: passthrough\nroutes: [unclosed\n");

            Bootstrap.init(testLogger, dataFolder.toFile());

            assertPrivacyFirstInstalled();
            assertEquals(RoutePreset.PRIVACY_FIRST, Bootstrap.getActiveConfig().getPreset());
            assertTrue(testLogger.hasMessageContaining(Level.SEVERE, PrivacyConfig.FILE_NAME));
        }

        @Test
        @DisplayName("should not overwrite the broken file")
        void keepsBrokenFile() throws IOException {
            writeConfig("routes: [unclosed\n");

            Bootstrap.init(testLogger, dataFolder.toFile());

            assertEquals("routes: [unclosed\n", Files.readString(configFile().toPath()));
        }

        @Test
        @DisplayName("should fall back to privacy-first for an unknown preset")
        void unknownPreset() throws IOException {
            writeConfig("preset: allow-everything\n");

            Bootstrap.init(testLogger, dataFolder.toFile());

            assertPrivacyFirstInstalled();
            assertTrue(testLogger.hasMessageContaining(Level.WARNING, "allow-everything"));
        }
    }

    @Nested
    @DisplayName("Verbose logging")
    class Verbose {

        @Test
        @DisplayName("should be enabled when the file enables it")
        void enabledFromFile() throws IOException {
            writeConfig("verbose-logging: true\n");

            Bootstrap.init(testLogger, dataFolder.toFile());

            assertTrue(Bootstrap.getActiveConfig().isVerboseLogging());
            LibreProtectLogger.debug("debug probe");
            assertTrue(testLogger.hasMessageContaining("debug probe"));
        }

        @Test
        @DisplayName("should make blocked requests visible when enabled")
        void blockedRequestsLogged() throws IOException {
            writeConfig("verbose-logging: true\n");
            Bootstrap.init(testLogger, dataFolder.toFile());

            assertThrows(EgressBlockedException.class, () -> Egress.openConnection(MockUrlFactory.bstatsUrl()));

            assertTrue(testLogger.hasMessageContaining("matched route"));
            assertTrue(testLogger.hasMessageContaining("Blocked"));
            assertTrue(testLogger.hasMessageContaining("https://bstats.org/api/v2/data/bukkit"));
        }

        @Test
        @DisplayName("should stay disabled by default")
        void disabledByDefault() {
            Bootstrap.init(testLogger, dataFolder.toFile());
            testLogger.clear();

            LibreProtectLogger.debug("debug probe");
            assertThrows(EgressBlockedException.class, () -> Egress.openConnection(MockUrlFactory.bstatsUrl()));

            assertTrue(testLogger.getRecords().isEmpty(), () -> testLogger.getMessages().toString());
        }

        @Test
        @DisplayName("should be turned off again when a later config disables it")
        void turnedOffOnReinit() throws IOException {
            writeConfig("verbose-logging: true\n");
            Bootstrap.init(testLogger, dataFolder.toFile());

            writeConfig("verbose-logging: false\n");
            Bootstrap.init(testLogger, dataFolder.toFile());
            testLogger.clear();

            LibreProtectLogger.debug("debug probe");
            assertFalse(testLogger.hasMessageContaining("debug probe"));
        }
    }

    @Nested
    @DisplayName("Logger")
    class LoggerSetup {

        @Test
        @DisplayName("should initialize LibreProtectLogger with the given logger")
        void initializesLogger() {
            Bootstrap.init(testLogger, dataFolder.toFile());

            assertTrue(LibreProtectLogger.isInitialized());
            LibreProtectLogger.info("hello");
            assertTrue(testLogger.hasMessageContaining(LibreProtectLogger.PREFIX + "hello"));
        }

        @Test
        @DisplayName("should flush messages logged before init")
        void flushesEarlyMessages() {
            LibreProtectLogger.warning("early warning");

            Bootstrap.init(testLogger, dataFolder.toFile());

            assertTrue(testLogger.hasMessageContaining(Level.WARNING, "early warning"));
        }
    }

    @Nested
    @DisplayName("Failing closed")
    class FailClosed {

        @Test
        @DisplayName("should uninstall any previous policy when setup throws")
        void uninstallsOnFailure() throws IOException {
            Bootstrap.init(testLogger, dataFolder.toFile());
            assertNotNull(Egress.getResolver());

            // The unknown preset makes loading log a warning, and this logger
            // throws on its first record, so setup fails part way through.
            writeConfig("preset: allow-everything\n");
            ThrowOnceLogger failing = new ThrowOnceLogger();
            assertDoesNotThrow(() -> Bootstrap.init(failing, dataFolder.toFile()));

            assertNull(Egress.getResolver());
            assertNull(Bootstrap.getActiveConfig());
            assertTrue(failing.hasMessageContaining(Level.SEVERE, "blocking all network requests"));
            assertThrows(EgressBlockedException.class, () -> Egress.openConnection(MockUrlFactory.updateUrl()));
        }

        @Test
        @DisplayName("init(JavaPlugin) should never throw, even for a broken plugin")
        void pluginInitNeverThrows() {
            Egress.install(PrivacyConfig.defaults().buildResolver());

            assertDoesNotThrow(() -> Bootstrap.init((org.bukkit.plugin.java.JavaPlugin) null));

            assertNull(Egress.getResolver());
            assertNull(Bootstrap.getActiveConfig());

            LibreProtectLogger.initialize(testLogger);
            assertTrue(testLogger.hasMessageContaining(Level.SEVERE, "blocking all network requests"));
        }

        @Test
        @DisplayName("enabled(JavaPlugin) should never throw, even for a broken plugin")
        void pluginEnabledNeverThrows() {
            LibreProtectLogger.initialize(testLogger);

            assertDoesNotThrow(() -> Bootstrap.enabled(null));

            assertTrue(testLogger.hasLevel(Level.WARNING));
        }
    }

    /**
     * Throws on the first record it receives, then records normally.
     */
    private static final class ThrowOnceLogger extends TestLogger {
        private boolean thrown;

        @Override
        public void log(LogRecord record) {
            if (!thrown) {
                thrown = true;
                throw new IllegalStateException("simulated logging failure");
            }
            super.log(record);
        }
    }

    @Test
    @DisplayName("getActiveConfig should describe the installed policy")
    void activeConfigMatchesInstalledPolicy() throws IOException {
        writeConfig("preset: allow-updates\nroutes:\n  - pattern: a\n    action: BLOCK\n");

        Bootstrap.init(testLogger, dataFolder.toFile());

        PrivacyConfig active = Bootstrap.getActiveConfig();
        RouteRegistry registry = Egress.getResolver().getRegistry();
        assertEquals(active.getCustomRoutes().size() + active.getPreset().getRoutes().size(), registry.size());
        Route first = registry.getRoutes().get(0);
        assertEquals("a", first.getPatternString());
        assertEquals(active.getPreset().getDefaultAction(), registry.getDefaultAction());
    }
}
