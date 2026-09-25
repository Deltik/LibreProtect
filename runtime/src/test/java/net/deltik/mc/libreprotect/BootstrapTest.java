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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
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

    /** Assert that Egress applies the preset's routes, and no custom ones */
    private static void assertInstalled(RoutePreset preset) {
        RouteResolver resolver = Egress.getResolver();
        assertNotNull(resolver, "no resolver installed");
        RouteRegistry registry = resolver.getRegistry();
        assertEquals(preset.getRoutes(), registry.getRoutes());
        assertEquals(RouteActionType.BLOCK, registry.getDefaultAction());
    }

    /** Assert that the installed policy sends nothing */
    private static void assertFailedClosed() {
        assertInstalled(RoutePreset.PRIVACY_FIRST);
        assertEquals(RoutePreset.PRIVACY_FIRST, Bootstrap.getActiveConfig().getPreset());
        assertEquals(List.of(), Bootstrap.getActiveConfig().getUpdateSources());
    }

    @Nested
    @DisplayName("init with a missing config file")
    class MissingFile {

        @Test
        @DisplayName("should install the default allow-updates policy")
        void installsDefaults() {
            Bootstrap.init(testLogger, dataFolder.toFile());

            assertInstalled(RoutePreset.ALLOW_UPDATES);
            assertEquals(RoutePreset.ALLOW_UPDATES, Bootstrap.getActiveConfig().getPreset());
            assertEquals(PrivacyConfig.defaults().getUpdateSources(), Bootstrap.getActiveConfig().getUpdateSources());
        }

        @Test
        @DisplayName("should install the policy that later boots read from the default file")
        void matchesLaterBoots() throws IOException {
            Bootstrap.init(testLogger, dataFolder.toFile());
            PrivacyConfig first = Bootstrap.getActiveConfig();
            List<Route> firstRoutes = Egress.getResolver().getRegistry().getRoutes();

            assertTrue(PrivacyConfig.writeDefaultIfMissing(configFile()));
            Bootstrap.init(testLogger, dataFolder.toFile());

            PrivacyConfig later = Bootstrap.getActiveConfig();
            assertEquals(first.describe(), later.describe());
            assertEquals(first.getUpdateSources(), later.getUpdateSources());
            assertEquals(firstRoutes, Egress.getResolver().getRegistry().getRoutes());
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

            assertInstalled(RoutePreset.ALLOW_UPDATES);
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

            writeConfig("preset: privacy-first\n");
            Bootstrap.init(testLogger, dataFolder.toFile());

            assertNotSame(first, Egress.getResolver());
            assertEquals(RoutePreset.PRIVACY_FIRST, Bootstrap.getActiveConfig().getPreset());
            assertEquals(RoutePreset.PRIVACY_FIRST.getRoutes(), Egress.getResolver().getRegistry().getRoutes());
        }

        @Test
        @DisplayName("should have update checks read check-updates from CoreProtect's config.yml in the data folder")
        void updateChecksReadCoreProtectConfig() throws IOException {
            try (LocalHttpServer server = new LocalHttpServer()) {
                writeConfig(String.join("\n",
                    "preset: allow-updates",
                    "update-sources:",
                    "  - type: modrinth",
                    "    project: libreprotect",
                    "    api: " + server.getBaseUrl(),
                    ""));
                Files.writeString(dataFolder.resolve("config.yml"), "check-updates: false\n");
                Bootstrap.init(testLogger, dataFolder.toFile());

                IOException ex = assertThrows(IOException.class,
                    () -> Egress.openConnection(MockUrlFactory.updateUrl()).getInputStream());

                assertEquals("Update check skipped: check-updates is off in " + dataFolder.resolve("config.yml"),
                    ex.getMessage());
                assertEquals(0, server.getRequests().size());
            }
        }
    }

    @Nested
    @DisplayName("init with an invalid config file")
    class InvalidFile {

        @Test
        @DisplayName("should install a policy that sends nothing, and log SEVERE")
        void failsClosed() throws IOException {
            writeConfig("preset: passthrough\nroutes: [unclosed\n");

            Bootstrap.init(testLogger, dataFolder.toFile());

            assertFailedClosed();
            assertTrue(testLogger.hasMessageContaining(Level.SEVERE, PrivacyConfig.FILE_NAME));
        }

        @Test
        @DisplayName("should install a policy that sends nothing when a directory is in the file's place")
        void directoryFailsClosed() throws IOException {
            Files.createDirectory(configFile().toPath());

            Bootstrap.init(testLogger, dataFolder.toFile());

            assertFailedClosed();
            assertTrue(testLogger.hasMessageContaining(Level.SEVERE, "blocking all network requests"));
        }

        @ParameterizedTest
        @DisplayName("should install a policy that sends nothing for a file without settings or with a mistyped one")
        @ValueSource(strings = {"", "# LibreProtect network policy\n#\n", "Preset: privacy-first\n"})
        void unusableFile(String yaml) throws IOException {
            writeConfig(yaml);

            Bootstrap.init(testLogger, dataFolder.toFile());

            assertFailedClosed();
            assertTrue(testLogger.hasLevel(Level.WARNING));
            assertEquals(yaml, Files.readString(configFile().toPath()));
        }

        @Test
        @DisplayName("should not overwrite the broken file")
        void keepsBrokenFile() throws IOException {
            writeConfig("routes: [unclosed\n");

            Bootstrap.init(testLogger, dataFolder.toFile());

            assertEquals("routes: [unclosed\n", Files.readString(configFile().toPath()));
        }

        @Test
        @DisplayName("should install a policy that sends nothing for an unknown preset")
        void unknownPreset() throws IOException {
            writeConfig("preset: allow-everything\n");

            Bootstrap.init(testLogger, dataFolder.toFile());

            assertFailedClosed();
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

    @Nested
    @DisplayName("Language cache")
    class LanguageCache {

        private static final String CACHE = "# CoreProtect v24.1 Language Cache (nl)\n\nHELP_HEADER: \"{0} Hulp\"";

        private Path cache() {
            return dataFolder.resolve(".language");
        }

        private void writeCache() throws IOException {
            Files.writeString(cache(), CACHE, StandardCharsets.UTF_8);
        }

        @Test
        @DisplayName("should keep CoreProtect's cache when LibreProtect replaces CoreProtect, and after it writes its "
            + "default policy")
        void installOverCoreProtect() throws IOException {
            writeCache();

            Bootstrap.init(testLogger, dataFolder.toFile());
            assertEquals(CACHE, Files.readString(cache()), "first start");
            PrivacyConfig.writeDefaultIfMissing(configFile());

            Bootstrap.init(testLogger, dataFolder.toFile());
            assertEquals(CACHE, Files.readString(cache()), "second start, with the default policy written");
        }

        @Test
        @DisplayName("should keep the cache when a policy edit doesn't change where translations come from")
        void unrelatedEdit() throws IOException {
            writeConfig("preset: passthrough\n");
            Bootstrap.init(testLogger, dataFolder.toFile());
            writeCache();

            writeConfig("preset: passthrough\nverbose-logging: true\n");
            Bootstrap.init(testLogger, dataFolder.toFile());

            assertEquals(CACHE, Files.readString(cache()));
        }

        @Test
        @DisplayName("should empty the cache when translations come from somewhere else")
        void sourceChanged() throws IOException {
            Bootstrap.init(testLogger, dataFolder.toFile());
            writeCache();

            writeConfig("preset: passthrough\n");
            Bootstrap.init(testLogger, dataFolder.toFile());

            assertEquals(RoutePreset.PASSTHROUGH, Bootstrap.getActiveConfig().getPreset());
            assertEquals(0, Files.size(cache()));
            assertTrue(testLogger.hasMessageContaining(Level.INFO, "Refreshing translations"));
        }

        @Test
        @DisplayName("should keep the cache when the policy fails to install")
        void keptWhenFailingClosed() throws IOException {
            Bootstrap.init(testLogger, dataFolder.toFile());
            writeCache();

            // Passthrough would empty the cache, but the invalid routes make loading log a warning, which this
            // logger throws on, so setup fails
            writeConfig("preset: passthrough\nroutes: 5\n");
            Bootstrap.init(new ThrowOnceLogger(), dataFolder.toFile());

            assertNull(Bootstrap.getActiveConfig());
            assertEquals(CACHE, Files.readString(cache()));
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
