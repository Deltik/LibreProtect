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
import net.deltik.mc.libreprotect.update.GitHubSource;
import net.deltik.mc.libreprotect.update.ModrinthSource;
import net.deltik.mc.libreprotect.update.TestUpdateStatus;
import net.deltik.mc.libreprotect.update.UpdateSource;
import net.deltik.mc.libreprotect.update.UpdateSourceParser;
import net.deltik.mc.libreprotect.update.UpdateStatus;
import org.bukkit.configuration.InvalidConfigurationException;
import org.bukkit.configuration.MemoryConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.io.IOException;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class PrivacyConfigTest {

    @TempDir
    Path tempDir;

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

    private File configFile() {
        return tempDir.resolve(PrivacyConfig.FILE_NAME).toFile();
    }

    private File write(String yaml) throws IOException {
        File file = configFile();
        Files.writeString(file.toPath(), yaml, StandardCharsets.UTF_8);
        return file;
    }

    private static PrivacyConfig parse(String yaml) throws InvalidConfigurationException {
        YamlConfiguration config = new YamlConfiguration();
        config.loadFromString(yaml);
        return PrivacyConfig.fromYaml(config);
    }

    private static void assertIsDefaults(PrivacyConfig config) {
        assertEquals(RoutePreset.PRIVACY_FIRST, config.getPreset());
        assertTrue(config.getCustomRoutes().isEmpty());
        assertEquals(PrivacyConfig.defaultUpdateSources(), config.getUpdateSources());
        assertFalse(config.isVerboseLogging());
    }

    /** An update source list that asks a Modrinth-like API on the server */
    private static List<UpdateSource> modrinthAt(LocalHttpServer server) {
        return new UpdateSourceParser().parse(List.of(
            Map.of("type", "modrinth", "project", "libreprotect", "api", server.getBaseUrl() + "/v2")));
    }

    /** A Modrinth-like API that lists one release */
    private static LocalHttpServer modrinthServer(String version) throws IOException {
        String body = "[{\"version_number\":\"" + version + "\",\"version_type\":\"release\",\"status\":\"listed\"}]";
        return new LocalHttpServer(exchange -> LocalHttpServer.respond(exchange, 200, body));
    }

    @Test
    @DisplayName("FILE_NAME should be libreprotect.yml")
    void fileName() {
        assertEquals("libreprotect.yml", PrivacyConfig.FILE_NAME);
    }

    @Nested
    @DisplayName("defaults")
    class Defaults {

        @Test
        @DisplayName("should use the privacy-first preset")
        void usesPrivacyFirst() {
            assertEquals(RoutePreset.PRIVACY_FIRST, PrivacyConfig.defaults().getPreset());
        }

        @Test
        @DisplayName("should have no custom routes")
        void hasNoCustomRoutes() {
            assertNotNull(PrivacyConfig.defaults().getCustomRoutes());
            assertTrue(PrivacyConfig.defaults().getCustomRoutes().isEmpty());
        }

        @Test
        @DisplayName("should have verbose logging disabled")
        void verboseDisabled() {
            assertFalse(PrivacyConfig.defaults().isVerboseLogging());
        }

        @Test
        @DisplayName("should ask GitHub, then Modrinth, for updates")
        void updateSources() {
            List<UpdateSource> sources = PrivacyConfig.defaults().getUpdateSources();

            assertEquals(2, sources.size());
            GitHubSource github = assertInstanceOf(GitHubSource.class, sources.get(0));
            assertEquals("Deltik/LibreProtect", github.repository());
            assertEquals("https://api.github.com", github.api());
            ModrinthSource modrinth = assertInstanceOf(ModrinthSource.class, sources.get(1));
            assertEquals("libreprotect", modrinth.project());
            assertEquals("https://api.modrinth.com/v2", modrinth.api());
        }

        @Test
        @DisplayName("should agree with the schema defaults")
        void agreesWithSchema() {
            PrivacyConfig defaults = PrivacyConfig.defaults();
            assertEquals(PrivacyConfigSchema.PRESET.defaultValue, defaults.getPreset().getConfigName());
            assertEquals(PrivacyConfigSchema.ROUTES.defaultValue, defaults.getCustomRoutes());
            assertEquals(new UpdateSourceParser().parse((List<?>) PrivacyConfigSchema.UPDATE_SOURCES.defaultValue),
                defaults.getUpdateSources());
            assertEquals(PrivacyConfigSchema.VERBOSE_LOGGING.defaultValue, defaults.isVerboseLogging());
        }
    }

    @Nested
    @DisplayName("load")
    class Load {

        @Test
        @DisplayName("should return defaults when the file is missing")
        void missingFileGivesDefaults() {
            PrivacyConfig config = PrivacyConfig.load(configFile());

            assertIsDefaults(config);
            assertTrue(testLogger.getRecords().isEmpty());
        }

        @Test
        @DisplayName("should not create the file")
        void doesNotCreateFile() {
            PrivacyConfig.load(configFile());
            assertFalse(configFile().exists());
        }

        @Test
        @DisplayName("should return defaults when the path is a directory")
        void directoryGivesDefaults() throws IOException {
            Files.createDirectory(configFile().toPath());
            assertIsDefaults(PrivacyConfig.load(configFile()));
        }

        @Test
        @DisplayName("should return defaults for an empty file")
        void emptyFileGivesDefaults() throws IOException {
            assertIsDefaults(PrivacyConfig.load(write("")));
            assertFalse(testLogger.hasLevel(Level.SEVERE));
        }

        @Test
        @DisplayName("should read every setting from the file")
        void readsEverySetting() throws IOException {
            File file = write(String.join("\n",
                "preset: allow-updates",
                "routes:",
                "  - pattern: \"https://example\\\\.com/.*\"",
                "    action: BLOCK",
                "  - pattern: \"http://update\\\\.coreprotect\\\\.net(?P<path>/.*)\"",
                "    action: REDIRECT",
                "    target: \"http://127.0.0.1:1${path}\"",
                "verbose-logging: true",
                ""));

            PrivacyConfig config = PrivacyConfig.load(file);

            assertEquals(RoutePreset.ALLOW_UPDATES, config.getPreset());
            assertTrue(config.isVerboseLogging());
            assertEquals(2, config.getCustomRoutes().size());
            Route first = config.getCustomRoutes().get(0);
            assertEquals("https://example\\.com/.*", first.getPatternString());
            assertEquals(RouteActionType.BLOCK, first.getActionType());
            Route second = config.getCustomRoutes().get(1);
            assertEquals(RouteActionType.REDIRECT, second.getActionType());
            assertEquals("http://127.0.0.1:1${path}", second.getTarget());
        }

        @Test
        @DisplayName("should use defaults for settings missing from the file")
        void missingSettingsUseDefaults() throws IOException {
            PrivacyConfig config = PrivacyConfig.load(write("verbose-logging: true\n"));

            assertEquals(RoutePreset.PRIVACY_FIRST, config.getPreset());
            assertTrue(config.getCustomRoutes().isEmpty());
            assertEquals(PrivacyConfig.defaultUpdateSources(), config.getUpdateSources());
            assertTrue(config.isVerboseLogging());
        }

        @ParameterizedTest
        @DisplayName("should turn update checks off for update-sources without a value, as when every source is commented out")
        @ValueSource(strings = {
            "update-sources:\n#  - type: modrinth\n#    project: libreprotect\npreset: allow-updates\n",
            "update-sources:\n",
            "update-sources:   # none\n",
            "update-sources: ~\n",
            "update-sources: null\n",
            "update-sources: !!null\n",
            "preset: allow-updates\nupdate-sources:",
            "\"update-sources\":\n#  - type: modrinth\n",
            "'update-sources': ~\n",
            "\"update\\x2dsources\": \n",
            "? update-sources\npreset: allow-updates\n",
            "{preset: allow-updates, update-sources: null}\n",
            "{preset: allow-updates, \"update-sources\"}\n",
            "{update-sources: , preset: allow-updates}\n",
            "update-sources:\n  - type: modrinth\n    project: first\nupdate-sources:\n"
        })
        void updateSourcesWithoutValue(String yaml) throws IOException {
            PrivacyConfig config = PrivacyConfig.load(write(yaml));

            assertEquals(List.of(), config.getUpdateSources());
            assertFalse(testLogger.hasLevel(Level.WARNING));
        }

        @ParameterizedTest
        @DisplayName("should keep update sources that have a value, however the key is written")
        @ValueSource(strings = {
            "\"update-sources\":\n  - type: modrinth\n    project: first\n",
            "{\"update-sources\": [{type: modrinth, project: first}]}\n",
            "update-sources: ~\nupdate-sources:\n  - type: modrinth\n    project: first\n"
        })
        void updateSourcesWithValue(String yaml) throws IOException {
            PrivacyConfig config = PrivacyConfig.load(write(yaml));

            assertEquals(List.of("Modrinth project first"),
                config.getUpdateSources().stream().map(UpdateSource::describe).toList());
        }

        @Test
        @DisplayName("should use the default update sources when the key is only in a comment or a nested setting")
        void updateSourcesKeyElsewhere() throws IOException {
            PrivacyConfig config = PrivacyConfig.load(write(
                "# update-sources:\nroutes:\n  - pattern: a\n    action: BLOCK\n    update-sources:\n"));

            assertEquals(PrivacyConfig.defaultUpdateSources(), config.getUpdateSources());
        }

        @Test
        @DisplayName("should return defaults and log SEVERE for invalid YAML")
        void invalidYamlGivesDefaults() throws IOException {
            File file = write("preset: passthrough\nroutes: [unclosed\n");

            PrivacyConfig config = PrivacyConfig.load(file);

            assertIsDefaults(config);
            assertTrue(testLogger.hasMessageContaining(Level.SEVERE, file.toString()));
            assertTrue(testLogger.hasMessageContaining(Level.SEVERE, "blocking all network requests"));
        }

        @Test
        @DisplayName("should return defaults and log SEVERE for a YAML document that is not a mapping")
        void nonMappingGivesDefaults() throws IOException {
            assertIsDefaults(PrivacyConfig.load(write("- just\n- a list\n")));
            assertTrue(testLogger.hasLevel(Level.SEVERE));
        }

        @Test
        @DisplayName("should return defaults and log SEVERE for an unreadable file")
        void unreadableFileGivesDefaults() throws IOException {
            File file = write("preset: passthrough\n");
            assumeTrue(file.setReadable(false, false) && !Files.isReadable(file.toPath()),
                "cannot make the file unreadable (running as root?)");
            try {
                assertIsDefaults(PrivacyConfig.load(file));
                assertTrue(testLogger.hasMessageContaining(Level.SEVERE, file.toString()));
            } finally {
                file.setReadable(true, false);
            }
        }
    }

    @Nested
    @DisplayName("fromYaml")
    class FromYaml {

        @ParameterizedTest
        @DisplayName("should parse each preset name")
        @CsvSource({
            "privacy-first, PRIVACY_FIRST",
            "allow-updates, ALLOW_UPDATES",
            "passthrough, PASSTHROUGH",
            "ALLOW-UPDATES, ALLOW_UPDATES"
        })
        void parsesPresets(String name, RoutePreset expected) throws InvalidConfigurationException {
            assertEquals(expected, parse("preset: " + name + "\n").getPreset());
            assertFalse(testLogger.hasLevel(Level.WARNING));
        }

        @Test
        @DisplayName("should fall back to privacy-first and warn for an unknown preset")
        void unknownPresetFallsBack() throws InvalidConfigurationException {
            PrivacyConfig config = parse("preset: allow-everything\n");

            assertEquals(RoutePreset.PRIVACY_FIRST, config.getPreset());
            assertTrue(testLogger.hasMessageContaining(Level.WARNING, "allow-everything"));
        }

        @ParameterizedTest
        @DisplayName("should parse verbose-logging values")
        @CsvSource({
            "true, true",
            "false, false",
            "yes, true",
            "no, false",
            "'\"yes\"', true",
            "'\"TRUE\"', true",
            "1, true",
            "0, false",
            "'\"maybe\"', false"
        })
        void parsesVerboseLogging(String value, boolean expected) throws InvalidConfigurationException {
            assertEquals(expected, parse("verbose-logging: " + value + "\n").isVerboseLogging());
        }

        @Test
        @DisplayName("should skip invalid routes and keep valid ones in order")
        void skipsInvalidRoutes() throws InvalidConfigurationException {
            PrivacyConfig config = parse(String.join("\n",
                "routes:",
                "  - pattern: first",
                "    action: block",
                "  - pattern: \"[unclosed\"",
                "    action: BLOCK",
                "  - not a map",
                "  - pattern: last",
                "    action: PASSTHROUGH",
                ""));

            List<Route> routes = config.getCustomRoutes();
            assertEquals(2, routes.size());
            assertEquals("first", routes.get(0).getPatternString());
            assertEquals("last", routes.get(1).getPatternString());
            assertTrue(testLogger.hasMessageContaining(Level.WARNING, "invalid regex"));
            assertTrue(testLogger.hasMessageContaining(Level.WARNING, "isn't a map"));
        }

        @Test
        @DisplayName("should ignore routes that are not a list")
        void ignoresNonListRoutes() throws InvalidConfigurationException {
            assertTrue(parse("routes: nope\n").getCustomRoutes().isEmpty());
        }

        @Test
        @DisplayName("should read update sources in order")
        void readsUpdateSources() throws InvalidConfigurationException {
            PrivacyConfig config = parse(String.join("\n",
                "update-sources:",
                "  - type: github",
                "    repository: Example/Fork",
                "  - type: Modrinth",
                "    project: example",
                "    api: http://127.0.0.1:1/v2/",
                ""));

            List<UpdateSource> sources = config.getUpdateSources();
            assertEquals(2, sources.size());
            assertEquals("Example/Fork", assertInstanceOf(GitHubSource.class, sources.get(0)).repository());
            ModrinthSource modrinth = assertInstanceOf(ModrinthSource.class, sources.get(1));
            assertEquals("example", modrinth.project());
            assertEquals("http://127.0.0.1:1/v2", modrinth.api());
            assertFalse(testLogger.hasLevel(Level.WARNING));
        }

        @Test
        @DisplayName("should turn update checks off for an empty update-sources list")
        void emptyUpdateSources() throws InvalidConfigurationException {
            assertEquals(List.of(), parse("update-sources: []\n").getUpdateSources());
            assertFalse(testLogger.hasLevel(Level.WARNING));
        }

        @ParameterizedTest
        @DisplayName("should turn update checks off and warn for update-sources that aren't a list")
        @ValueSource(strings = {"update-sources: modrinth", "update-sources: false", "update-sources: {type: github}"})
        void nonListUpdateSources(String yaml) throws InvalidConfigurationException {
            assertEquals(List.of(), parse(yaml + "\n").getUpdateSources());
            assertTrue(testLogger.hasMessageContaining(Level.WARNING,
                "'update-sources' in libreprotect.yml must be a list, so update checks are off"));
        }

        @Test
        @DisplayName("should skip invalid update sources and keep valid ones in order")
        void skipsInvalidUpdateSources() throws InvalidConfigurationException {
            PrivacyConfig config = parse(String.join("\n",
                "update-sources:",
                "  - type: modrinth",
                "    project: first",
                "  - type: gitlab",
                "    project: nope",
                "  - not a map",
                "  - type: github",
                "    repository: Last/One",
                ""));

            List<UpdateSource> sources = config.getUpdateSources();
            assertEquals(List.of("Modrinth project first", "GitHub repository Last/One"),
                sources.stream().map(UpdateSource::describe).toList());
            assertTrue(testLogger.hasMessageContaining(Level.WARNING, "Skipping update source #2 in libreprotect.yml: "));
            assertTrue(testLogger.hasMessageContaining(Level.WARNING, "Skipping update source #3 in libreprotect.yml: "));
        }

        @Test
        @DisplayName("should accept any ConfigurationSection")
        void acceptsConfigurationSection() {
            MemoryConfiguration section = new MemoryConfiguration();
            section.set("preset", "passthrough");
            section.set("verbose-logging", true);

            PrivacyConfig config = PrivacyConfig.fromYaml(section);

            assertEquals(RoutePreset.PASSTHROUGH, config.getPreset());
            assertTrue(config.isVerboseLogging());
        }
    }

    @Nested
    @DisplayName("Immutability")
    class Immutability {

        @Test
        @DisplayName("custom routes should be unmodifiable")
        void customRoutesUnmodifiable() throws InvalidConfigurationException {
            PrivacyConfig config = parse("routes:\n  - pattern: a\n    action: BLOCK\n");
            assertThrows(UnsupportedOperationException.class, () -> config.getCustomRoutes().clear());
        }

        @Test
        @DisplayName("defaults() should return independent, equal values")
        void defaultsAreFresh() {
            assertNotSame(PrivacyConfig.defaults(), PrivacyConfig.defaults());
            assertEquals(PrivacyConfig.defaults().describe(), PrivacyConfig.defaults().describe());
        }
    }

    @Nested
    @DisplayName("writeDefaultIfMissing")
    class WriteDefaultIfMissing {

        @Test
        @DisplayName("should write the generated default file when missing")
        void writesWhenMissing() throws IOException {
            File file = configFile();

            assertTrue(PrivacyConfig.writeDefaultIfMissing(file));

            assertEquals(PrivacyConfigSchema.generateDefaultFile(),
                Files.readString(file.toPath(), StandardCharsets.UTF_8));
        }

        @Test
        @DisplayName("written file should load back as the defaults")
        void writtenFileLoadsAsDefaults() throws IOException {
            File file = configFile();
            PrivacyConfig.writeDefaultIfMissing(file);

            PrivacyConfig loaded = PrivacyConfig.load(file);

            assertIsDefaults(loaded);
            assertEquals(PrivacyConfig.defaults().describe(), loaded.describe());
            assertFalse(testLogger.hasLevel(Level.WARNING));
            assertFalse(testLogger.hasLevel(Level.SEVERE));
        }

        @Test
        @DisplayName("should never overwrite an existing file")
        void neverOverwrites() throws IOException {
            File file = write("preset: passthrough\n");

            assertFalse(PrivacyConfig.writeDefaultIfMissing(file));

            assertEquals("preset: passthrough\n", Files.readString(file.toPath(), StandardCharsets.UTF_8));
        }

        @Test
        @DisplayName("should never overwrite an existing empty or invalid file")
        void neverOverwritesBrokenFiles() throws IOException {
            File file = write("");
            assertFalse(PrivacyConfig.writeDefaultIfMissing(file));
            assertEquals("", Files.readString(file.toPath()));

            write("routes: [unclosed");
            assertFalse(PrivacyConfig.writeDefaultIfMissing(file));
            assertEquals("routes: [unclosed", Files.readString(file.toPath()));
        }

        @Test
        @DisplayName("should not replace a directory")
        void doesNotReplaceDirectory() throws IOException {
            File dir = configFile();
            Files.createDirectory(dir.toPath());

            assertFalse(PrivacyConfig.writeDefaultIfMissing(dir));
            assertTrue(dir.isDirectory());
        }

        @Test
        @DisplayName("should write only once")
        void writesOnlyOnce() throws IOException {
            File file = configFile();
            assertTrue(PrivacyConfig.writeDefaultIfMissing(file));
            assertFalse(PrivacyConfig.writeDefaultIfMissing(file));
        }

        @Test
        @DisplayName("should throw IOException when the folder does not exist")
        void throwsWhenFolderMissing() {
            File file = tempDir.resolve("missing").resolve(PrivacyConfig.FILE_NAME).toFile();
            assertThrows(IOException.class, () -> PrivacyConfig.writeDefaultIfMissing(file));
            assertFalse(file.exists());
        }
    }

    @Nested
    @DisplayName("buildResolver")
    class BuildResolver {

        @ParameterizedTest
        @DisplayName("should use the preset's routes and default action")
        @org.junit.jupiter.params.provider.EnumSource(RoutePreset.class)
        void usesPreset(RoutePreset preset) {
            PrivacyConfig config = new PrivacyConfig(preset, List.of(), List.of(), false);

            RouteRegistry registry = config.buildResolver().getRegistry();

            assertEquals(preset.getRoutes(), registry.getRoutes());
            assertEquals(preset.getDefaultAction(), registry.getDefaultAction());
        }

        @Test
        @DisplayName("should put custom routes before the preset's routes")
        void customRoutesFirst() {
            Route custom = new Route("https?://update\\.coreprotect\\.net/.*", RouteActionType.PASSTHROUGH);
            PrivacyConfig config = new PrivacyConfig(RoutePreset.PRIVACY_FIRST, List.of(custom), List.of(), false);

            RouteRegistry registry = config.buildResolver().getRegistry();

            List<Route> expected = new ArrayList<>();
            expected.add(custom);
            expected.addAll(RoutePreset.PRIVACY_FIRST.getRoutes());
            assertEquals(expected, registry.getRoutes());

            RouteRegistry.RouteMatch match = registry.match("http://update.coreprotect.net/version/");
            assertSame(custom, match.getRoute());
            assertEquals(RouteActionType.PASSTHROUGH, match.getActionType());
        }

        @Test
        @DisplayName("should build a new resolver on each call")
        void buildsNewResolver() {
            PrivacyConfig config = PrivacyConfig.defaults();
            RouteResolver first = config.buildResolver();
            RouteResolver second = config.buildResolver();

            assertNotNull(first);
            assertNotSame(first, second);
        }
    }

    @Nested
    @DisplayName("buildResolver with update sources")
    class BuildResolverUpdates {

        private URLConnection updateCheck(RouteResolver resolver) throws IOException {
            Egress.install(resolver);
            try {
                URLConnection connection = Egress.openConnection(MockUrlFactory.updateUrl());
                connection.setRequestProperty("User-Agent", "CoreProtect/v24.1 (by Intelli)");
                return connection;
            } finally {
                Egress.uninstall();
            }
        }

        @AfterEach
        void clearStatus() {
            TestUpdateStatus.reset();
        }

        @Test
        @DisplayName("allow-updates should answer update checks from the configured sources")
        void allowUpdatesAsksSources() throws IOException {
            try (LocalHttpServer server = modrinthServer("24.1-libre2")) {
                PrivacyConfig config = new PrivacyConfig(RoutePreset.ALLOW_UPDATES, List.of(), modrinthAt(server), false);

                assertEquals("24.1.1", LocalHttpServer.read(updateCheck(config.buildResolver("24.1-libre1", null))));
                assertEquals(1, server.getRequests().size());
                assertEquals("24.1-libre2", UpdateStatus.current().version());
            }
        }

        @Test
        @DisplayName("privacy-first should never ask the update sources")
        void privacyFirstAsksNobody() throws IOException {
            try (LocalHttpServer server = modrinthServer("24.1-libre2")) {
                PrivacyConfig config = new PrivacyConfig(RoutePreset.PRIVACY_FIRST, List.of(), modrinthAt(server), false);

                assertThrows(EgressBlockedException.class, () -> updateCheck(config.buildResolver("24.1-libre1", null)));
                assertEquals(List.of(), server.getRequests());
                assertNull(UpdateStatus.current());
            }
        }

        @Test
        @DisplayName("allow-updates should answer without asking anyone when update checks are off")
        void allowUpdatesWithoutSources() throws IOException {
            try (LocalHttpServer server = modrinthServer("24.1-libre2")) {
                PrivacyConfig config = new PrivacyConfig(RoutePreset.ALLOW_UPDATES, List.of(), List.of(), false);

                assertEquals("24.1", LocalHttpServer.read(updateCheck(config.buildResolver("24.1-libre1", null))));
                assertEquals(List.of(), server.getRequests());
            }
        }

        @Test
        @DisplayName("allow-updates should stop asking the sources once check-updates is off in CoreProtect's config.yml")
        void checkUpdatesOff() throws IOException {
            Path coreProtectConfig = tempDir.resolve("config.yml");
            Files.writeString(coreProtectConfig, "check-updates: false\n");
            try (LocalHttpServer server = modrinthServer("24.1-libre2")) {
                PrivacyConfig config = new PrivacyConfig(RoutePreset.ALLOW_UPDATES, List.of(), modrinthAt(server), false);

                URLConnection connection = updateCheck(config.buildResolver("24.1-libre1", coreProtectConfig.toFile()));

                assertThrows(IOException.class, connection::getInputStream);
                assertEquals(List.of(), server.getRequests());
            }
        }

        @Test
        @DisplayName("a custom ANSWER route should ask the sources under privacy-first")
        void customAnswerRoute() throws IOException {
            try (LocalHttpServer server = modrinthServer("24.1-libre2")) {
                Route answerUpdates = new Route("https?://update\\.coreprotect\\.net/.*", RouteActionType.ANSWER);
                PrivacyConfig config = new PrivacyConfig(RoutePreset.PRIVACY_FIRST, List.of(answerUpdates),
                    modrinthAt(server), false);

                assertEquals("24.1.1", LocalHttpServer.read(updateCheck(config.buildResolver("24.1-libre1", null))));
                assertEquals(1, server.getRequests().size());
            }
        }
    }

    @Nested
    @DisplayName("describe")
    class Describe {

        @Test
        @DisplayName("should summarize the defaults")
        void summarizesDefaults() {
            assertEquals("preset privacy-first, 0 custom routes, default action BLOCK",
                PrivacyConfig.defaults().describe());
        }

        @Test
        @DisplayName("should use the singular for one custom route")
        void singularRoute() {
            PrivacyConfig config = new PrivacyConfig(RoutePreset.PASSTHROUGH,
                List.of(new Route("a", RouteActionType.BLOCK)), PrivacyConfig.defaultUpdateSources(), false);

            assertEquals("preset passthrough, 1 custom route, default action PASSTHROUGH", config.describe());
        }

        @Test
        @DisplayName("should mention verbose logging when enabled")
        void mentionsVerbose() {
            PrivacyConfig config = new PrivacyConfig(RoutePreset.ALLOW_UPDATES,
                List.of(new Route("a", RouteActionType.BLOCK), new Route("b", RouteActionType.ANSWER)),
                PrivacyConfig.defaultUpdateSources(), true);

            assertEquals("preset allow-updates, 2 custom routes, default action BLOCK, 2 update sources, verbose logging",
                config.describe());
        }

        @Test
        @DisplayName("should count update sources only when update checks are answered")
        void countsUpdateSourcesWhenAnswered() {
            List<UpdateSource> one = PrivacyConfig.defaultUpdateSources().subList(0, 1);
            Route answerUpdates = new Route("https?://update\\.coreprotect\\.net/.*", RouteActionType.ANSWER);

            assertEquals("preset allow-updates, 0 custom routes, default action BLOCK, 1 update source",
                new PrivacyConfig(RoutePreset.ALLOW_UPDATES, List.of(), one, false).describe());
            assertEquals("preset allow-updates, 0 custom routes, default action BLOCK, 0 update sources",
                new PrivacyConfig(RoutePreset.ALLOW_UPDATES, List.of(), List.of(), false).describe());
            assertEquals("preset privacy-first, 1 custom route, default action BLOCK, 1 update source",
                new PrivacyConfig(RoutePreset.PRIVACY_FIRST, List.of(answerUpdates), one, false).describe());
            assertEquals("preset privacy-first, 0 custom routes, default action BLOCK",
                new PrivacyConfig(RoutePreset.PRIVACY_FIRST, List.of(), one, false).describe());
        }
    }
}
