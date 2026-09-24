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
import net.deltik.mc.libreprotect.routing.RouteConfigParser;
import net.deltik.mc.libreprotect.routing.RoutePreset;
import net.deltik.mc.libreprotect.routing.RouteRegistry;
import net.deltik.mc.libreprotect.routing.UrlPatternMatcher;
import org.bukkit.configuration.InvalidConfigurationException;
import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class PrivacyConfigSchemaTest {

    @Nested
    @DisplayName("Constants")
    class Constants {

        @Test
        @DisplayName("should have a header naming LibreProtect")
        void headerContainsForkName() {
            boolean containsForkName = Arrays.stream(PrivacyConfigSchema.FILE_HEADER)
                .anyMatch(line -> line.contains(PrivacyConstants.FORK_NAME));
            assertTrue(containsForkName);
        }

        @Test
        @DisplayName("should have header with project URL")
        void headerContainsForkUrl() {
            assertTrue(Arrays.asList(PrivacyConfigSchema.FILE_HEADER).contains(PrivacyConstants.FORK_URL));
        }

        @Test
        @DisplayName("ALL_OPTIONS should contain all options")
        void allOptionsContainsAll() {
            assertEquals(3, PrivacyConfigSchema.ALL_OPTIONS.length);
        }
    }

    @Nested
    @DisplayName("ConfigOption")
    class ConfigOptionTests {

        @Test
        @DisplayName("PRESET should have correct defaults")
        void presetHasCorrectDefaults() {
            assertEquals("preset", PrivacyConfigSchema.PRESET.key);
            assertEquals("privacy-first", PrivacyConfigSchema.PRESET.defaultValue);
            assertEquals(PrivacyConfigSchema.ConfigType.STRING, PrivacyConfigSchema.PRESET.type);
        }

        @Test
        @DisplayName("PRESET default should name the privacy-first preset")
        void presetDefaultIsPrivacyFirst() {
            assertEquals(RoutePreset.PRIVACY_FIRST.getConfigName(), PrivacyConfigSchema.PRESET.defaultValue);
        }

        @Test
        @DisplayName("PRESET comments should document every preset")
        void presetCommentsDocumentEveryPreset() {
            for (String name : RoutePreset.getAvailablePresets()) {
                assertTrue(PrivacyConfigSchema.PRESET.comments.stream().anyMatch(c -> c.startsWith(name + " ")),
                    "Preset '" + name + "' is not documented");
            }
        }

        @Test
        @DisplayName("ROUTES should have empty list as default")
        void routesHasEmptyListDefault() {
            assertEquals("routes", PrivacyConfigSchema.ROUTES.key);
            assertTrue(((List<?>) PrivacyConfigSchema.ROUTES.defaultValue).isEmpty());
            assertEquals(PrivacyConfigSchema.ConfigType.LIST, PrivacyConfigSchema.ROUTES.type);
        }

        @Test
        @DisplayName("VERBOSE_LOGGING should default to false")
        void verboseLoggingDefaultsFalse() {
            assertEquals("verbose-logging", PrivacyConfigSchema.VERBOSE_LOGGING.key);
            assertEquals(false, PrivacyConfigSchema.VERBOSE_LOGGING.defaultValue);
            assertEquals(PrivacyConfigSchema.ConfigType.BOOLEAN, PrivacyConfigSchema.VERBOSE_LOGGING.type);
        }

        @Test
        @DisplayName("ConfigOption should have description")
        void configOptionHasDescription() {
            assertNotNull(PrivacyConfigSchema.PRESET.description);
            assertFalse(PrivacyConfigSchema.PRESET.description.isEmpty());
        }

        @Test
        @DisplayName("ConfigOption should have comments")
        void configOptionHasComments() {
            assertNotNull(PrivacyConfigSchema.PRESET.comments);
            assertFalse(PrivacyConfigSchema.PRESET.comments.isEmpty());
        }

        @Test
        @DisplayName("ConfigOption should infer INTEGER and fall back to STRING")
        void configOptionInfersTypes() {
            assertEquals(PrivacyConfigSchema.ConfigType.INTEGER,
                new PrivacyConfigSchema.ConfigOption("n", 1, "d").type);
            assertEquals(PrivacyConfigSchema.ConfigType.STRING,
                new PrivacyConfigSchema.ConfigOption("o", new Object(), "d").type);
        }
    }

    @Nested
    @DisplayName("getDefaults")
    class GetDefaults {

        @Test
        @DisplayName("should return map with all options")
        void returnsAllOptions() {
            Map<String, Object> defaults = PrivacyConfigSchema.getDefaults();

            assertEquals(PrivacyConfigSchema.ALL_OPTIONS.length, defaults.size());
            assertTrue(defaults.containsKey("preset"));
            assertTrue(defaults.containsKey("routes"));
            assertTrue(defaults.containsKey("verbose-logging"));
        }

        @Test
        @DisplayName("should return correct default values")
        void returnsCorrectDefaultValues() {
            Map<String, Object> defaults = PrivacyConfigSchema.getDefaults();

            assertEquals("privacy-first", defaults.get("preset"));
            assertTrue(((List<?>) defaults.get("routes")).isEmpty());
            assertEquals(false, defaults.get("verbose-logging"));
        }

        @Test
        @DisplayName("should keep options in declaration order")
        void keepsOrder() {
            assertEquals(List.of("preset", "routes", "verbose-logging"),
                new ArrayList<>(PrivacyConfigSchema.getDefaults().keySet()));
        }
    }

    @Nested
    @DisplayName("generateDefaultFile")
    class GenerateDefaultFile {

        @Test
        @DisplayName("should be the default file that README.md shows")
        void readme() throws IOException {
            // Tests run in the module's directory
            String readme = Files.readString(Path.of("..", "README.md"), StandardCharsets.UTF_8);
            String summary = "<details><summary>Default libreprotect.yml</summary>";
            int details = readme.indexOf(summary);
            assertTrue(details >= 0, "README.md has no " + summary);
            String section = readme.substring(details, readme.indexOf("</details>", details));
            String fence = "```yaml\n";
            int start = section.indexOf(fence);
            int end = section.indexOf("\n```\n", start);
            assertTrue(start >= 0 && end > start, "README.md's default libreprotect.yml isn't a YAML code block");

            assertEquals(PrivacyConfigSchema.generateDefaultFile(), section.substring(start + fence.length(), end + 1));
        }

        @Test
        @DisplayName("should contain every option")
        void containsEveryOption() {
            String yaml = PrivacyConfigSchema.generateDefaultFile();

            assertTrue(yaml.contains("preset:"));
            assertTrue(yaml.contains("routes:"));
            assertTrue(yaml.contains("verbose-logging:"));
        }

        @Test
        @DisplayName("should put options at the top level, not under a libreprotect section")
        void optionsAreTopLevel() {
            String yaml = PrivacyConfigSchema.generateDefaultFile();

            assertFalse(yaml.contains("libreprotect:"));
            for (PrivacyConfigSchema.ConfigOption option : PrivacyConfigSchema.ALL_OPTIONS) {
                assertTrue(yaml.lines().anyMatch(line -> line.startsWith(option.key + ": ")),
                    "No top-level line for " + option.key);
            }
        }

        @Test
        @DisplayName("should parse as YAML with exactly the schema's keys")
        void parsesWithSchemaKeys() throws InvalidConfigurationException {
            YamlConfiguration parsed = new YamlConfiguration();
            parsed.loadFromString(PrivacyConfigSchema.generateDefaultFile());

            assertEquals(PrivacyConfigSchema.getDefaults().keySet(), parsed.getKeys(false));
        }

        @Test
        @DisplayName("should parse back to the default values")
        void parsesToDefaults() throws InvalidConfigurationException {
            YamlConfiguration parsed = new YamlConfiguration();
            parsed.loadFromString(PrivacyConfigSchema.generateDefaultFile());

            assertEquals("privacy-first", parsed.getString("preset"));
            assertEquals(List.of(), parsed.getList("routes"));
            assertEquals(Boolean.FALSE, parsed.get("verbose-logging"));
        }

        @Test
        @DisplayName("should only contain comments, blank lines and option lines")
        void onlyCommentsAndOptions() {
            Set<String> keys = PrivacyConfigSchema.getDefaults().keySet();
            for (String line : PrivacyConfigSchema.generateDefaultFile().split("\n")) {
                boolean ok = line.isEmpty() || line.startsWith("#")
                    || keys.stream().anyMatch(key -> line.startsWith(key + ": "));
                assertTrue(ok, "Unexpected line: " + line);
            }
        }

        @Test
        @DisplayName("should include comments")
        void includesComments() {
            String yaml = PrivacyConfigSchema.generateDefaultFile();

            // Should have comment lines starting with #
            assertTrue(yaml.lines().anyMatch(line -> line.startsWith("# ")));
        }

        @Test
        @DisplayName("should include preset options in comments")
        void includesPresetOptionsInComments() {
            String yaml = PrivacyConfigSchema.generateDefaultFile();

            assertTrue(yaml.contains("privacy-first"));
            assertTrue(yaml.contains("allow-updates"));
            assertTrue(yaml.contains("passthrough"));
        }

        @Test
        @DisplayName("should have empty list for routes")
        void hasEmptyListForRoutes() {
            String yaml = PrivacyConfigSchema.generateDefaultFile();

            assertTrue(yaml.contains("routes: []"));
        }

        @Test
        @DisplayName("should have boolean value for verbose-logging")
        void hasBooleanForVerboseLogging() {
            String yaml = PrivacyConfigSchema.generateDefaultFile();

            assertTrue(yaml.contains("verbose-logging: false"));
        }

        @Test
        @DisplayName("should start with the file header")
        void startsWithHeader() {
            String yaml = PrivacyConfigSchema.generateDefaultFile();

            assertTrue(yaml.startsWith("# " + PrivacyConfigSchema.FILE_HEADER[0] + "\n"));
            assertTrue(yaml.contains(PrivacyConstants.FORK_NAME));
            assertTrue(yaml.contains("# " + PrivacyConstants.FORK_URL + "\n"));
        }

        @Test
        @DisplayName("should render blank header lines as a bare #")
        void blankHeaderLinesAreBareHash() {
            String yaml = PrivacyConfigSchema.generateDefaultFile();

            assertTrue(yaml.contains("\n#\n"));
            assertFalse(yaml.contains("# \n"));
        }

        @Test
        @DisplayName("should be deterministic")
        void isDeterministic() {
            assertEquals(PrivacyConfigSchema.generateDefaultFile(), PrivacyConfigSchema.generateDefaultFile());
        }

        @Test
        @DisplayName("commented route example should parse into a working REDIRECT route")
        void routeExampleWorks() throws InvalidConfigurationException {
            // Uncomment the example the way an operator would
            List<String> comments = PrivacyConfigSchema.ROUTES.comments;
            StringBuilder example = new StringBuilder("routes:\n");
            for (String line : comments.subList(comments.indexOf("Example:") + 1, comments.size())) {
                example.append(line).append("\n");
            }
            YamlConfiguration parsed = new YamlConfiguration();
            parsed.loadFromString(example.toString());

            List<Route> routes = new RouteConfigParser().parseRoutes(parsed.getList("routes"));

            assertEquals(1, routes.size());
            Route route = routes.get(0);
            assertEquals(RouteActionType.REDIRECT, route.getActionType());

            RouteRegistry.RouteMatch match = RouteRegistry.builder().addRoute(route).build()
                .match("http://update.coreprotect.net/version/");
            assertFalse(match.isDefault());
            assertEquals("http://my-mirror.example/version/",
                UrlPatternMatcher.substituteCaptures(route.getTarget(), match.getCaptures()));
        }
    }

    @Nested
    @DisplayName("getOption")
    class GetOption {

        @Test
        @DisplayName("should return option by key")
        void returnsOptionByKey() {
            var option = PrivacyConfigSchema.getOption("preset");
            assertNotNull(option);
            assertEquals("preset", option.key);
        }

        @Test
        @DisplayName("should return routes option")
        void returnsRoutesOption() {
            var option = PrivacyConfigSchema.getOption("routes");
            assertNotNull(option);
            assertEquals("routes", option.key);
        }

        @Test
        @DisplayName("should return verbose-logging option")
        void returnsVerboseLoggingOption() {
            var option = PrivacyConfigSchema.getOption("verbose-logging");
            assertNotNull(option);
            assertEquals("verbose-logging", option.key);
        }

        @Test
        @DisplayName("should return null for unknown key")
        void returnsNullForUnknownKey() {
            assertNull(PrivacyConfigSchema.getOption("unknown"));
        }

        @Test
        @DisplayName("should return null for null key")
        void returnsNullForNullKey() {
            assertNull(PrivacyConfigSchema.getOption(null));
        }
    }

    @Nested
    @DisplayName("isValidValue")
    class IsValidValue {

        @Test
        @DisplayName("should validate preset values")
        void validatesPresetValues() {
            assertTrue(PrivacyConfigSchema.isValidValue("preset", "privacy-first"));
            assertTrue(PrivacyConfigSchema.isValidValue("preset", "allow-updates"));
            assertTrue(PrivacyConfigSchema.isValidValue("preset", "passthrough"));
            assertFalse(PrivacyConfigSchema.isValidValue("preset", "invalid-preset"));
        }

        @Test
        @DisplayName("should accept preset values regardless of case and surrounding space")
        void acceptsPresetCaseAndSpace() {
            assertTrue(PrivacyConfigSchema.isValidValue("preset", "Allow-Updates"));
            assertTrue(PrivacyConfigSchema.isValidValue("preset", "  passthrough  "));
        }

        @Test
        @DisplayName("should reject non-string preset values")
        void rejectsNonStringPreset() {
            assertFalse(PrivacyConfigSchema.isValidValue("preset", null));
            assertFalse(PrivacyConfigSchema.isValidValue("preset", 1));
        }

        @Test
        @DisplayName("should validate routes as list")
        void validatesRoutesAsList() {
            assertTrue(PrivacyConfigSchema.isValidValue("routes", new ArrayList<>()));
            assertTrue(PrivacyConfigSchema.isValidValue("routes", List.of()));
            assertFalse(PrivacyConfigSchema.isValidValue("routes", "not a list"));
            assertFalse(PrivacyConfigSchema.isValidValue("routes", 123));
        }

        @Test
        @DisplayName("should validate verbose-logging as boolean")
        void validatesVerboseLogging() {
            assertTrue(PrivacyConfigSchema.isValidValue("verbose-logging", true));
            assertTrue(PrivacyConfigSchema.isValidValue("verbose-logging", false));
            assertTrue(PrivacyConfigSchema.isValidValue("verbose-logging", "true"));
            assertTrue(PrivacyConfigSchema.isValidValue("verbose-logging", "false"));
            assertTrue(PrivacyConfigSchema.isValidValue("verbose-logging", "yes"));
            assertTrue(PrivacyConfigSchema.isValidValue("verbose-logging", "no"));
            assertTrue(PrivacyConfigSchema.isValidValue("verbose-logging", "1"));
            assertTrue(PrivacyConfigSchema.isValidValue("verbose-logging", "0"));
        }

        @Test
        @DisplayName("should reject invalid boolean strings")
        void rejectsInvalidBooleanStrings() {
            assertFalse(PrivacyConfigSchema.isValidValue("verbose-logging", "invalid"));
            assertFalse(PrivacyConfigSchema.isValidValue("verbose-logging", "maybe"));
        }

        @Test
        @DisplayName("should return false for unknown key")
        void returnsFalseForUnknownKey() {
            assertFalse(PrivacyConfigSchema.isValidValue("unknown", "value"));
        }
    }

    @Nested
    @DisplayName("ConfigType")
    class ConfigTypeTests {

        @Test
        @DisplayName("should have all expected types")
        void hasAllExpectedTypes() {
            assertEquals(4, PrivacyConfigSchema.ConfigType.values().length);
            assertNotNull(PrivacyConfigSchema.ConfigType.STRING);
            assertNotNull(PrivacyConfigSchema.ConfigType.BOOLEAN);
            assertNotNull(PrivacyConfigSchema.ConfigType.INTEGER);
            assertNotNull(PrivacyConfigSchema.ConfigType.LIST);
        }
    }
}
