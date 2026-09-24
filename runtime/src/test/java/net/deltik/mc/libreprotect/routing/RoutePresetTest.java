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

package net.deltik.mc.libreprotect.routing;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class RoutePresetTest {

    /**
     * Every endpoint CoreProtect and its bundled bStats are known to contact,
     * as matched after UrlNormalizer (lowercase scheme and host).
     */
    private static final List<String> KNOWN_ENDPOINT_PATTERNS = List.of(
        RoutePreset.STATS,
        RoutePreset.LICENSE,
        RoutePreset.TRANSLATE,
        RoutePreset.UPDATE,
        RoutePreset.ERROR_REPORTING,
        RoutePreset.BSTATS
    );

    @Nested
    @DisplayName("PRIVACY_FIRST preset")
    class PrivacyFirst {

        private final RoutePreset preset = RoutePreset.PRIVACY_FIRST;

        @Test
        @DisplayName("should have privacy-first config name")
        void hasCorrectConfigName() {
            assertEquals("privacy-first", preset.getConfigName());
        }

        @Test
        @DisplayName("should have BLOCK as default action")
        void hasBlockAsDefault() {
            assertEquals(RouteActionType.BLOCK, preset.getDefaultAction());
        }

        @Test
        @DisplayName("should have a route for every known endpoint")
        void hasRoutesForKnownEndpoints() {
            assertEquals(KNOWN_ENDPOINT_PATTERNS, patterns(preset));
        }

        @Test
        @DisplayName("should ANSWER the translation endpoint and BLOCK every other route")
        void answersTranslationsBlocksRest() {
            for (Route route : preset.getRoutes()) {
                RouteActionType expected = route.getPatternString().equals(RoutePreset.TRANSLATE)
                    ? RouteActionType.ANSWER
                    : RouteActionType.BLOCK;
                assertEquals(expected, route.getActionType(), route.toString());
            }
        }

        @Test
        @DisplayName("should make no network requests: no PASSTHROUGH or REDIRECT, and BLOCK by default")
        void makesNoNetworkRequests() {
            assertNoNetworkRequests(preset);
        }

        @ParameterizedTest
        @DisplayName("should block stats endpoint")
        @ValueSource(strings = {
            "https://stats.coreprotect.net/",
            "http://stats.coreprotect.net/submit",
            "https://stats.coreprotect.net/u/"
        })
        void blocksStatsEndpoint(String url) {
            assertRoutedTo(preset, url, RoutePreset.STATS, RouteActionType.BLOCK);
        }

        @ParameterizedTest
        @DisplayName("should block license endpoint")
        @ValueSource(strings = {
            "https://coreprotect.net/license/TESTKEY",
            "http://coreprotect.net/license/12345678"
        })
        void blocksLicenseEndpoint(String url) {
            assertRoutedTo(preset, url, RoutePreset.LICENSE, RouteActionType.BLOCK);
        }

        @ParameterizedTest
        @DisplayName("should block update endpoint")
        @ValueSource(strings = {
            "https://update.coreprotect.net/",
            "http://update.coreprotect.net/version/",
            "http://update.coreprotect.net/version-edge/"
        })
        void blocksUpdateEndpoint(String url) {
            assertRoutedTo(preset, url, RoutePreset.UPDATE, RouteActionType.BLOCK);
        }

        @ParameterizedTest
        @DisplayName("should answer translation endpoint")
        @ValueSource(strings = {
            "https://coreprotect.net/translate/",
            "http://coreprotect.net/translate/",
            "http://coreprotect.net/translate"
        })
        void answersTranslateEndpoint(String url) {
            assertRoutedTo(preset, url, RoutePreset.TRANSLATE, RouteActionType.ANSWER);
        }

        @ParameterizedTest
        @DisplayName("should block error reporting endpoint")
        @ValueSource(strings = {
            "https://error-reporting.coreprotect.net/",
            "https://error-reporting.coreprotect.net/api/report"
        })
        void blocksErrorReportingEndpoint(String url) {
            assertRoutedTo(preset, url, RoutePreset.ERROR_REPORTING, RouteActionType.BLOCK);
        }

        @ParameterizedTest
        @DisplayName("should block bStats endpoint")
        @ValueSource(strings = {
            "https://bstats.org/api/v2/data/bukkit",
            "http://bstats.org/submitData/bukkit"
        })
        void blocksBstatsEndpoint(String url) {
            assertRoutedTo(preset, url, RoutePreset.BSTATS, RouteActionType.BLOCK);
        }

        @ParameterizedTest
        @DisplayName("should block unknown URLs by default")
        @ValueSource(strings = {
            "https://example.com/",
            "https://coreprotect.net/",
            "file:///tmp/anything"
        })
        void blocksUnknownByDefault(String url) {
            RouteRegistry.RouteMatch match = registry(preset).match(url);
            assertTrue(match.isDefault(), url);
            assertEquals(RouteActionType.BLOCK, match.getActionType());
        }
    }

    @Nested
    @DisplayName("ALLOW_UPDATES preset")
    class AllowUpdates {

        private final RoutePreset preset = RoutePreset.ALLOW_UPDATES;

        @Test
        @DisplayName("should have allow-updates config name")
        void hasCorrectConfigName() {
            assertEquals("allow-updates", preset.getConfigName());
        }

        @Test
        @DisplayName("should have BLOCK as default action")
        void hasBlockAsDefault() {
            assertEquals(RouteActionType.BLOCK, preset.getDefaultAction());
        }

        @Test
        @DisplayName("should have a route for every known endpoint")
        void hasRoutesForKnownEndpoints() {
            assertEquals(KNOWN_ENDPOINT_PATTERNS, patterns(preset));
        }

        @Test
        @DisplayName("should ANSWER the translation and update endpoints and BLOCK the rest")
        void answersTranslationsAndUpdatesBlocksRest() {
            for (Route route : preset.getRoutes()) {
                RouteActionType expected = route.getPatternString().equals(RoutePreset.TRANSLATE)
                    || route.getPatternString().equals(RoutePreset.UPDATE)
                    ? RouteActionType.ANSWER
                    : RouteActionType.BLOCK;
                assertEquals(expected, route.getActionType(), route.toString());
            }
        }

        @Test
        @DisplayName("should never PASSTHROUGH or REDIRECT, and BLOCK by default")
        void makesNoNetworkRequests() {
            assertNoNetworkRequests(preset);
        }

        @ParameterizedTest
        @DisplayName("should answer update endpoint")
        @ValueSource(strings = {
            "https://update.coreprotect.net/",
            "http://update.coreprotect.net/version/",
            "http://update.coreprotect.net/version-edge/"
        })
        void answersUpdateEndpoint(String url) {
            assertRoutedTo(preset, url, RoutePreset.UPDATE, RouteActionType.ANSWER);
        }

        @ParameterizedTest
        @DisplayName("should answer translation endpoint")
        @ValueSource(strings = {
            "https://coreprotect.net/translate/",
            "http://coreprotect.net/translate"
        })
        void answersTranslateEndpoint(String url) {
            assertRoutedTo(preset, url, RoutePreset.TRANSLATE, RouteActionType.ANSWER);
        }

        @ParameterizedTest
        @DisplayName("should still block stats endpoint")
        @ValueSource(strings = {
            "https://stats.coreprotect.net/submit",
            "http://stats.coreprotect.net/u/"
        })
        void blocksStatsEndpoint(String url) {
            assertRoutedTo(preset, url, RoutePreset.STATS, RouteActionType.BLOCK);
        }

        @ParameterizedTest
        @DisplayName("should still block license endpoint")
        @ValueSource(strings = {
            "https://coreprotect.net/license/KEY",
            "http://coreprotect.net/license/12345678"
        })
        void blocksLicenseEndpoint(String url) {
            assertRoutedTo(preset, url, RoutePreset.LICENSE, RouteActionType.BLOCK);
        }

        @Test
        @DisplayName("should still block error reporting and bStats")
        void blocksOthers() {
            assertRoutedTo(preset, "https://error-reporting.coreprotect.net/x",
                RoutePreset.ERROR_REPORTING, RouteActionType.BLOCK);
            assertRoutedTo(preset, "https://bstats.org/api/v2/data/bukkit", RoutePreset.BSTATS, RouteActionType.BLOCK);
        }

        @Test
        @DisplayName("should block unknown URLs by default")
        void blocksUnknownByDefault() {
            RouteRegistry.RouteMatch match = registry(preset).match("https://example.com/");
            assertTrue(match.isDefault());
            assertEquals(RouteActionType.BLOCK, match.getActionType());
        }
    }

    @Nested
    @DisplayName("PASSTHROUGH preset")
    class Passthrough {

        private final RoutePreset preset = RoutePreset.PASSTHROUGH;

        @Test
        @DisplayName("should have passthrough config name")
        void hasCorrectConfigName() {
            assertEquals("passthrough", preset.getConfigName());
        }

        @Test
        @DisplayName("should have PASSTHROUGH as default action")
        void hasPassthroughAsDefault() {
            assertEquals(RouteActionType.PASSTHROUGH, preset.getDefaultAction());
        }

        @Test
        @DisplayName("should have no routes")
        void hasNoRoutes() {
            assertTrue(preset.getRoutes().isEmpty());
        }

        @ParameterizedTest
        @DisplayName("should pass every URL through by default")
        @ValueSource(strings = {
            "http://coreprotect.net/translate/",
            "http://update.coreprotect.net/version/",
            "https://stats.coreprotect.net/u/",
            "https://coreprotect.net/license/KEY",
            "https://bstats.org/api/v2/data/bukkit",
            "https://example.com/"
        })
        void passesEverything(String url) {
            RouteRegistry.RouteMatch match = registry(preset).match(url);
            assertTrue(match.isDefault());
            assertEquals(RouteActionType.PASSTHROUGH, match.getActionType());
        }
    }

    @Nested
    @DisplayName("Preset table")
    class PresetTable {

        @ParameterizedTest(name = "{0}: {1}, {2}, {3}")
        @DisplayName("should treat each endpoint as the table in the README says")
        @CsvSource({
            // URL,                                     privacy-first, allow-updates, passthrough
            "http://update.coreprotect.net/version/,    BLOCK,         ANSWER,        PASSTHROUGH",
            "http://stats.coreprotect.net/u/,           BLOCK,         BLOCK,         PASSTHROUGH",
            "http://coreprotect.net/license/KEY,        BLOCK,         BLOCK,         PASSTHROUGH",
            "http://coreprotect.net/translate/,         ANSWER,        ANSWER,        PASSTHROUGH",
            "https://error-reporting.coreprotect.net/x, BLOCK,         BLOCK,         PASSTHROUGH",
            "https://bstats.org/api/v2/data/bukkit,     BLOCK,         BLOCK,         PASSTHROUGH",
            "https://example.com/,                      BLOCK,         BLOCK,         PASSTHROUGH"
        })
        void matchesTable(String url, RouteActionType privacyFirst, RouteActionType allowUpdates,
                          RouteActionType passthrough) {
            assertEquals(privacyFirst, registry(RoutePreset.PRIVACY_FIRST).match(url).getActionType(), url);
            assertEquals(allowUpdates, registry(RoutePreset.ALLOW_UPDATES).match(url).getActionType(), url);
            assertEquals(passthrough, registry(RoutePreset.PASSTHROUGH).match(url).getActionType(), url);
        }
    }

    @Nested
    @DisplayName("Endpoint patterns")
    class EndpointPatterns {

        @ParameterizedTest
        @DisplayName("should not match lookalike hosts")
        @ValueSource(strings = {
            "https://stats.coreprotect.net.evil.example/",
            "https://evilcoreprotect.net/license/KEY",
            "https://notbstats.org/api",
            "https://update-coreprotect.net/version/",
            "https://coreprotect.net/translate/extra",
            "ftp://update.coreprotect.net/version/"
        })
        void doesNotMatchLookalikes(String url) {
            for (String pattern : KNOWN_ENDPOINT_PATTERNS) {
                assertFalse(UrlPatternMatcher.compile(pattern).matcher(url).matches(),
                    pattern + " should not match " + url);
            }
        }

        @Test
        @DisplayName("should be lowercase, since they match normalized URLs")
        void lowercase() {
            for (String pattern : KNOWN_ENDPOINT_PATTERNS) {
                assertEquals(pattern.toLowerCase(java.util.Locale.ROOT), pattern);
            }
        }
    }

    @Nested
    @DisplayName("fromConfigName")
    class FromConfigName {

        @ParameterizedTest
        @DisplayName("should parse valid config names")
        @CsvSource({
            "privacy-first, PRIVACY_FIRST",
            "allow-updates, ALLOW_UPDATES",
            "passthrough, PASSTHROUGH"
        })
        void parsesValidConfigNames(String configName, RoutePreset expected) {
            assertEquals(expected, RoutePreset.fromConfigName(configName));
        }

        @ParameterizedTest
        @DisplayName("should handle case-insensitive names")
        @ValueSource(strings = {"PRIVACY-FIRST", "Privacy-First", "PRIVACY-first"})
        void handlesCaseInsensitive(String configName) {
            assertEquals(RoutePreset.PRIVACY_FIRST, RoutePreset.fromConfigName(configName));
        }

        @Test
        @DisplayName("should return PRIVACY_FIRST for null")
        void returnsDefaultForNull() {
            assertEquals(RoutePreset.PRIVACY_FIRST, RoutePreset.fromConfigName(null));
        }

        @Test
        @DisplayName("should return PRIVACY_FIRST for unknown preset")
        void returnsDefaultForUnknown() {
            assertEquals(RoutePreset.PRIVACY_FIRST, RoutePreset.fromConfigName("unknown"));
        }

        @Test
        @DisplayName("should not accept enum constant names")
        void rejectsEnumNames() {
            assertEquals(RoutePreset.PRIVACY_FIRST, RoutePreset.fromConfigName("ALLOW_UPDATES"));
        }

        @Test
        @DisplayName("should trim whitespace")
        void trimsWhitespace() {
            assertEquals(RoutePreset.ALLOW_UPDATES, RoutePreset.fromConfigName("  allow-updates  "));
        }

        @Test
        @DisplayName("should handle empty string")
        void handlesEmptyString() {
            assertEquals(RoutePreset.PRIVACY_FIRST, RoutePreset.fromConfigName(""));
        }
    }

    @Nested
    @DisplayName("getAvailablePresets")
    class GetAvailablePresets {

        @Test
        @DisplayName("should return all preset names")
        void returnsAllPresetNames() {
            String[] names = RoutePreset.getAvailablePresets();
            assertEquals(RoutePreset.values().length, names.length);
        }

        @Test
        @DisplayName("should return config names not enum names")
        void returnsConfigNames() {
            String[] names = RoutePreset.getAvailablePresets();
            assertTrue(Arrays.asList(names).contains("privacy-first"));
            assertFalse(Arrays.asList(names).contains("PRIVACY_FIRST"));
        }

        @Test
        @DisplayName("should include all expected presets")
        void includesAllExpectedPresets() {
            List<String> names = Arrays.asList(RoutePreset.getAvailablePresets());
            assertTrue(names.contains("privacy-first"));
            assertTrue(names.contains("allow-updates"));
            assertTrue(names.contains("passthrough"));
        }
    }

    @Nested
    @DisplayName("getRoutes immutability")
    class RoutesImmutability {

        @Test
        @DisplayName("should return unmodifiable list")
        void returnsUnmodifiableList() {
            List<Route> routes = RoutePreset.PRIVACY_FIRST.getRoutes();
            assertThrows(UnsupportedOperationException.class, () -> routes.add(null));
        }

        @ParameterizedTest
        @DisplayName("should return the same routes on every call")
        @EnumSource(RoutePreset.class)
        void stableRoutes(RoutePreset preset) {
            assertEquals(preset.getRoutes(), preset.getRoutes());
        }
    }

    // Helper methods

    private static List<String> patterns(RoutePreset preset) {
        return preset.getRoutes().stream().map(Route::getPatternString).collect(Collectors.toList());
    }

    private static RouteRegistry registry(RoutePreset preset) {
        return new RouteConfigParser().buildRegistry(preset, null);
    }

    /**
     * Assert that nothing the preset does reaches the network: ANSWER and
     * BLOCK send nothing, PASSTHROUGH and REDIRECT would.
     */
    private static void assertNoNetworkRequests(RoutePreset preset) {
        for (Route route : preset.getRoutes()) {
            assertTrue(route.getActionType() == RouteActionType.ANSWER
                || route.getActionType() == RouteActionType.BLOCK, route.toString());
        }
        assertEquals(RouteActionType.BLOCK, preset.getDefaultAction());
    }

    /**
     * Assert that the preset's first matching route for the URL is the given
     * pattern with the given action, so a URL can't pass a test by matching
     * some other route or the default action.
     */
    private static void assertRoutedTo(RoutePreset preset, String url, String expectedPattern,
                                       RouteActionType expectedAction) {
        RouteRegistry.RouteMatch match = registry(preset).match(url);
        assertFalse(match.isDefault(), "Expected " + url + " to match a route, got the default action");
        assertEquals(expectedPattern, match.getRoute().getPatternString(), url);
        assertEquals(expectedAction, match.getActionType(),
            "Expected " + url + " to be " + expectedAction);
    }
}
