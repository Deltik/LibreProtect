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

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.junit.jupiter.api.*;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class RouteConfigParserTest {

    private RouteConfigParser parser;
    private TestLogger testLogger;

    @BeforeEach
    void setUp() {
        parser = new RouteConfigParser();
        testLogger = new TestLogger();

        // Reset and initialize the logger
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(testLogger);
    }

    @AfterEach
    void tearDown() {
        LibreProtectLogger.reset();
    }

    @Nested
    @DisplayName("parseRoutes")
    class ParseRoutes {

        @Test
        @DisplayName("should parse valid route configuration")
        void parsesValidConfig() {
            List<Map<String, Object>> configs = List.of(
                Map.of("pattern", "https://example\\.com/.*", "action", "BLOCK")
            );

            List<Route> routes = parser.parseRoutes(configs);

            assertEquals(1, routes.size());
            assertEquals(RouteActionType.BLOCK, routes.get(0).getActionType());
        }

        @Test
        @DisplayName("should parse route with target")
        void parsesRouteWithTarget() {
            List<Map<String, Object>> configs = List.of(
                Map.of(
                    "pattern", "https://old\\.com/(?<path>.*)",
                    "action", "REDIRECT",
                    "target", "https://new.com/${path}"
                )
            );

            List<Route> routes = parser.parseRoutes(configs);

            assertEquals(1, routes.size());
            assertEquals(RouteActionType.REDIRECT, routes.get(0).getActionType());
            assertEquals("https://new.com/${path}", routes.get(0).getTarget());
        }

        @Test
        @DisplayName("should handle case-insensitive action names")
        void handlesCaseInsensitiveActions() {
            List<Map<String, Object>> configs = List.of(
                Map.of("pattern", "a", "action", "block"),
                Map.of("pattern", "b", "action", "Answer"),
                Map.of("pattern", "c", "action", "Passthrough")
            );

            List<Route> routes = parser.parseRoutes(configs);

            assertEquals(3, routes.size());
            assertEquals(RouteActionType.BLOCK, routes.get(0).getActionType());
            assertEquals(RouteActionType.ANSWER, routes.get(1).getActionType());
            assertEquals(RouteActionType.PASSTHROUGH, routes.get(2).getActionType());
        }

        @Test
        @DisplayName("should return empty list for null input")
        void returnsEmptyForNull() {
            List<Route> routes = parser.parseRoutes(null);
            assertTrue(routes.isEmpty());
        }

        @Test
        @DisplayName("should return empty list for empty input")
        void returnsEmptyForEmptyList() {
            List<Route> routes = parser.parseRoutes(List.of());
            assertTrue(routes.isEmpty());
        }

        @Test
        @DisplayName("should skip route missing pattern")
        void skipsRouteMissingPattern() {
            List<Map<String, Object>> configs = List.of(
                Map.of("action", "BLOCK")
            );

            List<Route> routes = parser.parseRoutes(configs);

            assertTrue(routes.isEmpty());
            assertTrue(testLogger.hasMessageContaining("has no 'pattern'"));
        }

        @Test
        @DisplayName("should skip route missing action")
        void skipsRouteMissingAction() {
            List<Map<String, Object>> configs = List.of(
                Map.of("pattern", ".*")
            );

            List<Route> routes = parser.parseRoutes(configs);

            assertTrue(routes.isEmpty());
            assertTrue(testLogger.hasMessageContaining("has no 'action'"));
        }

        @Test
        @DisplayName("should skip route with invalid action")
        void skipsRouteWithInvalidAction() {
            List<Map<String, Object>> configs = List.of(
                Map.of("pattern", ".*", "action", "INVALID_ACTION")
            );

            List<Route> routes = parser.parseRoutes(configs);

            assertTrue(routes.isEmpty());
            assertTrue(testLogger.hasMessageContaining(
                "its action 'INVALID_ACTION' isn't BLOCK, ANSWER, REDIRECT or PASSTHROUGH"));
        }

        @Test
        @DisplayName("should skip a route with the action MOCK")
        void skipsMock() {
            List<Route> routes = parser.parseRoutes(List.of(Map.of("pattern", ".*", "action", "mock")));

            assertTrue(routes.isEmpty());
            assertTrue(testLogger.hasMessageContaining("its action 'MOCK' isn't BLOCK, ANSWER, REDIRECT or PASSTHROUGH"));
        }

        @Test
        @DisplayName("should skip REDIRECT route without target")
        void skipsRedirectWithoutTarget() {
            List<Map<String, Object>> configs = List.of(
                Map.of("pattern", ".*", "action", "REDIRECT")
            );

            List<Route> routes = parser.parseRoutes(configs);

            assertTrue(routes.isEmpty());
            assertTrue(testLogger.hasMessageContaining("no 'target'"));
        }

        @Test
        @DisplayName("should skip REDIRECT route with empty target")
        void skipsRedirectWithEmptyTarget() {
            List<Map<String, Object>> configs = List.of(
                Map.of("pattern", ".*", "action", "REDIRECT", "target", "")
            );

            List<Route> routes = parser.parseRoutes(configs);

            assertTrue(routes.isEmpty());
        }

        @Test
        @DisplayName("should skip route with invalid regex")
        void skipsRouteWithInvalidRegex() {
            List<Map<String, Object>> configs = List.of(
                Map.of("pattern", "[invalid", "action", "BLOCK")
            );

            List<Route> routes = parser.parseRoutes(configs);

            assertTrue(routes.isEmpty());
            assertTrue(testLogger.hasMessageContaining("invalid regex"));
        }

        @Test
        @DisplayName("should skip non-map items in list")
        void skipsNonMapItems() {
            List<Object> configs = new ArrayList<>();
            configs.add("not a map");
            configs.add(null);
            configs.add(Map.of("pattern", ".*", "action", "BLOCK"));

            List<Route> routes = parser.parseRoutes(configs);

            assertEquals(1, routes.size());
            assertTrue(testLogger.hasMessageContaining("Skipping route #1 in libreprotect.yml: it isn't a map"));
            assertTrue(testLogger.hasMessageContaining("Skipping route #2 in libreprotect.yml: it isn't a map"));
        }

        @Test
        @DisplayName("should accept maps with any key and value types")
        void acceptsAnyMapTypes() {
            Map<Object, Object> config = new LinkedHashMap<>();
            config.put("pattern", 12345);
            config.put("action", RouteActionType.PASSTHROUGH);
            config.put(42, "ignored non-string key");
            List<Map<Object, Object>> configs = List.of(config);

            List<Route> routes = parser.parseRoutes(configs);

            assertEquals(1, routes.size());
            assertEquals("12345", routes.get(0).getPatternString());
            assertEquals(RouteActionType.PASSTHROUGH, routes.get(0).getActionType());
        }

        @Test
        @DisplayName("should number skipped routes from 1 in warnings")
        void numbersRoutesFromOne() {
            List<Map<String, Object>> configs = List.of(
                Map.of("pattern", "ok", "action", "BLOCK"),
                Map.of("pattern", "bad")
            );

            parser.parseRoutes(configs);

            assertTrue(testLogger.hasMessageContaining("Skipping route #2 in libreprotect.yml: it has no 'action'"));
        }

        @Test
        @DisplayName("should parse multiple valid routes")
        void parsesMultipleRoutes() {
            List<Map<String, Object>> configs = List.of(
                Map.of("pattern", "p1", "action", "BLOCK"),
                Map.of("pattern", "p2", "action", "ANSWER"),
                Map.of("pattern", "p3", "action", "PASSTHROUGH")
            );

            List<Route> routes = parser.parseRoutes(configs);

            assertEquals(3, routes.size());
        }

        @Test
        @DisplayName("should accept non-REDIRECT with target (ignored)")
        void acceptsNonRedirectWithTarget() {
            List<Map<String, Object>> configs = List.of(
                Map.of("pattern", ".*", "action", "BLOCK", "target", "ignored")
            );

            List<Route> routes = parser.parseRoutes(configs);

            assertEquals(1, routes.size());
            assertEquals(RouteActionType.BLOCK, routes.get(0).getActionType());
            // Target may or may not be stored; the key is no error
        }
    }

    @Nested
    @DisplayName("buildRegistry")
    class BuildRegistry {

        @Test
        @DisplayName("should build registry with custom routes first")
        void buildsRegistryWithCustomRoutesFirst() {
            List<Route> customRoutes = List.of(
                new Route("custom-pattern", RouteActionType.PASSTHROUGH)
            );

            RouteRegistry registry = parser.buildRegistry(RoutePreset.PRIVACY_FIRST, customRoutes);

            // Custom routes should be checked first
            assertEquals("custom-pattern", registry.getRoutes().get(0).getPatternString());
        }

        @Test
        @DisplayName("should include preset routes after custom routes")
        void includesPresetRoutesAfterCustom() {
            List<Route> customRoutes = List.of(
                new Route("custom", RouteActionType.BLOCK)
            );

            RouteRegistry registry = parser.buildRegistry(RoutePreset.PRIVACY_FIRST, customRoutes);

            // Total routes should be custom + preset routes
            assertTrue(registry.size() > 1);
        }

        @Test
        @DisplayName("should handle null custom routes")
        void handlesNullCustomRoutes() {
            RouteRegistry registry = parser.buildRegistry(RoutePreset.PRIVACY_FIRST, null);

            // Should only have preset routes
            assertEquals(RoutePreset.PRIVACY_FIRST.getRoutes().size(), registry.size());
        }

        @Test
        @DisplayName("should handle empty custom routes")
        void handlesEmptyCustomRoutes() {
            RouteRegistry registry = parser.buildRegistry(RoutePreset.PRIVACY_FIRST, List.of());

            // Should only have preset routes
            assertEquals(RoutePreset.PRIVACY_FIRST.getRoutes().size(), registry.size());
        }

        @Test
        @DisplayName("should use preset default action")
        void usesPresetDefaultAction() {
            RouteRegistry registry = parser.buildRegistry(RoutePreset.PASSTHROUGH, null);

            assertEquals(RouteActionType.PASSTHROUGH, registry.getDefaultAction());
        }

        @Test
        @DisplayName("should use BLOCK default for PRIVACY_FIRST")
        void usesBlockDefaultForPrivacyFirst() {
            RouteRegistry registry = parser.buildRegistry(RoutePreset.PRIVACY_FIRST, null);

            assertEquals(RouteActionType.BLOCK, registry.getDefaultAction());
        }
    }
}
