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
import org.junit.jupiter.params.provider.EnumSource;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class RouteRegistryTest {

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("should create registry with routes and default action")
        void createsRegistryWithRoutesAndDefault() {
            List<Route> routes = List.of(new Route(".*", RouteActionType.BLOCK));
            RouteRegistry registry = new RouteRegistry(routes, RouteActionType.PASSTHROUGH);

            assertEquals(1, registry.size());
            assertEquals(RouteActionType.PASSTHROUGH, registry.getDefaultAction());
        }

        @Test
        @DisplayName("should create defensive copy of routes")
        void createsDefensiveCopy() {
            List<Route> routes = new ArrayList<>();
            routes.add(new Route(".*", RouteActionType.BLOCK));
            RouteRegistry registry = new RouteRegistry(routes, RouteActionType.BLOCK);

            routes.clear(); // Modify original list
            assertEquals(1, registry.size()); // Registry should be unaffected
        }

        @Test
        @DisplayName("should accept empty route list")
        void acceptsEmptyRouteList() {
            RouteRegistry registry = new RouteRegistry(List.of(), RouteActionType.BLOCK);
            assertEquals(0, registry.size());
        }
    }

    @Nested
    @DisplayName("match")
    class Match {

        @Test
        @DisplayName("should match first matching route (first-match-wins)")
        void matchesFirstRoute() {
            RouteRegistry registry = RouteRegistry.builder()
                .addRoute("https://example\\.com/.*", RouteActionType.BLOCK)
                .addRoute("https://example\\.com/special", RouteActionType.MOCK)
                .build();

            RouteRegistry.RouteMatch match = registry.match("https://example.com/special");
            assertEquals(RouteActionType.BLOCK, match.getActionType()); // First match wins
            assertFalse(match.isDefault());
        }

        @Test
        @DisplayName("should return default match when no routes match")
        void returnsDefaultOnNoMatch() {
            RouteRegistry registry = RouteRegistry.builder()
                .addRoute("https://example\\.com/.*", RouteActionType.BLOCK)
                .setDefaultAction(RouteActionType.PASSTHROUGH)
                .build();

            RouteRegistry.RouteMatch match = registry.match("https://other.com/path");
            assertEquals(RouteActionType.PASSTHROUGH, match.getActionType());
            assertTrue(match.isDefault());
        }

        @Test
        @DisplayName("should capture named groups in match")
        void capturesNamedGroups() {
            RouteRegistry registry = RouteRegistry.builder()
                .addRoute("https://example\\.com/(?<path>.*)", RouteActionType.REDIRECT, "https://mirror/${path}")
                .build();

            RouteRegistry.RouteMatch match = registry.match("https://example.com/some/path");
            assertEquals("some/path", match.getCaptures().get("path"));
        }

        @Test
        @DisplayName("should match against empty registry using default")
        void matchesEmptyRegistryWithDefault() {
            RouteRegistry registry = RouteRegistry.builder()
                .setDefaultAction(RouteActionType.BLOCK)
                .build();

            RouteRegistry.RouteMatch match = registry.match("https://any.url.com");
            assertTrue(match.isDefault());
            assertEquals(RouteActionType.BLOCK, match.getActionType());
        }

        @Test
        @DisplayName("should match correct route among multiple")
        void matchesCorrectRouteAmongMultiple() {
            RouteRegistry registry = RouteRegistry.builder()
                .addRoute("https://stats\\.coreprotect\\.net/.*", RouteActionType.BLOCK)
                .addRoute("https://coreprotect\\.net/license/.*", RouteActionType.MOCK)
                .addRoute("https://update\\.coreprotect\\.net/.*", RouteActionType.PASSTHROUGH)
                .build();

            assertEquals(RouteActionType.BLOCK, registry.match("https://stats.coreprotect.net/submit").getActionType());
            assertEquals(RouteActionType.MOCK, registry.match("https://coreprotect.net/license/KEY").getActionType());
            assertEquals(RouteActionType.PASSTHROUGH, registry.match("https://update.coreprotect.net/check").getActionType());
        }
    }

    @Nested
    @DisplayName("getRoutes")
    class GetRoutes {

        @Test
        @DisplayName("should return unmodifiable list")
        void returnsUnmodifiableList() {
            RouteRegistry registry = RouteRegistry.builder()
                .addRoute(".*", RouteActionType.BLOCK)
                .build();

            List<Route> routes = registry.getRoutes();
            assertThrows(UnsupportedOperationException.class, () -> routes.add(null));
        }

        @Test
        @DisplayName("should return routes in order")
        void returnsRoutesInOrder() {
            RouteRegistry registry = RouteRegistry.builder()
                .addRoute("first", RouteActionType.BLOCK)
                .addRoute("second", RouteActionType.MOCK)
                .addRoute("third", RouteActionType.PASSTHROUGH)
                .build();

            List<Route> routes = registry.getRoutes();
            assertEquals("first", routes.get(0).getPatternString());
            assertEquals("second", routes.get(1).getPatternString());
            assertEquals("third", routes.get(2).getPatternString());
        }
    }

    @Nested
    @DisplayName("size")
    class Size {

        @Test
        @DisplayName("should return 0 for empty registry")
        void returnsZeroForEmpty() {
            RouteRegistry registry = RouteRegistry.builder().build();
            assertEquals(0, registry.size());
        }

        @Test
        @DisplayName("should return correct count")
        void returnsCorrectCount() {
            RouteRegistry registry = RouteRegistry.builder()
                .addRoute("a", RouteActionType.BLOCK)
                .addRoute("b", RouteActionType.MOCK)
                .addRoute("c", RouteActionType.PASSTHROUGH)
                .build();
            assertEquals(3, registry.size());
        }
    }

    @Nested
    @DisplayName("Builder")
    class BuilderTests {

        @Test
        @DisplayName("should build registry with fluent API")
        void buildsWithFluentApi() {
            RouteRegistry registry = RouteRegistry.builder()
                .addRoute("pattern1", RouteActionType.BLOCK)
                .addRoute("pattern2", RouteActionType.MOCK)
                .addRoute("pattern3", RouteActionType.REDIRECT, "target")
                .setDefaultAction(RouteActionType.PASSTHROUGH)
                .build();

            assertEquals(3, registry.size());
            assertEquals(RouteActionType.PASSTHROUGH, registry.getDefaultAction());
        }

        @Test
        @DisplayName("should add Route object")
        void addsRouteObject() {
            Route route = new Route("pattern", RouteActionType.BLOCK);
            RouteRegistry registry = RouteRegistry.builder()
                .addRoute(route)
                .build();

            assertEquals(1, registry.size());
        }

        @Test
        @DisplayName("should add routes from list")
        void addsRoutesFromList() {
            List<Route> routes = List.of(
                new Route("p1", RouteActionType.BLOCK),
                new Route("p2", RouteActionType.MOCK)
            );

            RouteRegistry registry = RouteRegistry.builder()
                .addRoutes(routes)
                .build();

            assertEquals(2, registry.size());
        }

        @Test
        @DisplayName("should use BLOCK as default action by default")
        void defaultsToBlock() {
            RouteRegistry registry = RouteRegistry.builder().build();
            assertEquals(RouteActionType.BLOCK, registry.getDefaultAction());
        }

        @Test
        @DisplayName("should support method chaining")
        void supportsMethodChaining() {
            RouteRegistry.Builder builder = RouteRegistry.builder();
            assertSame(builder, builder.addRoute("a", RouteActionType.BLOCK));
            assertSame(builder, builder.setDefaultAction(RouteActionType.MOCK));
        }
    }

    @Nested
    @DisplayName("RouteMatch")
    class RouteMatchTests {

        @Test
        @DisplayName("of() should create non-default match")
        void ofCreatesNonDefaultMatch() {
            Route route = new Route(".*", RouteActionType.BLOCK);
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.of(route, Map.of("key", "value"));

            assertFalse(match.isDefault());
            assertEquals(route, match.getRoute());
            assertEquals("value", match.getCaptures().get("key"));
        }

        @ParameterizedTest
        @DisplayName("defaultMatch() should create default match for each action type")
        @EnumSource(RouteActionType.class)
        void defaultMatchCreatesDefault(RouteActionType actionType) {
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.defaultMatch(actionType);

            assertTrue(match.isDefault());
            assertEquals(actionType, match.getActionType());
            assertTrue(match.getCaptures().isEmpty());
        }

        @Test
        @DisplayName("getRoute() should return matched route")
        void getRouteReturnsMatchedRoute() {
            Route route = new Route("test", RouteActionType.MOCK);
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.of(route, Map.of());
            assertSame(route, match.getRoute());
        }

        @Test
        @DisplayName("getCaptures() should return captures map")
        void getCapturesReturnsCapturesMap() {
            Route route = new Route(".*", RouteActionType.BLOCK);
            Map<String, String> captures = Map.of("a", "1", "b", "2");
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.of(route, captures);

            assertEquals(2, match.getCaptures().size());
            assertEquals("1", match.getCaptures().get("a"));
            assertEquals("2", match.getCaptures().get("b"));
        }
    }
}
