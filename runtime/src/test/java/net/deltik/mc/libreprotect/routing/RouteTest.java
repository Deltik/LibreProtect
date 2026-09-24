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

import java.util.regex.PatternSyntaxException;

import static org.junit.jupiter.api.Assertions.*;

class RouteTest {

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("should create route with pattern and action")
        void createsRouteWithPatternAndAction() {
            Route route = new Route("https://example\\.com/.*", RouteActionType.BLOCK);
            assertEquals("https://example\\.com/.*", route.getPatternString());
            assertEquals(RouteActionType.BLOCK, route.getActionType());
            assertNull(route.getTarget());
        }

        @Test
        @DisplayName("should create route with pattern, action, and target")
        void createsRouteWithTarget() {
            Route route = new Route("https://old\\.com/(?<path>.*)",
                RouteActionType.REDIRECT, "https://new.com/${path}");
            assertEquals(RouteActionType.REDIRECT, route.getActionType());
            assertEquals("https://new.com/${path}", route.getTarget());
        }

        @Test
        @DisplayName("should throw PatternSyntaxException for invalid regex")
        void throwsForInvalidRegex() {
            assertThrows(PatternSyntaxException.class,
                () -> new Route("[invalid", RouteActionType.BLOCK));
        }

        @ParameterizedTest
        @DisplayName("should compile pattern for each action type")
        @EnumSource(RouteActionType.class)
        void compilesPatternForAllActionTypes(RouteActionType actionType) {
            Route route = new Route(".*", actionType);
            assertNotNull(route.getCompiledPattern());
        }

        @Test
        @DisplayName("should allow null target for non-redirect")
        void allowsNullTargetForNonRedirect() {
            Route route = new Route(".*", RouteActionType.BLOCK, null);
            assertNull(route.getTarget());
        }
    }

    @Nested
    @DisplayName("Pattern Matching")
    class PatternMatching {

        @Test
        @DisplayName("should compile pattern that matches URLs")
        void compiledPatternMatchesUrls() {
            Route route = new Route("https://coreprotect\\.net/.*", RouteActionType.BLOCK);
            assertTrue(route.getCompiledPattern().matcher("https://coreprotect.net/license/key").matches());
            assertFalse(route.getCompiledPattern().matcher("https://other.com/path").matches());
        }

        @Test
        @DisplayName("should support Python-style named groups")
        void supportsPythonNamedGroups() {
            Route route = new Route("https://(?P<host>\\w+)\\.com/.*", RouteActionType.BLOCK);
            var matcher = route.getCompiledPattern().matcher("https://example.com/path");
            assertTrue(matcher.matches());
            assertEquals("example", matcher.group("host"));
        }

        @Test
        @DisplayName("should support Java-style named groups")
        void supportsJavaNamedGroups() {
            Route route = new Route("https://(?<host>\\w+)\\.com/.*", RouteActionType.BLOCK);
            var matcher = route.getCompiledPattern().matcher("https://example.com/path");
            assertTrue(matcher.matches());
            assertEquals("example", matcher.group("host"));
        }

        @Test
        @DisplayName("should match http and https with alternation")
        void matchesHttpAndHttps() {
            Route route = new Route("https?://example\\.com/.*", RouteActionType.ANSWER);
            assertTrue(route.getCompiledPattern().matcher("http://example.com/path").matches());
            assertTrue(route.getCompiledPattern().matcher("https://example.com/path").matches());
        }
    }

    @Nested
    @DisplayName("isRedirect")
    class IsRedirect {

        @Test
        @DisplayName("should return true for REDIRECT action")
        void returnsTrueForRedirect() {
            Route route = new Route(".*", RouteActionType.REDIRECT, "https://target.com");
            assertTrue(route.isRedirect());
        }

        @ParameterizedTest
        @DisplayName("should return false for non-REDIRECT actions")
        @EnumSource(value = RouteActionType.class, names = {"BLOCK", "ANSWER", "PASSTHROUGH"})
        void returnsFalseForNonRedirect(RouteActionType actionType) {
            Route route = new Route(".*", actionType);
            assertFalse(route.isRedirect());
        }
    }

    @Nested
    @DisplayName("Getters")
    class Getters {

        @Test
        @DisplayName("getPatternString should return original pattern")
        void getPatternStringReturnsOriginal() {
            String pattern = "(?P<name>\\w+)"; // Python style
            Route route = new Route(pattern, RouteActionType.BLOCK);
            assertEquals(pattern, route.getPatternString());
        }

        @Test
        @DisplayName("getCompiledPattern should return compiled pattern")
        void getCompiledPatternReturnsCompiled() {
            Route route = new Route("test", RouteActionType.BLOCK);
            assertNotNull(route.getCompiledPattern());
            assertTrue(route.getCompiledPattern().matcher("test").matches());
        }

        @Test
        @DisplayName("getActionType should return action type")
        void getActionTypeReturnsAction() {
            Route route = new Route(".*", RouteActionType.ANSWER);
            assertEquals(RouteActionType.ANSWER, route.getActionType());
        }

        @Test
        @DisplayName("getTarget should return target for redirect")
        void getTargetReturnsTarget() {
            String target = "https://new.com/${path}";
            Route route = new Route(".*", RouteActionType.REDIRECT, target);
            assertEquals(target, route.getTarget());
        }
    }

    @Nested
    @DisplayName("toString")
    class ToStringMethod {

        @Test
        @DisplayName("should format non-redirect route")
        void formatsNonRedirectRoute() {
            Route route = new Route("pattern", RouteActionType.BLOCK);
            String str = route.toString();
            assertTrue(str.contains("pattern"));
            assertTrue(str.contains("BLOCK"));
            assertFalse(str.contains("target"));
        }

        @Test
        @DisplayName("should format redirect route with target")
        void formatsRedirectRoute() {
            Route route = new Route("pattern", RouteActionType.REDIRECT, "target");
            String str = route.toString();
            assertTrue(str.contains("pattern"));
            assertTrue(str.contains("REDIRECT"));
            assertTrue(str.contains("target"));
        }

        @Test
        @DisplayName("should include Route class name")
        void includesClassName() {
            Route route = new Route(".*", RouteActionType.BLOCK);
            assertTrue(route.toString().startsWith("Route{"));
        }
    }
}
