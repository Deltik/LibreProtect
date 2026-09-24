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

import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static org.junit.jupiter.api.Assertions.*;

class UrlPatternMatcherTest {

    @Nested
    @DisplayName("convertPythonNamedGroups")
    class ConvertPythonNamedGroups {

        @Test
        @DisplayName("should convert single Python-style named group to Java-style")
        void convertsSinglePythonGroup() {
            String input = "(?P<name>\\w+)";
            String expected = "(?<name>\\w+)";
            assertEquals(expected, UrlPatternMatcher.convertPythonNamedGroups(input));
        }

        @Test
        @DisplayName("should convert multiple Python-style groups")
        void convertsMultiplePythonGroups() {
            String input = "(?P<host>\\w+)\\.(?P<domain>\\w+)";
            String expected = "(?<host>\\w+)\\.(?<domain>\\w+)";
            assertEquals(expected, UrlPatternMatcher.convertPythonNamedGroups(input));
        }

        @Test
        @DisplayName("should preserve Java-style named groups unchanged")
        void preservesJavaGroups() {
            String input = "(?<name>\\w+)";
            assertEquals(input, UrlPatternMatcher.convertPythonNamedGroups(input));
        }

        @Test
        @DisplayName("should handle patterns without named groups")
        void handlesNoNamedGroups() {
            String input = "https://example\\.com/.*";
            assertEquals(input, UrlPatternMatcher.convertPythonNamedGroups(input));
        }

        @Test
        @DisplayName("should handle empty string")
        void handlesEmptyString() {
            assertEquals("", UrlPatternMatcher.convertPythonNamedGroups(""));
        }

        @ParameterizedTest
        @DisplayName("should convert various valid group names")
        @ValueSource(strings = {"a", "name", "path123", "UPPER", "CamelCase"})
        void convertsValidGroupNames(String groupName) {
            String input = "(?P<" + groupName + ">\\w+)";
            String expected = "(?<" + groupName + ">\\w+)";
            assertEquals(expected, UrlPatternMatcher.convertPythonNamedGroups(input));
        }

        @Test
        @DisplayName("should handle mixed Python and Java groups")
        void handlesMixedGroups() {
            String input = "(?P<python>\\w+)/(?<java>\\w+)";
            String expected = "(?<python>\\w+)/(?<java>\\w+)";
            assertEquals(expected, UrlPatternMatcher.convertPythonNamedGroups(input));
        }
    }

    @Nested
    @DisplayName("extractNamedGroups")
    class ExtractNamedGroups {

        @Test
        @DisplayName("should extract single named group")
        void extractsSingleGroup() {
            Set<String> groups = UrlPatternMatcher.extractNamedGroups("(?<name>\\w+)");
            assertEquals(1, groups.size());
            assertTrue(groups.contains("name"));
        }

        @Test
        @DisplayName("should extract multiple named groups")
        void extractsMultipleGroups() {
            Set<String> groups = UrlPatternMatcher.extractNamedGroups("(?<host>\\w+)/(?<path>.*)");
            assertEquals(2, groups.size());
            assertTrue(groups.contains("host"));
            assertTrue(groups.contains("path"));
        }

        @Test
        @DisplayName("should return empty set for no named groups")
        void returnsEmptyForNoGroups() {
            Set<String> groups = UrlPatternMatcher.extractNamedGroups("\\w+/.*");
            assertTrue(groups.isEmpty());
        }

        @Test
        @DisplayName("should not extract Python-style groups (not converted)")
        void doesNotExtractPythonGroups() {
            Set<String> groups = UrlPatternMatcher.extractNamedGroups("(?P<name>\\w+)");
            assertTrue(groups.isEmpty()); // Python syntax not recognized by Java regex
        }

        @Test
        @DisplayName("should handle empty string")
        void handlesEmptyString() {
            Set<String> groups = UrlPatternMatcher.extractNamedGroups("");
            assertTrue(groups.isEmpty());
        }
    }

    @Nested
    @DisplayName("match")
    class Match {

        @Test
        @DisplayName("should match simple URL pattern")
        void matchesSimplePattern() {
            Pattern pattern = Pattern.compile("https://example\\.com/.*");
            UrlPatternMatcher.MatchResult result = UrlPatternMatcher.match(pattern, "https://example.com/path");
            assertTrue(result.isMatched());
        }

        @Test
        @DisplayName("should return no match for non-matching URL")
        void noMatchForDifferentUrl() {
            Pattern pattern = Pattern.compile("https://example\\.com/.*");
            UrlPatternMatcher.MatchResult result = UrlPatternMatcher.match(pattern, "https://other.com/path");
            assertFalse(result.isMatched());
        }

        @Test
        @DisplayName("should capture named groups")
        void capturesNamedGroups() {
            Pattern pattern = Pattern.compile("https://(?<host>\\w+)\\.com/(?<path>.*)");
            UrlPatternMatcher.MatchResult result = UrlPatternMatcher.match(pattern, "https://example.com/some/path");
            assertTrue(result.isMatched());
            assertEquals("example", result.getCaptures().get("host"));
            assertEquals("some/path", result.getCaptures().get("path"));
        }

        @Test
        @DisplayName("should return empty captures map on no match")
        void emptyCapturesOnNoMatch() {
            Pattern pattern = Pattern.compile("https://example\\.com/.*");
            UrlPatternMatcher.MatchResult result = UrlPatternMatcher.match(pattern, "https://other.com/path");
            assertTrue(result.getCaptures().isEmpty());
        }

        @Test
        @DisplayName("should handle pattern with no captures")
        void handlesNoCaptureGroups() {
            Pattern pattern = Pattern.compile("https://example\\.com/.*");
            UrlPatternMatcher.MatchResult result = UrlPatternMatcher.match(pattern, "https://example.com/path");
            assertTrue(result.isMatched());
            assertTrue(result.getCaptures().isEmpty());
        }

        @Test
        @DisplayName("should match URL with query string")
        void matchesUrlWithQueryString() {
            Pattern pattern = Pattern.compile("https://example\\.com/.*");
            UrlPatternMatcher.MatchResult result = UrlPatternMatcher.match(pattern, "https://example.com/path?query=value");
            assertTrue(result.isMatched());
        }

        @Test
        @DisplayName("should capture optional groups")
        void capturesOptionalGroups() {
            Pattern pattern = Pattern.compile("https://example\\.com/(?<version>v\\d+)?/?(?<path>.*)");
            UrlPatternMatcher.MatchResult result = UrlPatternMatcher.match(pattern, "https://example.com/v2/api");
            assertTrue(result.isMatched());
            assertEquals("v2", result.getCaptures().get("version"));
        }
    }

    @Nested
    @DisplayName("substituteCaptures")
    class SubstituteCaptures {

        @Test
        @DisplayName("should substitute single placeholder")
        void substitutesSinglePlaceholder() {
            Map<String, String> captures = Map.of("path", "some/value");
            String result = UrlPatternMatcher.substituteCaptures("https://mirror.com/${path}", captures);
            assertEquals("https://mirror.com/some/value", result);
        }

        @Test
        @DisplayName("should substitute multiple placeholders")
        void substitutesMultiplePlaceholders() {
            Map<String, String> captures = Map.of("host", "newhost", "path", "newpath");
            String result = UrlPatternMatcher.substituteCaptures("https://${host}.com/${path}", captures);
            assertEquals("https://newhost.com/newpath", result);
        }

        @Test
        @DisplayName("should leave unknown placeholders unchanged")
        void leavesUnknownPlaceholders() {
            Map<String, String> captures = Map.of("known", "value");
            String result = UrlPatternMatcher.substituteCaptures("${known}/${unknown}", captures);
            assertEquals("value/${unknown}", result);
        }

        @Test
        @DisplayName("should handle null target")
        void handlesNullTarget() {
            assertNull(UrlPatternMatcher.substituteCaptures(null, Map.of("key", "value")));
        }

        @Test
        @DisplayName("should handle empty captures")
        void handlesEmptyCaptures() {
            String target = "https://example.com/${path}";
            assertEquals(target, UrlPatternMatcher.substituteCaptures(target, Map.of()));
        }

        @Test
        @DisplayName("should handle null captures")
        void handlesNullCaptures() {
            String target = "https://example.com/path";
            assertEquals(target, UrlPatternMatcher.substituteCaptures(target, null));
        }

        @Test
        @DisplayName("should handle repeated placeholder")
        void handlesRepeatedPlaceholder() {
            Map<String, String> captures = Map.of("name", "test");
            String result = UrlPatternMatcher.substituteCaptures("${name}/${name}", captures);
            assertEquals("test/test", result);
        }

        @Test
        @DisplayName("should handle special characters in capture value")
        void handlesSpecialCharsInCapture() {
            Map<String, String> captures = Map.of("path", "path/with/slashes");
            String result = UrlPatternMatcher.substituteCaptures("https://host/${path}", captures);
            assertEquals("https://host/path/with/slashes", result);
        }
    }

    @Nested
    @DisplayName("compile")
    class Compile {

        @Test
        @DisplayName("should compile valid pattern")
        void compilesValidPattern() {
            Pattern pattern = UrlPatternMatcher.compile("https://example\\.com/.*");
            assertNotNull(pattern);
        }

        @Test
        @DisplayName("should convert Python groups during compilation")
        void convertsPythonGroupsDuringCompile() {
            Pattern pattern = UrlPatternMatcher.compile("(?P<name>\\w+)");
            UrlPatternMatcher.MatchResult result = UrlPatternMatcher.match(pattern, "test");
            assertTrue(result.isMatched());
            assertEquals("test", result.getCaptures().get("name"));
        }

        @Test
        @DisplayName("should throw PatternSyntaxException for invalid regex")
        void throwsForInvalidRegex() {
            assertThrows(PatternSyntaxException.class,
                () -> UrlPatternMatcher.compile("[invalid"));
        }

        @Test
        @DisplayName("should compile pattern with both http and https")
        void compilesHttpAndHttps() {
            Pattern pattern = UrlPatternMatcher.compile("https?://example\\.com/.*");
            assertTrue(pattern.matcher("http://example.com/path").matches());
            assertTrue(pattern.matcher("https://example.com/path").matches());
        }
    }

    @Nested
    @DisplayName("MatchResult")
    class MatchResultTests {

        @Test
        @DisplayName("noMatch() should return non-matching result")
        void noMatchReturnsNonMatchingResult() {
            UrlPatternMatcher.MatchResult result = UrlPatternMatcher.MatchResult.noMatch();
            assertFalse(result.isMatched());
            assertTrue(result.getCaptures().isEmpty());
        }

        @Test
        @DisplayName("match() should return matching result with captures")
        void matchReturnsMatchingResult() {
            Map<String, String> captures = Map.of("key", "value");
            UrlPatternMatcher.MatchResult result = UrlPatternMatcher.MatchResult.match(captures);
            assertTrue(result.isMatched());
            assertEquals("value", result.getCaptures().get("key"));
        }

        @Test
        @DisplayName("match() with null captures should return empty map")
        void matchWithNullCapturesReturnsEmptyMap() {
            UrlPatternMatcher.MatchResult result = UrlPatternMatcher.MatchResult.match(null);
            assertTrue(result.isMatched());
            assertTrue(result.getCaptures().isEmpty());
        }
    }
}
