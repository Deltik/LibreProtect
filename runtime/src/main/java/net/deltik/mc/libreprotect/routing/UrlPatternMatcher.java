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

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Handles URL pattern matching with regex and named capture group extraction.
 *
 * Supports both Java-style named groups (?<name>...) and Python-style (?P<name>...).
 * The Python-style syntax is converted to Java-style during pattern compilation.
 */
public class UrlPatternMatcher {

    // Pattern to find Python-style named groups: (?P<name>...)
    private static final Pattern PYTHON_NAMED_GROUP = Pattern.compile("\\(\\?P<([a-zA-Z][a-zA-Z0-9]*)>");

    // Pattern to find named group names in a regex
    private static final Pattern NAMED_GROUP_FINDER = Pattern.compile("\\(\\?<([a-zA-Z][a-zA-Z0-9]*)>");

    /**
     * Result of a pattern match containing captured groups
     */
    public static class MatchResult {
        private final boolean matched;
        private final Map<String, String> captures;

        private MatchResult(boolean matched, Map<String, String> captures) {
            this.matched = matched;
            this.captures = captures != null ? captures : Collections.emptyMap();
        }

        public boolean isMatched() {
            return matched;
        }

        public Map<String, String> getCaptures() {
            return captures;
        }

        public static MatchResult noMatch() {
            return new MatchResult(false, null);
        }

        public static MatchResult match(Map<String, String> captures) {
            return new MatchResult(true, captures);
        }
    }

    /**
     * Convert Python-style named groups to Java-style.
     * (?P<name>...) -> (?<name>...)
     */
    public static String convertPythonNamedGroups(String pattern) {
        return PYTHON_NAMED_GROUP.matcher(pattern).replaceAll("(?<$1>");
    }

    /**
     * Extract all named group names from a pattern string.
     */
    public static Set<String> extractNamedGroups(String pattern) {
        Set<String> names = new HashSet<>();
        Matcher matcher = NAMED_GROUP_FINDER.matcher(pattern);
        while (matcher.find()) {
            names.add(matcher.group(1));
        }
        return names;
    }

    /**
     * Match a URL against a compiled pattern and extract named captures.
     *
     * @param pattern The compiled regex pattern
     * @param url The URL to match
     * @return MatchResult containing match status and any captured groups
     */
    public static MatchResult match(Pattern pattern, String url) {
        Matcher matcher = pattern.matcher(url);

        if (!matcher.matches()) {
            return MatchResult.noMatch();
        }

        // Extract named groups
        Set<String> groupNames = extractNamedGroups(pattern.pattern());
        Map<String, String> captures = new HashMap<>();

        for (String name : groupNames) {
            try {
                String value = matcher.group(name);
                if (value != null) {
                    captures.put(name, value);
                }
            } catch (IllegalArgumentException e) {
                // Group name not found, skip
            }
        }

        return MatchResult.match(captures);
    }

    /**
     * Substitute captured values into a target string.
     * Replaces ${name} placeholders with captured values.
     *
     * @param target The target string with ${name} placeholders
     * @param captures The captured values
     * @return The target string with placeholders replaced
     */
    public static String substituteCaptures(String target, Map<String, String> captures) {
        if (target == null || captures == null || captures.isEmpty()) {
            return target;
        }

        String result = target;
        for (Map.Entry<String, String> entry : captures.entrySet()) {
            String placeholder = "${" + entry.getKey() + "}";
            result = result.replace(placeholder, entry.getValue());
        }
        return result;
    }

    /**
     * Compile a pattern string, converting Python-style named groups if necessary.
     *
     * @param patternString The pattern string (may contain Python or Java named groups)
     * @return Compiled Pattern
     */
    public static Pattern compile(String patternString) {
        String converted = convertPythonNamedGroups(patternString);
        return Pattern.compile(converted);
    }
}
