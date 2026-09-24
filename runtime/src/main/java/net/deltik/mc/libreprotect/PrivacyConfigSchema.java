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

import net.deltik.mc.libreprotect.routing.RoutePreset;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Schema definition for LibreProtect privacy configuration.
 * Defines the structure, defaults, and documentation for all privacy settings.
 */
public class PrivacyConfigSchema {

    /**
     * Configuration option definition
     */
    public static class ConfigOption {
        public final String key;
        public final Object defaultValue;
        public final String description;
        public final List<String> comments;
        public final ConfigType type;

        public ConfigOption(String key, Object defaultValue, String description, String... comments) {
            this.key = key;
            this.defaultValue = defaultValue;
            this.description = description;
            this.comments = Arrays.asList(comments);
            this.type = determineType(defaultValue);
        }

        private ConfigType determineType(Object value) {
            if (value instanceof Boolean) return ConfigType.BOOLEAN;
            if (value instanceof String) return ConfigType.STRING;
            if (value instanceof Integer) return ConfigType.INTEGER;
            if (value instanceof List) return ConfigType.LIST;
            return ConfigType.STRING;
        }
    }

    public enum ConfigType {
        STRING, BOOLEAN, INTEGER, LIST
    }

    // File header
    public static final String[] FILE_HEADER = {
        PrivacyConstants.FORK_NAME + " network policy",
        "",
        "Controls the web requests that CoreProtect makes: update checks, usage",
        "statistics, error reports, bStats, donation-key checks and translations.",
        "Connections to the databases in config.yml aren't affected.",
        "Changes take effect after a server restart.",
        "",
        PrivacyConstants.FORK_URL
    };

    // Configuration options
    public static final ConfigOption PRESET = new ConfigOption(
        "preset",
        "privacy-first",
        "What happens to requests that no route matches",
        "privacy-first - Send no web requests: LibreProtect answers translations itself and blocks the rest (default)",
        "allow-updates - Like privacy-first, but LibreProtect also answers update checks from update-sources",
        "passthrough - Allow every request through unchanged (for debugging). Bundled translations fill any gaps"
    );

    public static final ConfigOption UPDATE_SOURCES = new ConfigOption(
        "update-sources",
        Collections.unmodifiableList(Arrays.asList(
            item("type", "github", "repository", "Deltik/LibreProtect"),
            item("type", "modrinth", "project", "libreprotect"))),
        "Where update checks go when the preset allows them",
        "LibreProtect asks each source in order until one answers.",
        "Requests name LibreProtect but carry no version, server port or key. Sources see your server's IP address.",
        "Each source has a type and its settings:",
        "  type: github, with repository: owner/name",
        "  type: modrinth, with project: a Modrinth project ID or slug",
        "Either type also takes api: the base URL of the API, for a mirror",
        "Set this to [] to turn update checks off"
    );

    public static final ConfigOption ROUTES = new ConfigOption(
        "routes",
        new ArrayList<>(),
        "Custom routes, checked in order before the preset. The first match decides.",
        "Each route has: pattern (regex), action (BLOCK/ANSWER/REDIRECT/PASSTHROUGH), target (for REDIRECT)",
        "Patterns match the whole URL with a lowercase scheme and host, without user info or fragment",
        "Patterns support named capture groups: (?<name>...) or (?P<name>...)",
        "Capture substitution in targets: ${name}",
        "REDIRECT targets should keep the original scheme (http or https)",
        "Example:",
        "  - pattern: \"http://update\\\\.coreprotect\\\\.net(?<path>/.*)\"",
        "    action: REDIRECT",
        "    target: \"http://my-mirror.example${path}\""
    );

    public static final ConfigOption VERBOSE_LOGGING = new ConfigOption(
        "verbose-logging",
        false,
        "Log every network request that LibreProtect intercepts"
    );

    // All options in order
    public static final ConfigOption[] ALL_OPTIONS = {
        PRESET,
        UPDATE_SOURCES,
        ROUTES,
        VERBOSE_LOGGING
    };

    /** Strings that YAML reads back as themselves when written without quotes, apart from {@link #YAML_WORDS} */
    private static final Pattern PLAIN = Pattern.compile("[A-Za-z][A-Za-z0-9._/-]*");
    /** Words that YAML 1.1 reads as booleans or null */
    private static final Set<String> YAML_WORDS = Set.of("true", "false", "yes", "no", "on", "off", "y", "n", "null");

    /**
     * @param keysAndValues alternating keys and values
     * @return an unmodifiable map that keeps the order of its keys, for a
     *         list item of a default value
     */
    private static Map<String, Object> item(Object... keysAndValues) {
        Map<String, Object> item = new LinkedHashMap<>();
        for (int i = 0; i + 1 < keysAndValues.length; i += 2) {
            item.put(keysAndValues[i].toString(), keysAndValues[i + 1]);
        }
        return Collections.unmodifiableMap(item);
    }

    /**
     * Generate the default configuration map
     */
    public static Map<String, Object> getDefaults() {
        Map<String, Object> defaults = new LinkedHashMap<>();
        for (ConfigOption option : ALL_OPTIONS) {
            defaults.put(option.key, option.defaultValue);
        }
        return defaults;
    }

    /**
     * Generate the contents of a commented default settings file
     */
    public static String generateDefaultFile() {
        StringBuilder yaml = new StringBuilder();

        for (String headerLine : FILE_HEADER) {
            yaml.append(headerLine.isEmpty() ? "#" : "# " + headerLine).append("\n");
        }

        for (ConfigOption option : ALL_OPTIONS) {
            yaml.append("\n");
            yaml.append("# ").append(option.description).append("\n");
            for (String comment : option.comments) {
                yaml.append("# ").append(comment).append("\n");
            }

            yaml.append(option.key).append(":");
            if (option.type == ConfigType.LIST && !((List<?>) option.defaultValue).isEmpty()) {
                yaml.append("\n");
                appendItems(yaml, (List<?>) option.defaultValue);
            } else {
                yaml.append(" ").append(scalar(option.defaultValue)).append("\n");
            }
        }

        return yaml.toString();
    }

    /**
     * Append a list in block style, with each map item's entries on lines of
     * their own
     */
    private static void appendItems(StringBuilder yaml, List<?> items) {
        for (Object item : items) {
            if (item instanceof Map && !((Map<?, ?>) item).isEmpty()) {
                String indent = "  - ";
                for (Map.Entry<?, ?> entry : ((Map<?, ?>) item).entrySet()) {
                    yaml.append(indent).append(entry.getKey()).append(": ").append(scalar(entry.getValue())).append("\n");
                    indent = "    ";
                }
            } else {
                yaml.append("  - ").append(scalar(item)).append("\n");
            }
        }
    }

    /**
     * @return the value as a YAML scalar: plain if YAML reads it back as the
     *         same string, otherwise quoted
     */
    private static String scalar(Object value) {
        if (value instanceof List) {
            return "[]";
        }
        if (value instanceof Map) {
            return "{}";
        }
        if (!(value instanceof String)) {
            return value.toString().toLowerCase(Locale.ROOT);
        }
        String text = (String) value;
        if (PLAIN.matcher(text).matches() && !YAML_WORDS.contains(text.toLowerCase(Locale.ROOT))) {
            return text;
        }
        return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    /**
     * Get a configuration option by key
     */
    public static ConfigOption getOption(String key) {
        for (ConfigOption option : ALL_OPTIONS) {
            if (option.key.equals(key)) {
                return option;
            }
        }
        return null;
    }

    /**
     * Validate a configuration value
     */
    public static boolean isValidValue(String key, Object value) {
        ConfigOption option = getOption(key);
        if (option == null) return false;

        switch (option.key) {
            case "preset":
                if (!(value instanceof String)) return false;
                String preset = value.toString().toLowerCase(Locale.ROOT).trim();
                for (RoutePreset p : RoutePreset.values()) {
                    if (p.getConfigName().equals(preset)) {
                        return true;
                    }
                }
                return false;

            case "update-sources":
            case "routes":
                return value instanceof List;

            case "verbose-logging":
                return value instanceof Boolean ||
                       (value instanceof String && isValidBooleanString(value.toString()));

            default:
                return true;
        }
    }

    private static boolean isValidBooleanString(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        return lower.equals("true") || lower.equals("false") ||
               lower.equals("yes") || lower.equals("no") ||
               lower.equals("1") || lower.equals("0");
    }
}
