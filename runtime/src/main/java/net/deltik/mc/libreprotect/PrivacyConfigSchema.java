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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

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
        "allow-updates - Like privacy-first, but LibreProtect also answers update checks",
        "passthrough - Allow every request through unchanged (for debugging)"
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
        ROUTES,
        VERBOSE_LOGGING
    };

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

            yaml.append(option.key).append(": ");
            if (option.type == ConfigType.STRING) {
                yaml.append(option.defaultValue);
            } else if (option.type == ConfigType.LIST) {
                yaml.append("[]");
            } else {
                yaml.append(option.defaultValue.toString().toLowerCase(Locale.ROOT));
            }
            yaml.append("\n");
        }

        return yaml.toString();
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
