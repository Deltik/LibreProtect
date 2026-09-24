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
import net.deltik.mc.libreprotect.PrivacyConfig;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.PatternSyntaxException;

/**
 * Parses route configuration from YAML.
 */
public class RouteConfigParser {

    /**
     * Parse a list of route configurations from YAML.
     *
     * Expected format:
     * <pre>
     * - pattern: "http://example\\.com/.*"
     *   action: REDIRECT
     *   target: "https://mirror.example/path"
     * </pre>
     *
     * @param routeConfigs List of route config maps from YAML
     * @return List of parsed Route objects
     */
    public List<Route> parseRoutes(List<?> routeConfigs) {
        List<Route> routes = new ArrayList<>();

        if (routeConfigs == null) {
            return routes;
        }

        for (int i = 0; i < routeConfigs.size(); i++) {
            Object item = routeConfigs.get(i);
            if (!(item instanceof Map)) {
                skip(i + 1, "it isn't a map of pattern, action and target");
                continue;
            }

            Map<?, ?> config = (Map<?, ?>) item;
            Route route = parseRoute(config, i + 1);
            if (route != null) {
                routes.add(route);
            }
        }

        return routes;
    }

    /**
     * Parse a single route configuration
     */
    private Route parseRoute(Map<?, ?> config, int index) {
        // Get pattern (required)
        Object patternObj = config.get("pattern");
        if (patternObj == null) {
            skip(index, "it has no 'pattern'");
            return null;
        }
        String pattern = patternObj.toString();

        // Get action (required)
        Object actionObj = config.get("action");
        if (actionObj == null) {
            skip(index, "it has no 'action'");
            return null;
        }
        String actionStr = actionObj.toString().toUpperCase(Locale.ROOT);

        RouteActionType actionType;
        try {
            actionType = RouteActionType.valueOf(actionStr);
        } catch (IllegalArgumentException e) {
            skip(index, "its action '" + actionStr + "' isn't BLOCK, ANSWER, REDIRECT or PASSTHROUGH");
            return null;
        }

        // Get target (required for REDIRECT)
        Object targetObj = config.get("target");
        String target = targetObj != null ? targetObj.toString() : null;

        if (actionType == RouteActionType.REDIRECT && (target == null || target.isEmpty())) {
            skip(index, "its action is REDIRECT, but it has no 'target'");
            return null;
        }

        // Validate regex pattern
        try {
            return new Route(pattern, actionType, target);
        } catch (PatternSyntaxException e) {
            skip(index, "invalid regex pattern: " + e.getMessage());
            return null;
        }
    }

    /**
     * Build a complete RouteRegistry from configuration.
     * Custom routes are checked first, then preset routes, then default action.
     *
     * @param preset The preset to use for defaults
     * @param customRoutes Custom routes from config
     * @return Configured RouteRegistry
     */
    public RouteRegistry buildRegistry(RoutePreset preset, List<Route> customRoutes) {
        RouteRegistry.Builder builder = RouteRegistry.builder();

        // Add custom routes first (highest priority)
        if (customRoutes != null) {
            builder.addRoutes(customRoutes);
        }

        // Add preset routes
        builder.addRoutes(preset.getRoutes());

        // Set default action from preset
        builder.setDefaultAction(preset.getDefaultAction());

        return builder.build();
    }

    private static void skip(int index, String reason) {
        LibreProtectLogger.warning("Skipping route #" + index + " in " + PrivacyConfig.FILE_NAME + ": " + reason);
    }
}
