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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Built-in presets: what happens to each of CoreProtect's known endpoints,
 * and to every other request that no custom route matches.
 *
 * <p>Only passthrough sends anything to CoreProtect's servers. The other
 * presets let LibreProtect answer what it can answer itself (see
 * {@link RouteActionType#ANSWER}) and block the rest. A blocked request fails
 * the way it would offline, so CoreProtect carries on without it. The license
 * endpoint is never answered (see
 * {@link net.deltik.mc.libreprotect.routing.answer.AnswerRegistry}).
 */
public enum RoutePreset {
    /**
     * Privacy-first: answer translation requests, block everything else. No
     * request leaves the server.
     */
    PRIVACY_FIRST("privacy-first", RouteActionType.BLOCK),

    /**
     * Allow updates: like privacy-first, but answer update checks too
     */
    ALLOW_UPDATES("allow-updates", RouteActionType.BLOCK),

    /**
     * Passthrough: Allow all requests through unchanged, with translation
     * replies layered over the bundled translations
     */
    PASSTHROUGH("passthrough", RouteActionType.PASSTHROUGH);

    private final String configName;
    private final RouteActionType defaultAction;
    private final List<Route> routes;

    RoutePreset(String configName, RouteActionType defaultAction) {
        this.configName = configName;
        this.defaultAction = defaultAction;
        this.routes = buildRoutes();
    }

    // Known endpoints, matched against UrlNormalizer output (lowercase scheme and host)
    static final String STATS = "https?://stats\\.coreprotect\\.net/.*";
    static final String LICENSE = "https?://coreprotect\\.net/license/.*";
    static final String TRANSLATE = "https?://coreprotect\\.net/translate/?";
    static final String UPDATE = "https?://update\\.coreprotect\\.net/.*";
    static final String ERROR_REPORTING = "https?://error-reporting\\.coreprotect\\.net/.*";
    static final String BSTATS = "https?://bstats\\.org/.*";

    private List<Route> buildRoutes() {
        List<Route> routes = new ArrayList<>();

        switch (this.name()) {
            case "PRIVACY_FIRST":
                routes.add(new Route(STATS, RouteActionType.BLOCK));
                routes.add(new Route(LICENSE, RouteActionType.BLOCK));
                routes.add(new Route(TRANSLATE, RouteActionType.ANSWER));
                routes.add(new Route(UPDATE, RouteActionType.BLOCK));
                routes.add(new Route(ERROR_REPORTING, RouteActionType.BLOCK));
                routes.add(new Route(BSTATS, RouteActionType.BLOCK));
                break;

            case "ALLOW_UPDATES":
                routes.add(new Route(STATS, RouteActionType.BLOCK));
                routes.add(new Route(LICENSE, RouteActionType.BLOCK));
                routes.add(new Route(TRANSLATE, RouteActionType.ANSWER));
                routes.add(new Route(UPDATE, RouteActionType.ANSWER));
                routes.add(new Route(ERROR_REPORTING, RouteActionType.BLOCK));
                routes.add(new Route(BSTATS, RouteActionType.BLOCK));
                break;

            case "PASSTHROUGH":
                // No routes - everything passes through via default action
                break;
        }

        return routes;
    }

    /**
     * Get the config file name for this preset
     */
    public String getConfigName() {
        return configName;
    }

    /**
     * Get the default action for URLs not matching any route
     */
    public RouteActionType getDefaultAction() {
        return defaultAction;
    }

    /**
     * Get the routes defined by this preset
     */
    public List<Route> getRoutes() {
        return Collections.unmodifiableList(routes);
    }

    /**
     * Parse a preset from its config name
     *
     * @param name The config name (e.g., "privacy-first")
     * @return The preset, or PRIVACY_FIRST if not found
     */
    public static RoutePreset fromConfigName(String name) {
        if (name == null) {
            return PRIVACY_FIRST;
        }

        String normalized = name.toLowerCase(Locale.ROOT).trim();
        for (RoutePreset preset : values()) {
            if (preset.configName.equals(normalized)) {
                return preset;
            }
        }

        // Default to privacy-first for unknown presets
        return PRIVACY_FIRST;
    }

    /**
     * Get all available preset names for documentation
     */
    public static String[] getAvailablePresets() {
        RoutePreset[] presets = values();
        String[] names = new String[presets.length];
        for (int i = 0; i < presets.length; i++) {
            names[i] = presets[i].configName;
        }
        return names;
    }
}
