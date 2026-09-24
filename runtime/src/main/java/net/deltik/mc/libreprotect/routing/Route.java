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

import java.util.regex.Pattern;

/**
 * Immutable route definition containing a URL pattern and action.
 */
public final class Route {
    private final String patternString;
    private final Pattern compiledPattern;
    private final RouteActionType actionType;
    private final String target;  // For REDIRECT action

    /**
     * Create a route with an action (no redirect target)
     */
    public Route(String pattern, RouteActionType actionType) {
        this(pattern, actionType, null);
    }

    /**
     * Create a route with an action and optional redirect target
     */
    public Route(String pattern, RouteActionType actionType, String target) {
        this.patternString = pattern;
        // Use UrlPatternMatcher to support Python-style named groups
        this.compiledPattern = UrlPatternMatcher.compile(pattern);
        this.actionType = actionType;
        this.target = target;
    }

    /**
     * Get the original pattern string
     */
    public String getPatternString() {
        return patternString;
    }

    /**
     * Get the compiled regex pattern
     */
    public Pattern getCompiledPattern() {
        return compiledPattern;
    }

    /**
     * Get the action type for this route
     */
    public RouteActionType getActionType() {
        return actionType;
    }

    /**
     * Get the redirect target URL (may contain ${name} placeholders)
     * @return target URL or null if not a redirect
     */
    public String getTarget() {
        return target;
    }

    /**
     * Check if this is a redirect route
     */
    public boolean isRedirect() {
        return actionType == RouteActionType.REDIRECT;
    }

    @Override
    public String toString() {
        if (isRedirect()) {
            return String.format("Route{pattern='%s', action=%s, target='%s'}",
                patternString, actionType, target);
        }
        return String.format("Route{pattern='%s', action=%s}", patternString, actionType);
    }
}
