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
import java.util.Map;

/**
 * Registry that holds routes and performs URL matching.
 * Routes are checked in order - first match wins.
 */
public class RouteRegistry {
    private final List<Route> routes;
    private final RouteActionType defaultAction;

    /**
     * Create a registry with the given routes and default action.
     *
     * @param routes Routes to check (in priority order)
     * @param defaultAction Action to use when no route matches
     */
    public RouteRegistry(List<Route> routes, RouteActionType defaultAction) {
        this.routes = new ArrayList<>(routes);
        this.defaultAction = defaultAction;
    }

    /**
     * Result of a route match
     */
    public static class RouteMatch {
        private final Route route;
        private final Map<String, String> captures;
        private final boolean isDefault;

        private RouteMatch(Route route, Map<String, String> captures, boolean isDefault) {
            this.route = route;
            this.captures = captures;
            this.isDefault = isDefault;
        }

        public Route getRoute() {
            return route;
        }

        public Map<String, String> getCaptures() {
            return captures;
        }

        /**
         * @return true if this match is from the default action (no route matched)
         */
        public boolean isDefault() {
            return isDefault;
        }

        public RouteActionType getActionType() {
            return route.getActionType();
        }

        public static RouteMatch of(Route route, Map<String, String> captures) {
            return new RouteMatch(route, captures, false);
        }

        public static RouteMatch defaultMatch(RouteActionType defaultAction) {
            Route defaultRoute = new Route(".*", defaultAction);
            return new RouteMatch(defaultRoute, Collections.emptyMap(), true);
        }
    }

    /**
     * Find the first matching route for a URL.
     *
     * @param url The URL to match
     * @return RouteMatch containing the matched route and any captures
     */
    public RouteMatch match(String url) {
        for (Route route : routes) {
            UrlPatternMatcher.MatchResult result = UrlPatternMatcher.match(
                route.getCompiledPattern(), url);

            if (result.isMatched()) {
                return RouteMatch.of(route, result.getCaptures());
            }
        }

        // No route matched, return default action
        return RouteMatch.defaultMatch(defaultAction);
    }

    /**
     * Get the default action for unmatched URLs
     */
    public RouteActionType getDefaultAction() {
        return defaultAction;
    }

    /**
     * Get an unmodifiable view of the routes
     */
    public List<Route> getRoutes() {
        return Collections.unmodifiableList(routes);
    }

    /**
     * Get the number of routes in this registry
     */
    public int size() {
        return routes.size();
    }

    /**
     * Builder for creating RouteRegistry instances
     */
    public static class Builder {
        private final List<Route> routes = new ArrayList<>();
        private RouteActionType defaultAction = RouteActionType.BLOCK;

        public Builder addRoute(Route route) {
            routes.add(route);
            return this;
        }

        public Builder addRoute(String pattern, RouteActionType action) {
            routes.add(new Route(pattern, action));
            return this;
        }

        public Builder addRoute(String pattern, RouteActionType action, String target) {
            routes.add(new Route(pattern, action, target));
            return this;
        }

        public Builder addRoutes(List<Route> routes) {
            this.routes.addAll(routes);
            return this;
        }

        public Builder setDefaultAction(RouteActionType defaultAction) {
            this.defaultAction = defaultAction;
            return this;
        }

        public RouteRegistry build() {
            return new RouteRegistry(routes, defaultAction);
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
