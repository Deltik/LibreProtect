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

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.util.Objects;

/**
 * Main orchestrator for URL routing decisions.
 * Coordinates between RouteRegistry and RouteActionFactory to resolve URLs.
 */
public class RouteResolver {
    private final RouteRegistry registry;
    private final RouteActionFactory actions;

    /**
     * Create a resolver with the given registry and the default actions
     * ({@link RouteActionFactory#defaults()})
     *
     * @param registry The route registry to use for matching
     */
    public RouteResolver(RouteRegistry registry) {
        this(registry, RouteActionFactory.defaults());
    }

    /**
     * Create a resolver with the given registry and actions
     *
     * @param registry The route registry to use for matching
     * @param actions  The actions that matched routes run
     */
    public RouteResolver(RouteRegistry registry, RouteActionFactory actions) {
        this.registry = registry;
        this.actions = Objects.requireNonNull(actions, "actions");
    }

    /**
     * Resolve a URL to a URLConnection based on configured routes.
     *
     * @param url The URL to resolve
     * @param proxy The proxy the caller asked for, or {@code null} if none
     * @return A URLConnection for handling the request
     * @throws IOException If the request is blocked or connection creation fails
     */
    public URLConnection resolve(URL url, Proxy proxy) throws IOException {
        String target = UrlNormalizer.normalize(url);
        RouteRegistry.RouteMatch match = registry.match(target);

        if (match.isDefault()) {
            LibreProtectLogger.debug("URL '" + target + "' using default action: " + match.getActionType());
        } else {
            LibreProtectLogger.debug("URL '" + target + "' matched route: " + match.getRoute().getPatternString());
        }

        RouteAction action = actions.getAction(match.getActionType());
        return action.createConnection(url, proxy, match);
    }

    /**
     * Resolve a URL without a proxy.
     *
     * @see #resolve(URL, Proxy)
     */
    public URLConnection resolve(URL url) throws IOException {
        return resolve(url, null);
    }

    /**
     * Get the underlying registry
     */
    public RouteRegistry getRegistry() {
        return registry;
    }
}
