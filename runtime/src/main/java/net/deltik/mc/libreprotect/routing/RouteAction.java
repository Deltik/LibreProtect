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

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;

/**
 * Strategy interface for handling URL route actions.
 * Each implementation defines how to handle a matched URL.
 */
public interface RouteAction {

    /**
     * Get the action type this handler implements
     *
     * @return The action type
     */
    RouteActionType getType();

    /**
     * Create a URLConnection for the given route match.
     *
     * @param url The URL that was intercepted
     * @param proxy The proxy the caller asked for, or {@code null} if none
     * @param match The route match result containing the route and captures
     * @return A URLConnection to handle the request
     * @throws IOException If the request is blocked or connection creation fails
     */
    URLConnection createConnection(URL url, Proxy proxy, RouteRegistry.RouteMatch match) throws IOException;
}
