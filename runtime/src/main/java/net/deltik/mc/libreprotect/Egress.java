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

import net.deltik.mc.libreprotect.routing.RouteResolver;

import java.io.IOException;
import java.io.InputStream;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;

/**
 * Gate for every network request that CoreProtect makes through {@link URL}.
 *
 * <p>When LibreProtect is built, the transformer rewrites each call to
 * {@code java.net.URL#openConnection()}, {@code openConnection(Proxy)},
 * {@code openStream()} and {@code getContent(..)} in CoreProtect's bytecode,
 * including bundled libraries such as bStats, into a call to the static method
 * of the same name here. The receiver becomes the first parameter. The
 * transformer depends on these names and descriptors, so don't rename them.
 *
 * <p>Requests are routed by the installed {@link RouteResolver}. Until
 * {@link Bootstrap} installs one, every request is blocked.
 */
public final class Egress {

    private static volatile RouteResolver resolver;

    private Egress() {
    }

    /**
     * Install the resolver that decides what happens to each request.
     */
    public static void install(RouteResolver routeResolver) {
        resolver = routeResolver;
    }

    /**
     * Remove the installed resolver so that all requests are blocked again.
     */
    public static void uninstall() {
        resolver = null;
    }

    /**
     * @return the installed resolver, or {@code null} if requests are being blocked
     */
    public static RouteResolver getResolver() {
        return resolver;
    }

    public static URLConnection openConnection(URL url) throws IOException {
        return route(url, null);
    }

    public static URLConnection openConnection(URL url, Proxy proxy) throws IOException {
        if (proxy == null) {
            // Same contract as URL#openConnection(Proxy)
            throw new IllegalArgumentException("proxy can not be null");
        }
        return route(url, proxy);
    }

    public static InputStream openStream(URL url) throws IOException {
        return openConnection(url).getInputStream();
    }

    public static Object getContent(URL url) throws IOException {
        return openConnection(url).getContent();
    }

    public static Object getContent(URL url, Class<?>[] classes) throws IOException {
        return openConnection(url).getContent(classes);
    }

    private static URLConnection route(URL url, Proxy proxy) throws IOException {
        RouteResolver current = resolver;
        if (current == null) {
            EgressBlockedException blocked = new EgressBlockedException(url, "network policy not loaded");
            LibreProtectLogger.debug(blocked.getMessage());
            throw blocked;
        }
        return current.resolve(url, proxy);
    }
}
