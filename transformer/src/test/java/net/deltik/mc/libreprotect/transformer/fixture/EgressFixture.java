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

package net.deltik.mc.libreprotect.transformer.fixture;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.Callable;
import java.util.function.Function;

/**
 * Compiled by javac so the tests exercise real call-site shapes, not
 * hand-written bytecode. Every method except {@link #notEgress} opens a
 * connection in a different way.
 */
public class EgressFixture {

    public interface UrlOpener {
        URLConnection open(URL url) throws IOException;
    }

    public static URLConnection direct(URL url) throws IOException {
        return url.openConnection();
    }

    public static URLConnection withProxy(URL url) throws IOException {
        return url.openConnection(Proxy.NO_PROXY);
    }

    public static InputStream stream(URL url) throws IOException {
        return url.openStream();
    }

    public static Object content(URL url) throws IOException {
        return url.getContent();
    }

    public static Object typedContent(URL url) throws IOException {
        return url.getContent(new Class<?>[] {InputStream.class});
    }

    /** Bound method reference: invokedynamic with a captured receiver */
    public static Callable<InputStream> boundReference(URL url) {
        return url::openStream;
    }

    /** Unbound method reference: invokedynamic whose handle takes the receiver as an argument */
    public static UrlOpener unboundReference() {
        return URL::openConnection;
    }

    /** Lambda: javac puts the call in a synthetic method */
    public static Function<URL, URLConnection> lambda() {
        return url -> {
            try {
                return url.openConnection();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        };
    }

    public static String notEgress(URL url) {
        return url.getHost();
    }
}
