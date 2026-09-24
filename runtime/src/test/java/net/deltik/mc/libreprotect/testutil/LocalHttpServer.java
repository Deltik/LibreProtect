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

package net.deltik.mc.libreprotect.testutil;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * An HTTP server bound to 127.0.0.1 on an ephemeral port, so tests can make
 * real connections without touching the network.
 *
 * <p>Every request gets a 200 response whose body tells how the request
 * arrived: {@code "proxied <uri>"} when the request line carries an absolute
 * URI, which is what a client sends to an HTTP proxy, or
 * {@code "direct <path>"} otherwise. Tests can therefore point a connection at
 * this server either as the destination or as a {@link Proxy}.
 */
public final class LocalHttpServer implements AutoCloseable {

    private final HttpServer server;
    private final List<URI> requests = new CopyOnWriteArrayList<>();

    public LocalHttpServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    private void handle(HttpExchange exchange) throws IOException {
        URI uri = exchange.getRequestURI();
        requests.add(uri);
        byte[] body = ((uri.isAbsolute() ? "proxied " : "direct ") + uri).getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(body);
        }
    }

    public int getPort() {
        return server.getAddress().getPort();
    }

    /**
     * @return {@code http://127.0.0.1:<port>}
     */
    public String getBaseUrl() {
        return "http://127.0.0.1:" + getPort();
    }

    /**
     * @return a URL on this server for the given absolute path
     */
    public URL url(String path) {
        return MockUrlFactory.createUrl(getBaseUrl() + path);
    }

    /**
     * @return a proxy that sends requests through this server
     */
    public Proxy asProxy() {
        return new Proxy(Proxy.Type.HTTP, server.getAddress());
    }

    /**
     * @return the request URIs received so far, in order
     */
    public List<URI> getRequests() {
        return List.copyOf(requests);
    }

    /**
     * Read the whole response body of a connection as UTF-8.
     */
    public static String read(URLConnection connection) throws IOException {
        try (InputStream is = connection.getInputStream()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
