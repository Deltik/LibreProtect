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

import java.io.ByteArrayInputStream;
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
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * An HTTP server bound to 127.0.0.1 on an ephemeral port, so tests can make
 * real connections without touching the network.
 *
 * <p>By default, every request gets a 200 response whose body tells how the
 * request arrived: {@code "proxied <uri>"} when the request line carries an
 * absolute URI, which is what a client sends to an HTTP proxy, or
 * {@code "direct <path>"} otherwise. Tests can therefore point a connection at
 * this server either as the destination or as a {@link Proxy}. A test can
 * give its own {@link Handler} instead.
 */
public final class LocalHttpServer implements AutoCloseable {

    /** Answers one request */
    @FunctionalInterface
    public interface Handler {
        void handle(HttpExchange exchange) throws IOException;
    }

    /** A request as the server received it */
    public static final class Received {

        private final String method;
        private final URI uri;
        private final Map<String, List<String>> headers;
        private final byte[] body;

        private Received(String method, URI uri, Map<String, List<String>> headers, byte[] body) {
            this.method = method;
            this.uri = uri;
            this.headers = headers;
            this.body = body;
        }

        public String method() {
            return method;
        }

        public URI uri() {
            return uri;
        }

        /**
         * @return the request headers, with case-insensitive names
         */
        public Map<String, List<String>> headers() {
            return headers;
        }

        /**
         * @return the first value of the named header, or {@code null}
         */
        public String header(String name) {
            List<String> values = headers.get(name);
            return values == null || values.isEmpty() ? null : values.get(0);
        }

        /**
         * @return a copy of the request body, empty if there was none
         */
        public byte[] body() {
            return body.clone();
        }
    }

    private final HttpServer server;
    private final ExecutorService executor = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "LocalHttpServer");
        thread.setDaemon(true);
        return thread;
    });
    private final List<Received> received = new CopyOnWriteArrayList<>();

    public LocalHttpServer() throws IOException {
        this(LocalHttpServer::describe);
    }

    /**
     * @param handler answers every request; exceptions it throws close the
     *                connection without a response
     */
    public LocalHttpServer(Handler handler) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            exchange.getRequestHeaders().forEach((name, values) -> headers.put(name, List.copyOf(values)));
            byte[] body;
            try (InputStream in = exchange.getRequestBody()) {
                body = in.readAllBytes();
            }
            // The handler can read the body too
            exchange.setStreams(new ByteArrayInputStream(body), null);
            received.add(new Received(exchange.getRequestMethod(), exchange.getRequestURI(), headers, body));
            try (exchange) {
                handler.handle(exchange);
            }
        });
        server.setExecutor(executor);
        server.start();
    }

    private static void describe(HttpExchange exchange) throws IOException {
        URI uri = exchange.getRequestURI();
        respond(exchange, 200, ((uri.isAbsolute() ? "proxied " : "direct ") + uri).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Send a complete response with a known length.
     */
    public static void respond(HttpExchange exchange, int status, byte[] body) throws IOException {
        exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(body);
        }
    }

    public static void respond(HttpExchange exchange, int status, String body) throws IOException {
        respond(exchange, status, body.getBytes(StandardCharsets.UTF_8));
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
        return received.stream().map(Received::uri).toList();
    }

    /**
     * @return the requests received so far, in order
     */
    public List<Received> getReceived() {
        return List.copyOf(received);
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
        executor.shutdownNow();
    }
}
