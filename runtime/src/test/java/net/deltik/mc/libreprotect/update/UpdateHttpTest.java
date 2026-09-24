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

package net.deltik.mc.libreprotect.update;

import net.deltik.mc.libreprotect.testutil.LocalHttpServer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.concurrent.CountDownLatch;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.*;

/**
 * About ten of these tests wait out a deadline of a second or so, so the
 * tests run at the same time. Each has a client and servers of its own.
 */
@Execution(ExecutionMode.CONCURRENT)
class UpdateHttpTest {

    /**
     * Generous limits, because the tests run at the same time and a busy
     * machine can stall one for a moment. Tests of a limit use a client of
     * their own.
     */
    private final UpdateHttp http = new UpdateHttp(10_000, 10_000, 10_000);

    @Test
    @DisplayName("should return the body of a 200 response as UTF-8")
    void ok() throws IOException {
        try (LocalHttpServer server = new LocalHttpServer(exchange -> LocalHttpServer.respond(exchange, 200, "[\"é\"]"))) {
            assertEquals("[\"é\"]", http.get(server.url("/a"), Map.of()));
        }
    }

    @Test
    @DisplayName("should send only a GET with a User-Agent that names LibreProtect, without a version, server port or key")
    void requestHeaders() throws IOException {
        try (LocalHttpServer server = new LocalHttpServer(exchange -> LocalHttpServer.respond(exchange, 200, "{}"))) {
            http.get(server.url("/a?b=c"), Map.of("Accept", "application/json", "X-Test", "1"));

            LocalHttpServer.Received request = server.getReceived().get(0);
            assertEquals("GET", request.method());
            assertEquals("/a?b=c", request.uri().toString());
            assertEquals("LibreProtect (+https://github.com/Deltik/LibreProtect)", request.header("User-Agent"));
            assertEquals("application/json", request.header("Accept"));
            Set<String> names = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
            names.addAll(request.headers().keySet());
            Set<String> expected = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
            expected.addAll(Set.of("Host", "User-Agent", "Accept", "Connection", "X-Test"));
            assertEquals(expected, names);
        }
    }

    @ParameterizedTest
    @DisplayName("should fail for any status but 200, saying what it was")
    @CsvSource(delimiter = '|', value = {
        "404 | HTTP 404 (not found)",
        "403 | HTTP 403 (forbidden or rate limited)",
        "429 | HTTP 429 (rate limited)",
        "500 | HTTP 500",
        "204 | HTTP 204",
        "300 | HTTP 300",
        "304 | HTTP 304",
        "301 | HTTP 301 without a Location",
        "302 | HTTP 302 without a Location"
    })
    void failsForOtherStatus(int status, String message) throws IOException {
        try (LocalHttpServer server = new LocalHttpServer(
            exchange -> LocalHttpServer.respond(exchange, status, status == 204 || status == 304 ? "" : "{}"))) {
            IOException e = assertThrows(IOException.class, () -> http.get(server.url("/a"), Map.of()));
            assertEquals(message, e.getMessage());
        }
    }

    @Test
    @DisplayName("should accept a body of exactly the limit")
    void atLimit() throws IOException {
        byte[] body = new byte[UpdateHttp.MAX_RESPONSE_BYTES];
        Arrays.fill(body, (byte) 'a');
        try (LocalHttpServer server = new LocalHttpServer(exchange -> LocalHttpServer.respond(exchange, 200, body))) {
            assertEquals(UpdateHttp.MAX_RESPONSE_BYTES, http.get(server.url("/a"), Map.of()).length());
        }
    }

    @Test
    @DisplayName("should refuse a body over the limit that says its length")
    void tooLargeWithLength() throws IOException {
        byte[] body = new byte[UpdateHttp.MAX_RESPONSE_BYTES + 1];
        try (LocalHttpServer server = new LocalHttpServer(exchange -> {
            try {
                LocalHttpServer.respond(exchange, 200, body);
            } catch (IOException e) {
                // The client hung up, as it should
            }
        })) {
            IOException e = assertThrows(IOException.class, () -> http.get(server.url("/a"), Map.of()));
            assertEquals("the response is larger than 1 MiB", e.getMessage());
        }
    }

    @Test
    @DisplayName("should stop reading a streamed body once it passes the limit")
    void tooLargeStreamed() throws IOException {
        try (LocalHttpServer server = new LocalHttpServer(exchange -> {
            exchange.sendResponseHeaders(200, 0);
            byte[] chunk = "[".repeat(64 * 1024).getBytes(StandardCharsets.UTF_8);
            try (OutputStream out = exchange.getResponseBody()) {
                // Far more than the limit, unless the client stops
                for (int i = 0; i < 1024; i++) {
                    out.write(chunk);
                }
            } catch (IOException e) {
                // The client hung up, as it should
            }
        })) {
            IOException e = assertThrows(IOException.class, () -> http.get(server.url("/a"), Map.of()));
            assertEquals("the response is larger than 1 MiB", e.getMessage());
        }
    }

    @Test
    @DisplayName("should time out when the server doesn't answer")
    void readTimeout() throws IOException {
        try (LocalHttpServer server = new LocalHttpServer(exchange -> {
            try {
                Thread.sleep(5_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        })) {
            long start = System.nanoTime();
            assertThrows(SocketTimeoutException.class,
                () -> new UpdateHttp(2_000, 500, 2_000).get(server.url("/a"), Map.of()));
            assertTrue(System.nanoTime() - start < 4_000_000_000L);
        }
    }

    @Test
    @DisplayName("should give up on a response that trickles in for longer than the total time limit")
    void totalTimeout() throws IOException {
        try (LocalHttpServer server = new LocalHttpServer(exchange -> {
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream out = exchange.getResponseBody()) {
                for (int i = 0; i < 100; i++) {
                    out.write('[');
                    out.flush();
                    Thread.sleep(100);
                }
            } catch (IOException | InterruptedException e) {
                // The client hung up, as it should
            }
        })) {
            long start = System.nanoTime();
            IOException e = assertThrows(IOException.class,
                () -> new UpdateHttp(2_000, 1_000, 1_000).get(server.url("/a"), Map.of()));
            assertTrue(e.getMessage().startsWith("the response took longer than"), e.getMessage());
            assertTrue(System.nanoTime() - start < 5_000_000_000L);
        }
    }

    @Test
    @DisplayName("should give up on response headers that trickle in for longer than the total time limit")
    void totalTimeoutInHeaders() throws IOException {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            trickle(server, "HTTP/1.1 200 OK\r\nX-Slow: ".getBytes(StandardCharsets.US_ASCII), 'a');

            long start = System.nanoTime();
            IOException e = assertThrows(IOException.class, () -> new UpdateHttp(2_000, 1_000, 1_000)
                .get(new java.net.URL("http://127.0.0.1:" + server.getLocalPort() + "/"), Map.of()));
            assertEquals("the response took longer than 1 s", e.getMessage());
            assertTrue(System.nanoTime() - start < 5_000_000_000L);
        }
    }

    /**
     * Accept one connection, read the request, send {@code first}, then
     * send {@code next} every 200 ms until the client hangs up
     */
    private static Thread trickle(ServerSocket server, byte[] first, int next) {
        Thread trickle = new Thread(() -> {
            try (Socket socket = server.accept()) {
                socket.getInputStream().read(new byte[16384]);
                OutputStream out = socket.getOutputStream();
                out.write(first);
                out.flush();
                for (int i = 0; i < 1000; i++) {
                    out.write(next);
                    out.flush();
                    Thread.sleep(200);
                }
            } catch (IOException | InterruptedException e) {
                // The client hung up, as it should
            }
        });
        trickle.setDaemon(true);
        trickle.start();
        return trickle;
    }

    /**
     * Closing a connection whose body has a Content-Length can hand it to the
     * JDK, which drains the rest while holding the stream, so the timing
     * varies; hence the repetitions
     */
    @RepeatedTest(5)
    @DisplayName("should give up on a body with a Content-Length that trickles in for longer than the total time limit")
    void totalTimeoutWithContentLength() throws IOException {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            trickle(server, "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nContent-Type: application/json\r\n\r\n["
                .getBytes(StandardCharsets.US_ASCII), ' ');

            long start = System.nanoTime();
            IOException e = assertThrows(IOException.class, () -> new UpdateHttp(2_000, 1_000, 1_000)
                .get(new java.net.URL("http://127.0.0.1:" + server.getLocalPort() + "/"), Map.of()));
            assertEquals("the response took longer than 1 s", e.getMessage());
            assertTrue(System.nanoTime() - start < 5_000_000_000L);
        }
    }

    @Test
    @DisplayName("should give up on a TLS handshake that trickles in for longer than the total time limit")
    void totalTimeoutInTlsHandshake() throws IOException {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            // A handshake record of 16,000 bytes, sent one byte at a time
            trickle(server, new byte[] {0x16, 0x03, 0x03, 0x3e, (byte) 0x80}, 0);

            long start = System.nanoTime();
            IOException e = assertThrows(IOException.class, () -> new UpdateHttp(2_000, 1_000, 1_000)
                .get(new java.net.URL("https://127.0.0.1:" + server.getLocalPort() + "/"), Map.of()));
            assertEquals("the response took longer than 1 s", e.getMessage());
            assertTrue(System.nanoTime() - start < 5_000_000_000L);
        }
    }

    @Test
    @DisplayName("should stop waiting at the total time limit even for a request that can't be stopped")
    void deadlineForStuckRequest() throws IOException {
        CountDownLatch release = new CountDownLatch(1);
        URLStreamHandler stuck = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(java.net.URL url) {
                return new HttpURLConnection(url) {
                    @Override
                    public int getResponseCode() throws IOException {
                        try {
                            release.await();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                        throw new IOException("released");
                    }

                    @Override
                    public void connect() {
                    }

                    @Override
                    public void disconnect() {
                        // Like a connection the JDK is still draining: closing it doesn't end the wait
                    }

                    @Override
                    public boolean usingProxy() {
                        return false;
                    }
                };
            }
        };
        try {
            IOException e = assertTimeoutPreemptively(Duration.ofSeconds(3), () -> assertThrows(IOException.class,
                () -> new UpdateHttp(2_000, 1_000, 500).get(new java.net.URL(null, "http://stuck.invalid/", stuck), Map.of())));

            assertEquals("the response took longer than 500 ms", e.getMessage());
        } finally {
            release.countDown();
        }
    }

    @Nested
    @DisplayName("Redirects")
    class Redirects {

        /**
         * A server that redirects each path in {@code redirects} to its
         * location, with {@code {port}} standing for its own port, and
         * answers any other path with {@code "arrived at <path and query>"}
         */
        private LocalHttpServer server(int status, Map<String, String> redirects) throws IOException {
            return new LocalHttpServer(exchange -> {
                String location = redirects.get(exchange.getRequestURI().getPath());
                if (location == null) {
                    LocalHttpServer.respond(exchange, 200, "arrived at " + exchange.getRequestURI());
                    return;
                }
                exchange.getResponseHeaders().set("Location",
                    location.replace("{port}", String.valueOf(exchange.getLocalAddress().getPort())));
                LocalHttpServer.respond(exchange, status, "");
            });
        }

        /** Something to redirect to that notices any connection, even one that isn't HTTP */
        private ServerSocket listener() throws IOException {
            return new ServerSocket(0, 5, InetAddress.getLoopbackAddress());
        }

        private void assertNotContacted(ServerSocket listener) throws IOException {
            listener.setSoTimeout(300);
            assertThrows(SocketTimeoutException.class, listener::accept, "the redirect's target was contacted");
        }

        @ParameterizedTest
        @DisplayName("should follow a redirect within the API, sending the same request again")
        @ValueSource(ints = {301, 302, 303, 307, 308})
        void followsWithinApi(int status) throws IOException {
            try (LocalHttpServer server = server(status, Map.of("/start", "/moved?x=1"))) {
                assertEquals("arrived at /moved?x=1", http.get(server.url("/start"), Map.of("Accept", "application/json")));

                List<LocalHttpServer.Received> requests = server.getReceived();
                assertEquals(List.of("/start", "/moved?x=1"), requests.stream().map(r -> r.uri().toString()).toList());
                for (LocalHttpServer.Received request : requests) {
                    assertEquals("GET", request.method());
                    assertEquals(UpdateHttp.USER_AGENT, request.header("User-Agent"));
                    assertEquals("application/json", request.header("Accept"));
                }
            }
        }

        @ParameterizedTest
        @DisplayName("should follow an absolute redirect to the same scheme, host and port")
        @ValueSource(strings = {"http://127.0.0.1:{port}/moved", "HTTP://127.0.0.1:{port}/moved", "//127.0.0.1:{port}/moved"})
        void followsAbsolute(String location) throws IOException {
            try (LocalHttpServer server = server(301, Map.of("/start", location))) {
                assertEquals("arrived at /moved", http.get(server.url("/start"), Map.of()));
            }
        }

        @Test
        @DisplayName("should follow up to " + UpdateHttp.MAX_REDIRECTS + " redirects")
        void followsChain() throws IOException {
            try (LocalHttpServer server = server(302, Map.of("/1", "/2", "/2", "/3", "/3", "/done"))) {
                assertEquals("arrived at /done", http.get(server.url("/1"), Map.of()));
            }
        }

        @Test
        @DisplayName("should give up on a redirect loop")
        void loop() throws IOException {
            try (LocalHttpServer server = server(302, Map.of("/loop", "/loop"))) {
                IOException e = assertThrows(IOException.class, () -> http.get(server.url("/loop"), Map.of()));

                assertEquals("HTTP 302 after 3 redirects", e.getMessage());
                assertEquals(UpdateHttp.MAX_REDIRECTS + 1, server.getRequests().size());
            }
        }

        @ParameterizedTest
        @DisplayName("should refuse a redirect to another host, port or scheme without contacting it")
        @ValueSource(strings = {
            "http://localhost:{listener}/elsewhere?tracker=1",
            "//localhost:{listener}/elsewhere",
            "http://127.0.0.2:{listener}/elsewhere",
            "http://127.0.0.1:{listener}/elsewhere",
            "https://127.0.0.1:{listener}/elsewhere",
            "http://user:secret@127.0.0.1:{listener}/elsewhere"
        })
        void refusesElsewhere(String location) throws IOException {
            try (ServerSocket listener = listener();
                 LocalHttpServer server = server(302,
                     Map.of("/start", location.replace("{listener}", String.valueOf(listener.getLocalPort()))))) {
                IOException e = assertThrows(IOException.class, () -> http.get(server.url("/start"), Map.of()));

                assertTrue(e.getMessage().startsWith("HTTP 302 to somewhere other than the API: "), e.getMessage());
                assertNotContacted(listener);
                assertEquals(1, server.getRequests().size());
            }
        }

        @Test
        @DisplayName("should refuse a redirect to the API with user info")
        void refusesUserInfo() throws IOException {
            try (LocalHttpServer server = server(302, Map.of("/start", "http://user:secret@127.0.0.1:{port}/moved"))) {
                assertThrows(IOException.class, () -> http.get(server.url("/start"), Map.of()));
                assertEquals(1, server.getRequests().size());
            }
        }

        @Test
        @DisplayName("should keep to the total time limit across redirects")
        void deadlineSpansRedirects() throws IOException {
            try (LocalHttpServer server = new LocalHttpServer(exchange -> {
                try {
                    Thread.sleep(400);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                exchange.getResponseHeaders().set("Location", "/again");
                LocalHttpServer.respond(exchange, 307, "");
            })) {
                IOException e = assertThrows(IOException.class,
                    () -> new UpdateHttp(2_000, 2_000, 1_000).get(server.url("/start"), Map.of()));

                assertEquals("the response took longer than 1 s", e.getMessage());
            }
        }

        @ParameterizedTest
        @DisplayName("should count only the same scheme, host and port, without user info, as the API")
        @CsvSource({
            "https://api.github.com/repos/a/b, https://api.github.com/repositories/1, true",
            "https://api.github.com/, HTTPS://API.GitHub.com:443/x, true",
            "http://127.0.0.1:8080/v2, http://127.0.0.1:8080/other, true",
            "https://api.github.com/, http://api.github.com/, false",
            "http://api.github.com/, https://api.github.com/, false",
            "https://api.github.com/, https://api.github.com:8443/, false",
            "https://api.github.com/, https://github.com/, false",
            "https://api.github.com/, https://api.github.com.evil.example/, false",
            "https://api.github.com/, https://user@api.github.com/, false",
            "http://127.0.0.1:8080/, http://localhost:8080/, false",
            "https://api.github.com/, https://ap\u0131.github.com/, false",
            "https://api.modrinth.com/, https://api.modrinth.\u212Aom/, false",
            "http://localhost:8080/, http://localho\u017Ft:8080/, false"
        })
        void sameOrigin(String origin, String to, boolean expected) throws IOException {
            assertEquals(expected, UpdateHttp.sameOrigin(new java.net.URL(origin), new java.net.URL(to)));
        }
    }

    @Test
    @DisplayName("should fail when nothing listens")
    void connectionRefused() throws IOException {
        int port;
        try (LocalHttpServer server = new LocalHttpServer()) {
            port = server.getPort();
        }
        assertThrows(IOException.class,
            () -> http.get(new java.net.URL("http://127.0.0.1:" + port + "/"), Map.of()));
    }
}
