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

/*
 * Portions of this file are copied or adapted from CoreProtect
 * <https://github.com/PlayPro/CoreProtect>:
 *
 * Copyright (c) Intelli and the CoreProtect contributors
 *
 * CoreProtect is licensed under the Artistic License 2.0 (see
 * LICENSES/Artistic-2.0.txt). As section 4(c)(ii) of that license
 * permits, LibreProtect distributes these portions under the
 * GNU General Public License, version 3 or later. See NOTICE.
 */

package net.deltik.mc.libreprotect.routing.answer;

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.routing.Route;
import net.deltik.mc.libreprotect.routing.RouteActionType;
import net.deltik.mc.libreprotect.routing.RouteRegistry;
import net.deltik.mc.libreprotect.routing.action.PassthroughAction;
import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import net.deltik.mc.libreprotect.testutil.LocalHttpServer;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LayeredTranslationAnswerTest {

    private static final Map<String, String> HEADERS = Map.of(
        "Accept-Charset", "UTF-8",
        "Content-Type", "application/x-www-form-urlencoded; charset=utf-8",
        "User-Agent", "CoreProtect");

    private final TranslationAnswer bundled = new TranslationAnswer(TranslationAnswerTest.bundle());
    /** CoreProtect's translation service, which gives every request the reply that {@link #reply} sets */
    private LocalHttpServer service;
    private volatile int status = 200;
    private volatile String reply = "";
    private TestLogger logger;

    @BeforeEach
    void setUp() throws IOException {
        service = new LocalHttpServer(exchange -> LocalHttpServer.respond(exchange, status, reply));
        logger = new TestLogger();
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(logger);
    }

    @AfterEach
    void tearDown() {
        service.close();
        LibreProtectLogger.reset();
    }

    /**
     * Give every later request to the service this reply.
     */
    private void reply(int status, String body) {
        this.status = status;
        this.reply = body;
    }

    private static Request request(URL url, String language) {
        return new Request(url, "POST", HEADERS, TranslationAnswerTest.body(TranslationAnswerTest.builtInPhrases(language)));
    }

    private Map<String, String> ask(String language) throws IOException {
        Response response = new LayeredTranslationAnswer(bundled, null)
            .answer(request(service.url("/translate/"), language));
        assertEquals(200, response.status());
        return TranslationAnswerTest.answer(response);
    }

    @Nested
    @DisplayName("When the service answers")
    class ServiceAnswers {

        @Test
        @DisplayName("should layer its translations over the bundled ones")
        void layers() throws IOException {
            // The bundle has no German STATUS_AUTO_PURGE
            reply(200, "{\"HELP_HEADER\":\"{0} Hilfe (Dienst)\",\"STATUS_AUTO_PURGE\":\"Auto-Bereinigung: {0}\"}\n");

            Map<String, String> expected = new TreeMap<>(TranslationAnswerTest.GERMAN_ANSWER);
            expected.put("HELP_HEADER", "{0} Hilfe (Dienst)");
            expected.put("STATUS_AUTO_PURGE", "Auto-Bereinigung: {0}");
            assertEquals(expected, ask("de"));
        }

        @Test
        @DisplayName("should leave out its translations of phrases customized in language.yml, which CoreProtect "
            + "would show at once")
        void customized() throws IOException {
            Map<String, String> phrases = TranslationAnswerTest.builtInPhrases("de");
            phrases.put("HELP_STATUS_COMMAND", "Shows whether our logger is alive.");
            phrases.put("STATUS_AUTO_PURGE", "Purging: {0}");
            reply(200, "{\"HELP_STATUS_COMMAND\":\"Zeigt, ob unser Logger lebt.\","
                + "\"STATUS_AUTO_PURGE\":\"Bereinigung: {0}\",\"HELP_HEADER\":\"{0} Hilfe (Dienst)\","
                + "\"WORLD_NOT_FOUND\":\"Welt nicht gefunden\"}");

            Response response = new LayeredTranslationAnswer(bundled, null).answer(new Request(service.url("/translate/"),
                "POST", HEADERS, TranslationAnswerTest.body(phrases)));

            Map<String, String> expected = new TreeMap<>(TranslationAnswerTest.GERMAN_ANSWER);
            expected.remove("HELP_STATUS_COMMAND");
            expected.put("HELP_HEADER", "{0} Hilfe (Dienst)");
            assertEquals(expected, TranslationAnswerTest.answer(response),
                "no customized phrase, nor WORLD_NOT_FOUND, which this CoreProtect doesn't have");
        }

        @Test
        @DisplayName("should pass its translations on as they are when it can't tell customized phrases")
        void noBuiltInEnglish() throws IOException {
            reply(200, "{\"HELP_HEADER\":\"{0} Hilfe (Dienst)\"}");
            TranslationAnswer withoutBuiltIn = new TranslationAnswer(TranslationBundleTest.bundle(
                Map.of("de.yml", TranslationAnswerTest.GERMAN), new ArrayList<>()));

            Response response = new LayeredTranslationAnswer(withoutBuiltIn, null)
                .answer(request(service.url("/translate/"), "de"));

            assertEquals(Map.of("HELP_HEADER", "{0} Hilfe (Dienst)"), TranslationAnswerTest.answer(response));
        }

        @Test
        @DisplayName("should keep bundled translations that the service leaves blank or gives as anything but text")
        void ignoresBlankAndNonText() throws IOException {
            reply(200, "{\"HELP_HEADER\":\"  \",\"COMMAND_NOT_FOUND\":null,\"UNICODE\":{\"x\":\"y\"},"
                + "\"HELP_ACTION_2\":7,\"EMPTY\":\"\"}");

            assertEquals(new TreeMap<>(TranslationAnswerTest.GERMAN_ANSWER), ask("de"));
        }

        @Test
        @DisplayName("should send the service exactly the request that CoreProtect made")
        void forwardsRequest() throws IOException {
            reply(200, "{}");
            Request request = request(service.url("/translate/"), "de");

            new LayeredTranslationAnswer(bundled, null).answer(request);

            assertEquals(1, service.getReceived().size());
            LocalHttpServer.Received received = service.getReceived().get(0);
            assertEquals("POST", received.method());
            assertEquals("/translate/", received.uri().toString());
            assertArrayEquals(request.body(), received.body());
            HEADERS.forEach((name, value) -> assertEquals(value, received.header(name), name));
        }

        @Test
        @DisplayName("should use the proxy that CoreProtect asked for")
        void proxy() throws IOException {
            reply(200, "{}");

            new LayeredTranslationAnswer(bundled, service.asProxy()).answer(request(service.url("/translate/"), "de"));

            assertEquals(service.url("/translate/").toString(), service.getReceived().get(0).uri().toString());
        }

        @Test
        @DisplayName("should answer with the service alone for a language that isn't bundled")
        void notBundled() throws IOException {
            reply(200, "{\"HELP_HEADER\":\"{0} Hulp\"}");

            assertEquals(Map.of("HELP_HEADER", "{0} Hulp"), ask("nl"));
            assertFalse(logger.hasLevel(Level.WARNING), "allowing the service is what the warning suggests");
        }

        @Test
        @DisplayName("should pass on a request that it can't read, and answer with the service alone")
        void garbledRequest() throws IOException {
            reply(200, "{\"HELP_HEADER\":\"{0} Hilfe\"}");
            byte[] body = "not a translation request".getBytes(StandardCharsets.UTF_8);

            Response response = new LayeredTranslationAnswer(bundled, null)
                .answer(new Request(service.url("/translate/"), "POST", HEADERS, body));

            assertEquals(Map.of("HELP_HEADER", "{0} Hilfe"), TranslationAnswerTest.answer(response));
            assertArrayEquals(body, service.getReceived().get(0).body());
        }
    }

    static Stream<Arguments> failures() {
        return Stream.of(
            Arguments.of("server error", 500, "{\"HELP_HEADER\":\"x\"}"),
            Arguments.of("not found", 404, ""),
            Arguments.of("redirect", 302, ""),
            Arguments.of("no content", 204, ""),
            Arguments.of("empty reply", 200, ""),
            Arguments.of("not JSON", 200, "<html>Service unavailable</html>"),
            Arguments.of("a JSON array", 200, "[\"HELP_HEADER\",\"x\"]"),
            Arguments.of("more after the object", 200, "{\"HELP_HEADER\":\"x\"} {}"),
            Arguments.of("an unfinished object", 200, "{\"HELP_HEADER\":\"x\""),
            Arguments.of("a reply that is too large", 200,
                "{\"HELP_HEADER\":\"" + "x".repeat(LayeredTranslationAnswer.MAX_REPLY_BYTES) + "\"}"));
    }

    @Nested
    @DisplayName("When the service fails")
    class ServiceFails {

        @ParameterizedTest(name = "{0}")
        @MethodSource("net.deltik.mc.libreprotect.routing.answer.LayeredTranslationAnswerTest#failures")
        @DisplayName("should answer with the bundled translation alone")
        void bundledAlone(String description, int status, String reply) throws IOException {
            reply(status, reply);

            assertEquals(new TreeMap<>(TranslationAnswerTest.GERMAN_ANSWER), ask("de"));
        }

        @Test
        @DisplayName("should answer with the bundled translation alone when the service is unreachable")
        void unreachable() throws IOException {
            URL closed = service.url("/translate/");
            service.close();

            Response response = new LayeredTranslationAnswer(bundled, null).answer(request(closed, "de"));

            assertEquals(new TreeMap<>(TranslationAnswerTest.GERMAN_ANSWER), TranslationAnswerTest.answer(response));
        }

        @Test
        @DisplayName("should survive a deeply nested reply")
        void deepNesting() throws IOException {
            reply(200, "{\"X\":" + "[".repeat(200_000) + "]".repeat(200_000) + "}");

            assertEquals(new TreeMap<>(TranslationAnswerTest.GERMAN_ANSWER), ask("de"));
        }

        @Test
        @DisplayName("should fail like a connection for a language that isn't bundled, so CoreProtect saves no cache")
        void notBundled() {
            reply(503, "");

            assertThrows(IOException.class, () -> ask("nl"));
            assertFalse(logger.hasLevel(Level.WARNING));
        }
    }

    @Test
    @DisplayName("should send the service byte for byte what CoreProtect sends it without LibreProtect")
    void wireParity() throws Exception {
        Map<String, String> phrases = new HashMap<>(TranslationAnswerTest.builtInPhrases("de"));
        phrases.put("HELP_HEADER", "Mein \"Server\" + Hilfe \\ ü ☃ 😀");
        byte[] postData = TranslationAnswerTest.body(phrases);
        URL url = MockUrlFactory.translateUrl();
        RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.of(new Route(".*", RouteActionType.PASSTHROUGH),
            Map.of());

        String reply = "{\"HELP_HEADER\":\"{0} Hilfe\",\"STATUS_AUTO_PURGE\":\"Auto-Bereinigung: {0}\"}";
        try (RawProxy proxy = new RawProxy(reply)) {
            upstreamRequest((HttpURLConnection) url.openConnection(proxy.proxy()), postData);
            String layered = upstreamRequest((HttpURLConnection) new PassthroughAction(bundled)
                .createConnection(url, proxy.proxy(), match), postData);

            assertEquals(2, proxy.requests.size());
            assertEquals(new String(proxy.requests.get(0), StandardCharsets.UTF_8),
                new String(proxy.requests.get(1), StandardCharsets.UTF_8));
            // The reply reaches CoreProtect, without the phrase that this request customized
            Map<String, String> reached = TranslationAnswer.strings(layered);
            assertEquals("Auto-Bereinigung: {0}", reached.get("STATUS_AUTO_PURGE"));
            assertFalse(reached.containsKey("HELP_HEADER"));
        }
    }

    /**
     * CoreProtect's NetworkHandler, from setting up the connection to reading
     * the reply, on the connection that it was given
     *
     * @return the reply's lines, trimmed and joined, or "" for a status other than 200
     */
    private static String upstreamRequest(HttpURLConnection connection, byte[] postData) throws IOException {
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Accept-Charset", "UTF-8");
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
        connection.setRequestProperty("User-Agent", "CoreProtect");
        connection.setRequestProperty("Content-Length", Integer.toString(postData.length));
        connection.setDoOutput(true);
        connection.setInstanceFollowRedirects(true);
        connection.setUseCaches(false);
        connection.setConnectTimeout(5000);
        DataOutputStream outputStream = new DataOutputStream(connection.getOutputStream());
        outputStream.write(postData);
        outputStream.close();

        StringBuilder response = new StringBuilder();
        if (connection.getResponseCode() == 200) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), "utf-8"));
            for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                response.append(line.trim());
            }
            reader.close();
        }
        connection.disconnect();
        return response.toString();
    }

    /**
     * An HTTP proxy on loopback that records each request's raw bytes, head
     * and body, and answers every request with the same JSON
     */
    private static final class RawProxy implements AutoCloseable {

        final List<byte[]> requests = new CopyOnWriteArrayList<>();
        private final ServerSocket socket;

        RawProxy(String reply) throws IOException {
            socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread thread = new Thread(() -> {
                while (!socket.isClosed()) {
                    try (Socket client = socket.accept()) {
                        requests.add(read(client.getInputStream()));
                        byte[] content = reply.getBytes(StandardCharsets.UTF_8);
                        OutputStream out = client.getOutputStream();
                        out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                            + content.length + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                        out.write(content);
                        out.flush();
                    } catch (IOException e) {
                        // Closed
                    }
                }
            });
            thread.setDaemon(true);
            thread.start();
        }

        private static byte[] read(InputStream in) throws IOException {
            ByteArrayOutputStream request = new ByteArrayOutputStream();
            for (int b = in.read(); b >= 0; b = in.read()) {
                request.write(b);
                if (request.toString(StandardCharsets.ISO_8859_1).endsWith("\r\n\r\n")) {
                    break;
                }
            }
            int length = 0;
            for (String line : request.toString(StandardCharsets.ISO_8859_1).split("\r\n")) {
                if (line.toLowerCase(Locale.ROOT).startsWith("content-length:")) {
                    length = Integer.parseInt(line.substring("content-length:".length()).trim());
                }
            }
            request.write(in.readNBytes(length));
            return request.toByteArray();
        }

        Proxy proxy() {
            return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(InetAddress.getLoopbackAddress(),
                socket.getLocalPort()));
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    @Nested
    @DisplayName("Through a connection")
    class ThroughConnection {

        @Test
        @DisplayName("should send nothing until CoreProtect asks for the reply, then send once")
        void lazy() throws IOException {
            reply(200, "{\"STATUS_AUTO_PURGE\":\"Auto-Bereinigung: {0}\"}");
            AnswerConnection connection = new AnswerConnection(service.url("/translate/"),
                new LayeredTranslationAnswer(bundled, null));
            connection.setRequestMethod("POST");
            HEADERS.forEach(connection::setRequestProperty);
            connection.setDoOutput(true);
            try (OutputStream out = connection.getOutputStream()) {
                out.write(TranslationAnswerTest.body(TranslationAnswerTest.builtInPhrases("de")));
            }
            assertTrue(service.getReceived().isEmpty());

            assertEquals(200, connection.getResponseCode());
            assertEquals("Auto-Bereinigung: {0}", TranslationAnswer.strings(new String(
                connection.getInputStream().readAllBytes(), StandardCharsets.UTF_8)).get("STATUS_AUTO_PURGE"));
            assertEquals(1, service.getReceived().size());
        }

        @Test
        @DisplayName("should fail each call, as a failed connection does, when neither can answer")
        void fails() {
            reply(500, "");
            AnswerConnection connection = new AnswerConnection(service.url("/translate/"),
                new LayeredTranslationAnswer(bundled, null));

            assertThrows(IOException.class, connection::getResponseCode);
            assertThrows(IOException.class, connection::getInputStream);
            assertEquals(1, service.getReceived().size());
        }
    }
}
