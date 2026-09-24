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

package net.deltik.mc.libreprotect.routing.action;

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.routing.Route;
import net.deltik.mc.libreprotect.routing.RouteActionType;
import net.deltik.mc.libreprotect.routing.RouteRegistry;
import net.deltik.mc.libreprotect.routing.answer.AnswerConnection;
import net.deltik.mc.libreprotect.testutil.LocalHttpServer;
import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PassthroughActionTest {

    @TempDir
    Path tempDir;

    private PassthroughAction action;
    private TestLogger testLogger;
    private final RouteRegistry.RouteMatch match =
        RouteRegistry.RouteMatch.of(new Route(".*", RouteActionType.PASSTHROUGH), Map.of());

    @BeforeEach
    void setUp() {
        action = new PassthroughAction();
        testLogger = new TestLogger();
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(testLogger);
    }

    @AfterEach
    void tearDown() {
        LibreProtectLogger.reset();
    }

    private URL fileUrl(String content) throws IOException {
        return Files.writeString(tempDir.resolve("data.txt"), content).toUri().toURL();
    }

    @Test
    @DisplayName("getType() should return PASSTHROUGH")
    void getTypeReturnsPassthrough() {
        assertEquals(RouteActionType.PASSTHROUGH, action.getType());
    }

    @Nested
    @DisplayName("createConnection")
    class CreateConnection {

        @Test
        @DisplayName("should return a real connection to the same URL")
        void returnsRealConnection() throws IOException {
            URL url = fileUrl("original content");

            URLConnection conn = action.createConnection(url, null, match);

            assertEquals(url.toExternalForm(), conn.getURL().toExternalForm());
            assertEquals("original content", new String(conn.getInputStream().readAllBytes()));
        }

        @Test
        @DisplayName("should connect directly when no proxy is given")
        void directWithoutProxy() throws IOException {
            try (LocalHttpServer server = new LocalHttpServer()) {
                URLConnection conn = action.createConnection(server.url("/direct"), null, match);

                assertInstanceOf(HttpURLConnection.class, conn);
                assertEquals("direct /direct", LocalHttpServer.read(conn));
            }
        }

        @Test
        @DisplayName("should connect through the proxy the caller asked for")
        void honorsProxy() throws IOException {
            try (LocalHttpServer server = new LocalHttpServer()) {
                URLConnection conn = action.createConnection(server.url("/target"), server.asProxy(), match);

                assertEquals("proxied " + server.getBaseUrl() + "/target", LocalHttpServer.read(conn));
            }
        }

        @Test
        @DisplayName("should honor Proxy.NO_PROXY")
        void honorsNoProxy() throws IOException {
            try (LocalHttpServer server = new LocalHttpServer()) {
                URLConnection conn = action.createConnection(server.url("/target"), Proxy.NO_PROXY, match);

                assertEquals("direct /target", LocalHttpServer.read(conn));
            }
        }

        @Test
        @DisplayName("should log when verbose logging is enabled")
        void logsWhenVerbose() throws IOException {
            LibreProtectLogger.setVerbose(true);

            action.createConnection(fileUrl("x"), null, match);

            // Should have logged "Passthrough:" message
            assertTrue(testLogger.hasMessageContaining("Passthrough"));
            assertTrue(testLogger.hasMessageContaining("file:///"));
        }

        @Test
        @DisplayName("should NOT log when verbose logging is disabled")
        void doesNotLogWhenNotVerbose() throws IOException {
            LibreProtectLogger.setVerbose(false);

            action.createConnection(fileUrl("x"), null, match);

            // Should not have logged "Passthrough:" message
            assertFalse(testLogger.hasMessageContaining("Passthrough"));
            assertTrue(testLogger.getRecords().isEmpty());
        }

        @Test
        @DisplayName("should log the normalized URL without user info")
        void logsNormalizedUrl() throws IOException {
            LibreProtectLogger.setVerbose(true);
            try (LocalHttpServer server = new LocalHttpServer()) {
                URL withUserInfo = MockUrlFactory.createUrl(
                    "http://user:secret@127.0.0.1:" + server.getPort() + "/x#frag");

                action.createConnection(withUserInfo, null, match);

                assertTrue(testLogger.hasMessageContaining("Passthrough: " + server.getBaseUrl() + "/x"));
                assertFalse(testLogger.hasMessageContaining("secret"));
                assertFalse(testLogger.hasMessageContaining("frag"));
            }
        }
    }

    @Nested
    @DisplayName("Translation requests")
    class Translations {

        @ParameterizedTest
        @ValueSource(strings = {
            "http://coreprotect.net/translate/",
            "https://coreprotect.net/translate/",
            "http://CoreProtect.NET/translate"
        })
        @DisplayName("should get the bundled translation layered under the service's")
        void layered(String url) throws IOException {
            URLConnection conn = action.createConnection(MockUrlFactory.createUrl(url), null, match);
            assertInstanceOf(AnswerConnection.class, conn);
        }

        @Test
        @DisplayName("should reach the service through the proxy that CoreProtect asked for")
        void throughProxy() throws IOException {
            try (LocalHttpServer service = new LocalHttpServer(exchange ->
                LocalHttpServer.respond(exchange, 200, "{\"HELP_HEADER\":\"{0} Hilfe\"}"))) {
                HttpURLConnection conn = (HttpURLConnection) action.createConnection(MockUrlFactory.translateUrl(),
                    service.asProxy(), match);
                conn.setRequestMethod("POST");
                conn.setDoOutput(true);
                try (OutputStream out = conn.getOutputStream()) {
                    out.write("data={\"DATA_LANGUAGE\":\"de\",\"HELP_HEADER\":\"{0} Help\"}"
                        .getBytes(StandardCharsets.UTF_8));
                }

                assertEquals(200, conn.getResponseCode());
                assertEquals("{\"HELP_HEADER\":\"{0} Hilfe\"}", LocalHttpServer.read(conn));
                assertEquals("http://coreprotect.net/translate/", service.getRequests().get(0).toString());
            }
        }

        @Test
        @DisplayName("should leave CoreProtect's other endpoints unchanged")
        void otherEndpoints() throws IOException {
            for (URL url : new URL[] {MockUrlFactory.licenseUrl(), MockUrlFactory.updateUrl(),
                MockUrlFactory.createUrl("http://coreprotect.net/translate/extra")}) {
                URLConnection conn = action.createConnection(url, null, match);
                assertFalse(conn instanceof AnswerConnection, url.toString());
            }
        }
    }
}
