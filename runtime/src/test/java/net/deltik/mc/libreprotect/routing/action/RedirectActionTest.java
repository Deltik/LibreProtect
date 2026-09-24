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
import net.deltik.mc.libreprotect.routing.UrlNormalizer;
import net.deltik.mc.libreprotect.testutil.LocalHttpServer;
import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RedirectActionTest {

    @TempDir
    Path tempDir;

    private RedirectAction action;
    private TestLogger testLogger;

    @BeforeEach
    void setUp() {
        action = new RedirectAction();
        testLogger = new TestLogger();
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(testLogger);
    }

    @AfterEach
    void tearDown() {
        LibreProtectLogger.reset();
    }

    /**
     * @return the temp dir as a {@code file:} URL prefix ending in a slash
     */
    private String tempDirUrl() {
        String uri = tempDir.toUri().toString();
        return uri.endsWith("/") ? uri : uri + "/";
    }

    /**
     * Match a URL the way RouteResolver does, so captures are real.
     */
    private static RouteRegistry.RouteMatch matchFor(Route route, URL url) {
        RouteRegistry.RouteMatch match = RouteRegistry.builder().addRoute(route).build()
            .match(UrlNormalizer.normalize(url));
        assertFalse(match.isDefault(), "route did not match " + url);
        return match;
    }

    @Test
    @DisplayName("getType() should return REDIRECT")
    void getTypeReturnsRedirect() {
        assertEquals(RouteActionType.REDIRECT, action.getType());
    }

    @Nested
    @DisplayName("createConnection")
    class CreateConnection {

        @Test
        @DisplayName("should throw IOException when target is null")
        void throwsWhenTargetNull() {
            Route route = new Route(".*", RouteActionType.REDIRECT, null);
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.of(route, Map.of());

            IOException ex = assertThrows(IOException.class,
                () -> action.createConnection(MockUrlFactory.createUrl("https://old.example/path"), null, match));
            assertTrue(ex.getMessage().contains("target"));
        }

        @Test
        @DisplayName("should throw IOException when target is empty")
        void throwsWhenTargetEmpty() {
            Route route = new Route(".*", RouteActionType.REDIRECT, "");
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.of(route, Map.of());

            IOException ex = assertThrows(IOException.class,
                () -> action.createConnection(MockUrlFactory.createUrl("https://old.example/path"), null, match));
            assertTrue(ex.getMessage().contains("target"));
        }

        @Test
        @DisplayName("should throw IOException when the substituted target is not a URL")
        void throwsForBadTarget() {
            Route route = new Route(".*", RouteActionType.REDIRECT, "no-scheme/${path}");
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.of(route, Map.of("path", "x"));

            assertThrows(IOException.class,
                () -> action.createConnection(MockUrlFactory.createUrl("https://old.example/x"), null, match));
        }

        @Test
        @DisplayName("should log redirect with original and target URLs when verbose")
        void logsRedirectWhenVerbose() throws IOException {
            LibreProtectLogger.setVerbose(true);
            Files.writeString(tempDir.resolve("some-file"), "x");
            Route route = new Route("https://old\\.example/(?<path>.*)", RouteActionType.REDIRECT,
                tempDirUrl() + "${path}");
            URL url = MockUrlFactory.createUrl("https://old.example/some-file");

            action.createConnection(url, null, matchFor(route, url));

            assertTrue(testLogger.hasMessageContaining("Redirect"));
            assertTrue(testLogger.hasMessageContaining("https://old.example/some-file"));
            assertTrue(testLogger.hasMessageContaining(tempDirUrl() + "some-file"));
        }

        @Test
        @DisplayName("should NOT log redirect when verbose logging disabled")
        void doesNotLogRedirectWhenNotVerbose() throws IOException {
            LibreProtectLogger.setVerbose(false);
            Route route = new Route("https://old\\.example/(?<path>.*)", RouteActionType.REDIRECT,
                tempDirUrl() + "${path}");
            URL url = MockUrlFactory.createUrl("https://old.example/some-file");

            action.createConnection(url, null, matchFor(route, url));

            assertFalse(testLogger.hasMessageContaining("Redirect"));
            assertTrue(testLogger.getRecords().isEmpty());
        }

        @Test
        @DisplayName("should substitute captures in target URL")
        void substitutesCapturesInTarget() throws IOException {
            Files.writeString(tempDir.resolve("example-v1.txt"), "mirrored");
            Route route = new Route("https://(?<host>\\w+)\\.com/api/(?<version>\\w+)",
                RouteActionType.REDIRECT, tempDirUrl() + "${host}-${version}.txt");
            URL url = MockUrlFactory.createUrl("https://example.com/api/v1");

            URLConnection conn = action.createConnection(url, null, matchFor(route, url));

            assertEquals(tempDirUrl() + "example-v1.txt", UrlNormalizer.normalize(conn.getURL()));
            assertEquals("mirrored", new String(conn.getInputStream().readAllBytes()));
        }

        @Test
        @DisplayName("should work with empty captures")
        void worksWithEmptyCaptures() throws IOException {
            Files.writeString(tempDir.resolve("static-target.txt"), "static");
            Route route = new Route(".*", RouteActionType.REDIRECT, tempDirUrl() + "static-target.txt");
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.of(route, Map.of());

            URLConnection conn = action.createConnection(MockUrlFactory.createUrl("https://any.example/path"), null, match);

            assertEquals("static", new String(conn.getInputStream().readAllBytes()));
        }

        @Test
        @DisplayName("should connect to the redirect target")
        void connectsToTarget() throws IOException {
            try (LocalHttpServer server = new LocalHttpServer()) {
                Route route = new Route("http://update\\.coreprotect\\.net(?P<path>/.*)", RouteActionType.REDIRECT,
                    server.getBaseUrl() + "/mirror${path}");
                URL url = MockUrlFactory.updateUrl();

                URLConnection conn = action.createConnection(url, null, matchFor(route, url));

                assertEquals("direct /mirror/version/", LocalHttpServer.read(conn));
            }
        }

        @Test
        @DisplayName("should connect to the redirect target through the caller's proxy")
        void honorsProxy() throws IOException {
            try (LocalHttpServer server = new LocalHttpServer()) {
                Route route = new Route("http://update\\.coreprotect\\.net(?P<path>/.*)", RouteActionType.REDIRECT,
                    server.getBaseUrl() + "/mirror${path}");
                URL url = MockUrlFactory.updateUrl();

                URLConnection conn = action.createConnection(url, server.asProxy(), matchFor(route, url));

                assertEquals("proxied " + server.getBaseUrl() + "/mirror/version/", LocalHttpServer.read(conn));
            }
        }

        @Test
        @DisplayName("should honor Proxy.NO_PROXY")
        void honorsNoProxy() throws IOException {
            try (LocalHttpServer server = new LocalHttpServer()) {
                Route route = new Route(".*", RouteActionType.REDIRECT, server.getBaseUrl() + "/fixed");
                RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.of(route, Map.of());

                URLConnection conn = action.createConnection(MockUrlFactory.updateUrl(), Proxy.NO_PROXY, match);

                assertEquals("direct /fixed", LocalHttpServer.read(conn));
            }
        }
    }
}
