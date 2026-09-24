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

import net.deltik.mc.libreprotect.routing.Route;
import net.deltik.mc.libreprotect.routing.RouteActionType;
import net.deltik.mc.libreprotect.routing.RoutePreset;
import net.deltik.mc.libreprotect.routing.RouteRegistry;
import net.deltik.mc.libreprotect.routing.RouteResolver;
import net.deltik.mc.libreprotect.routing.answer.AnswerConnection;
import net.deltik.mc.libreprotect.testutil.LocalHttpServer;
import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class EgressTest {

    private TestLogger testLogger;

    @BeforeEach
    void setUp() {
        Egress.uninstall();
        LibreProtectLogger.reset();
        testLogger = new TestLogger();
        LibreProtectLogger.initialize(testLogger);
    }

    @AfterEach
    void tearDown() {
        Egress.uninstall();
        LibreProtectLogger.reset();
    }

    private static RouteResolver resolver(RoutePreset preset) {
        return new PrivacyConfig(preset, List.of(), false).buildResolver();
    }

    private static RouteResolver resolver(Route... routes) {
        return new RouteResolver(RouteRegistry.builder()
            .addRoutes(List.of(routes))
            .setDefaultAction(RouteActionType.BLOCK)
            .build());
    }

    private static String read(InputStream is) throws IOException {
        try (is) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Nested
    @DisplayName("Without a resolver")
    class WithoutResolver {

        private final URL url = MockUrlFactory.updateUrl();

        @Test
        @DisplayName("getResolver() should return null")
        void noResolver() {
            assertNull(Egress.getResolver());
        }

        @Test
        @DisplayName("openConnection(URL) should be blocked")
        void openConnectionBlocked() {
            EgressBlockedException ex = assertThrows(EgressBlockedException.class, () -> Egress.openConnection(url));
            assertEquals("network policy not loaded", ex.getReason());
            assertTrue(ex.getMessage().contains("http://update.coreprotect.net/version/"), ex.getMessage());
        }

        @Test
        @DisplayName("openConnection(URL, Proxy) should be blocked")
        void openConnectionWithProxyBlocked() {
            assertThrows(EgressBlockedException.class, () -> Egress.openConnection(url, Proxy.NO_PROXY));
        }

        @Test
        @DisplayName("openStream(URL) should be blocked")
        void openStreamBlocked() {
            assertThrows(EgressBlockedException.class, () -> Egress.openStream(url));
        }

        @Test
        @DisplayName("getContent(URL) should be blocked")
        void getContentBlocked() {
            assertThrows(EgressBlockedException.class, () -> Egress.getContent(url));
        }

        @Test
        @DisplayName("getContent(URL, Class[]) should be blocked")
        void getContentClassesBlocked() {
            assertThrows(EgressBlockedException.class,
                () -> Egress.getContent(url, new Class<?>[]{InputStream.class}));
        }

        @Test
        @DisplayName("should block even local file: URLs")
        void blocksFileUrls(@TempDir Path dir) throws IOException {
            Path file = Files.writeString(dir.resolve("data.txt"), "local");
            assertThrows(EgressBlockedException.class, () -> Egress.openStream(file.toUri().toURL()));
        }

        @Test
        @DisplayName("should throw an IOException, so callers treat it as offline")
        void isIOException() {
            IOException ex = assertThrows(IOException.class, () -> Egress.openConnection(url));
            assertInstanceOf(EgressBlockedException.class, ex);
        }

        @Test
        @DisplayName("should log the blocked request when verbose logging is enabled")
        void logsWhenVerbose() {
            LibreProtectLogger.setVerbose(true);

            assertThrows(EgressBlockedException.class, () -> Egress.openConnection(url));

            assertTrue(testLogger.hasMessageContaining("Blocked"));
            assertTrue(testLogger.hasMessageContaining("network policy not loaded"));
        }

        @Test
        @DisplayName("should NOT log the blocked request when verbose logging is disabled")
        void doesNotLogWhenNotVerbose() {
            LibreProtectLogger.setVerbose(false);

            assertThrows(EgressBlockedException.class, () -> Egress.openConnection(url));

            assertFalse(testLogger.hasMessageContaining("Blocked"));
            assertTrue(testLogger.getRecords().isEmpty());
        }
    }

    @Nested
    @DisplayName("install and uninstall")
    class InstallUninstall {

        @Test
        @DisplayName("install() should make the resolver current")
        void installSetsResolver() {
            RouteResolver resolver = resolver(RoutePreset.PASSTHROUGH);
            Egress.install(resolver);
            assertSame(resolver, Egress.getResolver());
        }

        @Test
        @DisplayName("install() should replace the previous resolver")
        void installReplaces() {
            Egress.install(resolver(RoutePreset.PASSTHROUGH));
            RouteResolver second = resolver(RoutePreset.PRIVACY_FIRST);
            Egress.install(second);
            assertSame(second, Egress.getResolver());
        }

        @Test
        @DisplayName("uninstall() should block every request again")
        void uninstallBlocksAgain(@TempDir Path dir) throws IOException {
            Path file = Files.writeString(dir.resolve("data.txt"), "local");
            URL url = file.toUri().toURL();
            Egress.install(resolver(RoutePreset.PASSTHROUGH));
            assertEquals("local", read(Egress.openStream(url)));

            Egress.uninstall();

            assertNull(Egress.getResolver());
            EgressBlockedException ex = assertThrows(EgressBlockedException.class, () -> Egress.openStream(url));
            assertEquals("network policy not loaded", ex.getReason());
        }

        @Test
        @DisplayName("install(null) should behave like uninstall()")
        void installNullBlocks() {
            Egress.install(resolver(RoutePreset.PASSTHROUGH));
            Egress.install(null);
            assertNull(Egress.getResolver());
            assertThrows(EgressBlockedException.class, () -> Egress.openConnection(MockUrlFactory.updateUrl()));
        }
    }

    @Nested
    @DisplayName("openConnection(URL, Proxy)")
    class OpenConnectionWithProxy {

        @Test
        @DisplayName("should reject a null proxy like URL#openConnection(Proxy)")
        void rejectsNullProxy() {
            Egress.install(resolver(RoutePreset.PASSTHROUGH));
            assertThrows(IllegalArgumentException.class,
                () -> Egress.openConnection(MockUrlFactory.updateUrl(), null));
        }

        @Test
        @DisplayName("should reject a null proxy even without a resolver")
        void rejectsNullProxyWithoutResolver() {
            assertThrows(IllegalArgumentException.class,
                () -> Egress.openConnection(MockUrlFactory.updateUrl(), null));
        }

        @Test
        @DisplayName("should connect through the given proxy on passthrough")
        void usesProxy() throws IOException {
            Egress.install(resolver(RoutePreset.PASSTHROUGH));
            try (LocalHttpServer server = new LocalHttpServer()) {
                URLConnection conn = Egress.openConnection(server.url("/via-proxy"), server.asProxy());
                assertEquals("proxied " + server.getBaseUrl() + "/via-proxy", LocalHttpServer.read(conn));
            }
        }

        @Test
        @DisplayName("should connect directly without a proxy on passthrough")
        void directWithoutProxy() throws IOException {
            Egress.install(resolver(RoutePreset.PASSTHROUGH));
            try (LocalHttpServer server = new LocalHttpServer()) {
                URLConnection conn = Egress.openConnection(server.url("/direct"));
                assertEquals("direct /direct", LocalHttpServer.read(conn));
            }
        }

        @Test
        @DisplayName("should still apply the policy when a proxy is given")
        void appliesPolicyWithProxy() {
            Egress.install(resolver(RoutePreset.PRIVACY_FIRST));
            assertThrows(EgressBlockedException.class,
                () -> Egress.openConnection(MockUrlFactory.statsUrl(), Proxy.NO_PROXY));
        }
    }

    @Nested
    @DisplayName("Delegation through routing")
    class Delegation {

        private final Route answerUpdates = new Route("https?://update\\.coreprotect\\.net/.*", RouteActionType.ANSWER);

        @Test
        @DisplayName("openConnection(URL) should return the routed connection")
        void openConnectionRoutes() throws IOException {
            Egress.install(resolver(answerUpdates));
            assertInstanceOf(AnswerConnection.class, Egress.openConnection(MockUrlFactory.updateUrl()));
        }

        @Test
        @DisplayName("openStream(URL) should read the routed connection")
        void openStreamRoutes() throws IOException {
            Egress.install(resolver(answerUpdates));
            assertEquals("0.0", read(Egress.openStream(MockUrlFactory.updateUrl())));
        }

        @Test
        @DisplayName("getContent(URL) should return the routed connection's content")
        void getContentRoutes() throws IOException {
            Egress.install(resolver(answerUpdates));
            Object content = Egress.getContent(MockUrlFactory.updateUrl());
            assertEquals("0.0", read(assertInstanceOf(InputStream.class, content)));
        }

        @Test
        @DisplayName("getContent(URL, Class[]) should honor the requested classes")
        void getContentClassesRoutes() throws IOException {
            Egress.install(resolver(answerUpdates));

            Object stream = Egress.getContent(MockUrlFactory.updateUrl(), new Class<?>[]{InputStream.class});
            assertEquals("0.0", read(assertInstanceOf(InputStream.class, stream)));

            assertNull(Egress.getContent(MockUrlFactory.updateUrl(), new Class<?>[]{String.class}));
        }

        @Test
        @DisplayName("every entry point should apply BLOCK routes")
        void everyEntryPointBlocks() {
            Egress.install(resolver(RoutePreset.PRIVACY_FIRST));
            URL url = MockUrlFactory.statsUrl();

            List<Executable> calls = List.of(
                () -> Egress.openConnection(url),
                () -> Egress.openConnection(url, Proxy.NO_PROXY),
                () -> Egress.openStream(url),
                () -> Egress.getContent(url),
                () -> Egress.getContent(url, new Class<?>[]{InputStream.class}));
            for (Executable call : calls) {
                EgressBlockedException ex = assertThrows(EgressBlockedException.class, call);
                assertTrue(ex.getReason().contains("stats"), ex.getReason());
            }
        }

        @Test
        @DisplayName("an https answer should be an HttpsURLConnection")
        void httpsAnswerIsHttps() throws IOException {
            Egress.install(resolver(new Route("https://stats\\.coreprotect\\.net/.*", RouteActionType.ANSWER)));

            URLConnection conn = Egress.openConnection(MockUrlFactory.httpsStatsUrl());

            assertInstanceOf(HttpsURLConnection.class, conn);
            assertInstanceOf(HttpURLConnection.class, conn);
            assertEquals(HttpURLConnection.HTTP_OK, ((HttpsURLConnection) conn).getResponseCode());
        }
    }

    @Nested
    @DisplayName("URL normalization")
    class Normalization {

        private String bstatsPattern() {
            return RoutePreset.PRIVACY_FIRST.getRoutes().stream()
                .map(Route::getPatternString)
                .filter(p -> p.contains("bstats"))
                .findFirst()
                .orElseThrow();
        }

        @Test
        @DisplayName("privacy-first should block bStats.org through its bstats.org route")
        void blocksMixedCaseBstats() {
            Egress.install(resolver(RoutePreset.PRIVACY_FIRST));

            EgressBlockedException ex = assertThrows(EgressBlockedException.class,
                () -> Egress.openConnection(MockUrlFactory.createUrl("https://bStats.org/api/v2/data/bukkit")));

            // Not the default action: the route itself must match the mixed-case host
            assertEquals("route " + bstatsPattern(), ex.getReason());
            assertTrue(ex.getReason().contains("bstats\\.org"), ex.getReason());
            assertTrue(ex.getMessage().contains("https://bstats.org/api/v2/data/bukkit"), ex.getMessage());
        }

        @Test
        @DisplayName("allow-updates should block bStats.org through its bstats.org route")
        void allowUpdatesBlocksMixedCaseBstats() {
            Egress.install(resolver(RoutePreset.ALLOW_UPDATES));

            EgressBlockedException ex = assertThrows(EgressBlockedException.class,
                () -> Egress.openConnection(MockUrlFactory.bstatsUrl()));

            assertEquals("route " + bstatsPattern(), ex.getReason());
        }

        @Test
        @DisplayName("a mixed-case scheme and host should match a lowercase custom route")
        void mixedCaseMatchesCustomRoute() throws IOException {
            Egress.install(resolver(new Route("https?://update\\.coreprotect\\.net/.*", RouteActionType.ANSWER)));

            URLConnection conn = Egress.openConnection(MockUrlFactory.createUrl("HTTP://Update.CoreProtect.NET/version/"));

            assertInstanceOf(AnswerConnection.class, conn);
        }

        @Test
        @DisplayName("user info should not affect matching or appear in the block message")
        void userInfoDropped() {
            Egress.install(resolver(RoutePreset.PRIVACY_FIRST));

            EgressBlockedException ex = assertThrows(EgressBlockedException.class,
                () -> Egress.openConnection(MockUrlFactory.createUrl("https://user:secret@stats.coreprotect.net/submit#frag")));

            assertTrue(ex.getReason().startsWith("route "), ex.getReason());
            assertFalse(ex.getMessage().contains("secret"), ex.getMessage());
            assertFalse(ex.getMessage().contains("frag"), ex.getMessage());
        }
    }

    @Nested
    @DisplayName("EgressBlockedException")
    class BlockedException {

        @Test
        @DisplayName("should name LibreProtect, the reason and the normalized URL")
        void messageFormat() {
            EgressBlockedException ex = new EgressBlockedException(
                MockUrlFactory.createUrl("HTTPS://user:pw@Stats.CoreProtect.net/Submit?Q=1#top"), "some reason");

            assertEquals("Blocked by " + PrivacyConstants.FORK_NAME
                + " (some reason): https://stats.coreprotect.net/Submit?Q=1", ex.getMessage());
            assertEquals("some reason", ex.getReason());
        }

        @Test
        @DisplayName("should be an IOException")
        void isIOException() {
            assertInstanceOf(IOException.class, new EgressBlockedException(MockUrlFactory.statsUrl(), "r"));
        }
    }

    @Nested
    @DisplayName("Passthrough end to end")
    class PassthroughEndToEnd {

        @TempDir
        Path dir;

        @Test
        @DisplayName("a file: URL should be readable through openStream")
        void fileUrlOpenStream() throws IOException {
            Path file = Files.writeString(dir.resolve("data.txt"), "passthrough works");
            Egress.install(resolver(RoutePreset.PASSTHROUGH));

            assertEquals("passthrough works", read(Egress.openStream(file.toUri().toURL())));
        }

        @Test
        @DisplayName("a file: URL should be readable through openConnection")
        void fileUrlOpenConnection() throws IOException {
            Path file = Files.writeString(dir.resolve("data.bin"), "bytes");
            Egress.install(resolver(RoutePreset.PASSTHROUGH));

            URLConnection conn = Egress.openConnection(file.toUri().toURL());

            assertEquals(file.toUri().toURL().toExternalForm(), conn.getURL().toExternalForm());
            assertEquals("bytes", read(conn.getInputStream()));
        }

        @Test
        @DisplayName("a file: URL should be readable through getContent")
        void fileUrlGetContent() throws IOException {
            Path file = Files.writeString(dir.resolve("data.txt"), "content");
            Egress.install(resolver(RoutePreset.PASSTHROUGH));

            Object content = Egress.getContent(file.toUri().toURL());

            assertEquals("content", read(assertInstanceOf(InputStream.class, content)));
        }

        @Test
        @DisplayName("a custom PASSTHROUGH route should let a file: URL through privacy-first")
        void customPassthroughRoute() throws IOException {
            Path file = Files.writeString(dir.resolve("allowed.txt"), "allowed");
            Route allowFiles = new Route("file://.*/allowed\\.txt", RouteActionType.PASSTHROUGH);
            Egress.install(new PrivacyConfig(RoutePreset.PRIVACY_FIRST, List.of(allowFiles), false).buildResolver());

            assertEquals("allowed", read(Egress.openStream(file.toUri().toURL())));

            Path other = Files.writeString(dir.resolve("other.txt"), "other");
            EgressBlockedException ex = assertThrows(EgressBlockedException.class,
                () -> Egress.openStream(other.toUri().toURL()));
            assertEquals("default action", ex.getReason());
        }

        @Test
        @DisplayName("passthrough should log when verbose logging is enabled")
        void logsWhenVerbose() throws IOException {
            Path file = Files.writeString(dir.resolve("data.txt"), "x");
            Egress.install(resolver(RoutePreset.PASSTHROUGH));
            LibreProtectLogger.setVerbose(true);

            read(Egress.openStream(file.toUri().toURL()));

            assertTrue(testLogger.hasMessageContaining("Passthrough"));
            assertTrue(testLogger.hasMessageContaining("default action"));
        }

        @Test
        @DisplayName("passthrough should NOT log when verbose logging is disabled")
        void doesNotLogWhenNotVerbose() throws IOException {
            Path file = Files.writeString(dir.resolve("data.txt"), "x");
            Egress.install(resolver(RoutePreset.PASSTHROUGH));
            LibreProtectLogger.setVerbose(false);

            read(Egress.openStream(file.toUri().toURL()));

            assertTrue(testLogger.getRecords().isEmpty());
        }
    }
}
