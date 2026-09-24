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

import net.deltik.mc.libreprotect.*;
import net.deltik.mc.libreprotect.routing.answer.AnswerConnection;
import net.deltik.mc.libreprotect.routing.answer.Response;
import net.deltik.mc.libreprotect.testutil.LocalHttpServer;
import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import net.deltik.mc.libreprotect.testutil.RecordingAnswer;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;

import static org.junit.jupiter.api.Assertions.*;

class RouteResolverTest {

    private TestLogger testLogger;

    @BeforeEach
    void setUp() {
        testLogger = new TestLogger();
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(testLogger);
    }

    @AfterEach
    void tearDown() {
        LibreProtectLogger.reset();
    }

    private static URL url(String spec) {
        return MockUrlFactory.createUrl(spec);
    }

    @Nested
    @DisplayName("resolve")
    class Resolve {

        @Test
        @DisplayName("should throw EgressBlockedException for BLOCK action")
        void throwsForBlockAction() {
            RouteRegistry registry = RouteRegistry.builder()
                .addRoute("https://stats\\.coreprotect\\.net/.*", RouteActionType.BLOCK)
                .build();
            RouteResolver resolver = new RouteResolver(registry);

            EgressBlockedException ex = assertThrows(EgressBlockedException.class,
                () -> resolver.resolve(url("https://stats.coreprotect.net/submit")));
            assertEquals("route https://stats\\.coreprotect\\.net/.*", ex.getReason());
        }

        @Test
        @DisplayName("should return an AnswerConnection for ANSWER action")
        void returnsAnswerConnectionForAnswerAction() throws IOException {
            RouteRegistry registry = RouteRegistry.builder()
                .addRoute("https?://update\\.coreprotect\\.net/.*", RouteActionType.ANSWER)
                .build();
            RouteResolver resolver = new RouteResolver(registry);

            URLConnection conn = resolver.resolve(MockUrlFactory.updateUrl());

            assertInstanceOf(AnswerConnection.class, conn);
        }

        @Test
        @DisplayName("should log match info when verbose logging enabled")
        void logsWhenVerbose() {
            LibreProtectLogger.setVerbose(true);
            RouteRegistry registry = RouteRegistry.builder()
                .addRoute("https://example\\.com/.*", RouteActionType.BLOCK)
                .build();
            RouteResolver resolver = new RouteResolver(registry);

            assertThrows(EgressBlockedException.class, () -> resolver.resolve(url("https://example.com/path")));

            assertTrue(testLogger.hasMessageContaining("matched route"));
            assertTrue(testLogger.hasMessageContaining("https://example\\.com/.*"));
        }

        @Test
        @DisplayName("should not log match info when verbose logging disabled")
        void doesNotLogWhenNotVerbose() {
            LibreProtectLogger.setVerbose(false);
            RouteRegistry registry = RouteRegistry.builder()
                .addRoute("https://example\\.com/.*", RouteActionType.BLOCK)
                .build();
            RouteResolver resolver = new RouteResolver(registry);

            testLogger.clear();
            assertThrows(EgressBlockedException.class, () -> resolver.resolve(url("https://example.com/path")));

            // Neither the route match info nor BlockAction's "Blocked" message
            assertFalse(testLogger.hasMessageContaining("matched route"));
            assertFalse(testLogger.hasMessageContaining("Blocked"));
            assertTrue(testLogger.getRecords().isEmpty());
        }

        @Test
        @DisplayName("should use default action for unmatched URLs")
        void usesDefaultActionForUnmatched() {
            LibreProtectLogger.setVerbose(true);
            RouteRegistry registry = RouteRegistry.builder()
                .setDefaultAction(RouteActionType.BLOCK)
                .build();
            RouteResolver resolver = new RouteResolver(registry);

            EgressBlockedException ex = assertThrows(EgressBlockedException.class,
                () -> resolver.resolve(url("https://any.url.com/path")));

            assertEquals("default action", ex.getReason());
            assertTrue(testLogger.hasMessageContaining("using default action: BLOCK"));
        }

        @Test
        @DisplayName("should not log default action info when verbose logging disabled")
        void doesNotLogDefaultWhenNotVerbose() {
            LibreProtectLogger.setVerbose(false);
            RouteResolver resolver = new RouteResolver(RouteRegistry.builder().build());

            assertThrows(EgressBlockedException.class, () -> resolver.resolve(url("https://any.url.com/path")));

            assertFalse(testLogger.hasMessageContaining("default action"));
            assertTrue(testLogger.getRecords().isEmpty());
        }

        @Test
        @DisplayName("should log the normalized URL, not the original")
        void logsNormalizedUrl() {
            LibreProtectLogger.setVerbose(true);
            RouteResolver resolver = new RouteResolver(RouteRegistry.builder().build());

            assertThrows(EgressBlockedException.class,
                () -> resolver.resolve(url("HTTPS://user:secret@Any.Example/Path#frag")));

            assertTrue(testLogger.hasMessageContaining("URL 'https://any.example/Path'"));
            assertFalse(testLogger.hasMessageContaining("secret"));
        }

        @Test
        @DisplayName("should match multiple URLs correctly")
        void matchesMultipleUrlsCorrectly() throws IOException {
            RouteRegistry registry = RouteRegistry.builder()
                .addRoute("https?://stats\\.coreprotect\\.net/.*", RouteActionType.BLOCK)
                .addRoute("https?://coreprotect\\.net/translate/?", RouteActionType.ANSWER)
                .addRoute("https?://update\\.coreprotect\\.net/.*", RouteActionType.ANSWER)
                .setDefaultAction(RouteActionType.BLOCK)
                .build();
            RouteResolver resolver = new RouteResolver(registry);

            assertThrows(EgressBlockedException.class,
                () -> resolver.resolve(url("http://stats.coreprotect.net/submit")));
            assertInstanceOf(AnswerConnection.class,
                resolver.resolve(url("http://coreprotect.net/translate/")));
            assertInstanceOf(AnswerConnection.class,
                resolver.resolve(url("http://update.coreprotect.net/version/")));
            assertThrows(EgressBlockedException.class,
                () -> resolver.resolve(url("http://coreprotect.net/license/KEY")));
        }

        @Test
        @DisplayName("should answer with the actions it was given")
        void usesGivenActions() throws IOException {
            RecordingAnswer answer = RecordingAnswer.replying(Response.text("given"));
            RouteResolver resolver = new RouteResolver(RouteRegistry.builder()
                .setDefaultAction(RouteActionType.ANSWER).build(), new RouteActionFactory(answer));

            assertEquals("given", LocalHttpServer.read(resolver.resolve(MockUrlFactory.updateUrl())));
            assertEquals(1, answer.calls());
        }

        @Test
        @DisplayName("resolve(URL) should behave like resolve(URL, null)")
        void resolveWithoutProxy() throws IOException {
            RouteResolver resolver = new RouteResolver(RouteRegistry.builder()
                .setDefaultAction(RouteActionType.PASSTHROUGH).build());
            try (LocalHttpServer server = new LocalHttpServer()) {
                assertEquals("direct /a", LocalHttpServer.read(resolver.resolve(server.url("/a"))));
                assertEquals("direct /b", LocalHttpServer.read(resolver.resolve(server.url("/b"), null)));
            }
        }

        @Test
        @DisplayName("should pass the proxy to the action")
        void passesProxy() throws IOException {
            RouteResolver resolver = new RouteResolver(RouteRegistry.builder()
                .setDefaultAction(RouteActionType.PASSTHROUGH).build());
            try (LocalHttpServer server = new LocalHttpServer()) {
                URLConnection conn = resolver.resolve(server.url("/p"), server.asProxy());
                assertEquals("proxied " + server.getBaseUrl() + "/p", LocalHttpServer.read(conn));
            }
        }
    }

    @Nested
    @DisplayName("Normalized matching")
    class NormalizedMatching {

        private final RouteResolver resolver = new RouteResolver(RouteRegistry.builder()
            .addRoute("https://example\\.com/Path", RouteActionType.ANSWER)
            .setDefaultAction(RouteActionType.BLOCK)
            .build());

        @Test
        @DisplayName("should match a mixed-case scheme and host against a lowercase pattern")
        void mixedCaseHost() throws IOException {
            assertInstanceOf(AnswerConnection.class, resolver.resolve(url("HTTPS://EXAMPLE.Com/Path")));
        }

        @Test
        @DisplayName("should keep the path case-sensitive")
        void pathCaseSensitive() {
            EgressBlockedException ex = assertThrows(EgressBlockedException.class,
                () -> resolver.resolve(url("https://example.com/path")));
            assertEquals("default action", ex.getReason());
        }

        @Test
        @DisplayName("should ignore user info when matching")
        void ignoresUserInfo() throws IOException {
            assertInstanceOf(AnswerConnection.class, resolver.resolve(url("https://user:pw@example.com/Path")));
        }

        @Test
        @DisplayName("should ignore the fragment when matching")
        void ignoresFragment() throws IOException {
            assertInstanceOf(AnswerConnection.class, resolver.resolve(url("https://example.com/Path#anchor")));
        }

        @Test
        @DisplayName("should include the query when matching")
        void includesQuery() {
            assertThrows(EgressBlockedException.class, () -> resolver.resolve(url("https://example.com/Path?x=1")));
        }
    }

    @Nested
    @DisplayName("Getters")
    class Getters {

        @Test
        @DisplayName("getRegistry() should return the registry")
        void returnsRegistry() {
            RouteRegistry registry = RouteRegistry.builder().build();
            RouteResolver resolver = new RouteResolver(registry);

            assertSame(registry, resolver.getRegistry());
        }
    }

    @Nested
    @DisplayName("Integration with presets")
    class PresetIntegration {

        @Test
        @DisplayName("should work with PRIVACY_FIRST preset")
        void worksWithPrivacyFirstPreset() throws IOException {
            RouteConfigParser parser = new RouteConfigParser();
            RouteRegistry registry = parser.buildRegistry(RoutePreset.PRIVACY_FIRST, null);
            RouteResolver resolver = new RouteResolver(registry);

            // Translations are answered, which fails until translations are bundled
            URLConnection translation = resolver.resolve(MockUrlFactory.translateUrl());
            assertInstanceOf(AnswerConnection.class, translation);
            IOException failure = assertThrows(IOException.class, translation::connect);
            assertFalse(failure instanceof EgressBlockedException);

            // Every other known endpoint is blocked by its own route
            for (URL url : new URL[]{
                MockUrlFactory.statsUrl(),
                MockUrlFactory.licenseUrl(),
                MockUrlFactory.httpsLicenseUrl(),
                MockUrlFactory.updateUrl(),
                MockUrlFactory.updateEdgeUrl(),
                MockUrlFactory.errorReportingUrl(),
                MockUrlFactory.bstatsUrl()
            }) {
                EgressBlockedException ex = assertThrows(EgressBlockedException.class, () -> resolver.resolve(url));
                assertTrue(ex.getReason().startsWith("route "), url + ": " + ex.getReason());
            }

            // Anything else is blocked by the default action
            EgressBlockedException ex = assertThrows(EgressBlockedException.class,
                () -> resolver.resolve(MockUrlFactory.unknownUrl()));
            assertEquals("default action", ex.getReason());
        }

        @Test
        @DisplayName("should work with ALLOW_UPDATES preset")
        void worksWithAllowUpdatesPreset() throws IOException {
            RouteConfigParser parser = new RouteConfigParser();
            RouteRegistry registry = parser.buildRegistry(RoutePreset.ALLOW_UPDATES, null);
            RouteResolver resolver = new RouteResolver(registry);

            // Stats should still be blocked
            assertThrows(EgressBlockedException.class, () -> resolver.resolve(MockUrlFactory.statsUrl()));

            // License should be blocked
            assertThrows(EgressBlockedException.class, () -> resolver.resolve(MockUrlFactory.licenseUrl()));

            // Updates and translations are answered
            URLConnection update = resolver.resolve(MockUrlFactory.createUrl("HTTP://Update.CoreProtect.net/version/"));
            update.setRequestProperty("User-Agent", "CoreProtect/v24.1 (by Intelli)");
            assertEquals("24.1", LocalHttpServer.read(update));
            assertInstanceOf(AnswerConnection.class, resolver.resolve(MockUrlFactory.translateUrl()));
        }

        @Test
        @DisplayName("should work with PASSTHROUGH preset")
        void worksWithPassthroughPreset() throws IOException {
            RouteRegistry registry = new RouteConfigParser().buildRegistry(RoutePreset.PASSTHROUGH, null);
            RouteResolver resolver = new RouteResolver(registry);

            try (LocalHttpServer server = new LocalHttpServer()) {
                assertEquals("direct /anything", LocalHttpServer.read(resolver.resolve(server.url("/anything"))));
            }
        }
    }
}
