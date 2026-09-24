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
import net.deltik.mc.libreprotect.routing.answer.Response;
import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import net.deltik.mc.libreprotect.testutil.RecordingAnswer;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.junit.jupiter.api.*;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AnswerActionTest {

    private AnswerAction action;
    private TestLogger testLogger;
    private final RouteRegistry.RouteMatch match =
        RouteRegistry.RouteMatch.of(new Route(".*", RouteActionType.ANSWER), Map.of());

    @BeforeEach
    void setUp() {
        action = new AnswerAction();
        testLogger = new TestLogger();
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(testLogger);
    }

    @AfterEach
    void tearDown() {
        LibreProtectLogger.reset();
    }

    private static String read(URLConnection conn) throws IOException {
        try (InputStream is = conn.getInputStream()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    @DisplayName("getType() should return ANSWER")
    void getTypeReturnsAnswer() {
        assertEquals(RouteActionType.ANSWER, action.getType());
    }

    @Nested
    @DisplayName("createConnection")
    class CreateConnection {

        @Test
        @DisplayName("should return an AnswerConnection")
        void returnsAnswerConnection() throws IOException {
            URLConnection conn = action.createConnection(MockUrlFactory.updateUrl(), null, match);

            assertInstanceOf(AnswerConnection.class, conn);
        }

        @Test
        @DisplayName("should return a connection for the requested URL")
        void connectionForRequestedUrl() throws IOException {
            URL url = MockUrlFactory.updateUrl();
            assertSame(url, action.createConnection(url, null, match).getURL());
        }

        @Test
        @DisplayName("should satisfy both HttpURLConnection and HttpsURLConnection casts")
        void satisfiesBothCasts() throws IOException {
            URLConnection conn = action.createConnection(MockUrlFactory.httpsStatsUrl(), null, match);

            assertInstanceOf(HttpURLConnection.class, conn);
            assertInstanceOf(HttpsURLConnection.class, conn);
        }

        @Test
        @DisplayName("should log the answered URL when verbose logging enabled")
        void logsAnsweredUrlWhenVerbose() throws IOException {
            LibreProtectLogger.setVerbose(true);

            action.createConnection(MockUrlFactory.updateUrl(), null, match);

            assertTrue(testLogger.hasMessageContaining("Answering"));
            assertTrue(testLogger.hasMessageContaining("update.coreprotect.net"));
        }

        @Test
        @DisplayName("should NOT log the answered URL when verbose logging disabled")
        void doesNotLogAnsweredUrlWhenNotVerbose() throws IOException {
            LibreProtectLogger.setVerbose(false);

            action.createConnection(MockUrlFactory.updateUrl(), null, match);

            assertFalse(testLogger.hasMessageContaining("Answering"));
            assertTrue(testLogger.getRecords().isEmpty());
        }

        @Test
        @DisplayName("should log the normalized URL without user info")
        void logsNormalizedUrl() throws IOException {
            LibreProtectLogger.setVerbose(true);

            action.createConnection(
                MockUrlFactory.createUrl("http://user:secret@Update.CoreProtect.net/version/#x"), null, match);

            assertTrue(testLogger.hasMessageContaining("Answering: http://update.coreprotect.net/version/"));
            assertFalse(testLogger.hasMessageContaining("secret"));
        }

        @Test
        @DisplayName("should refuse to produce a license response")
        void refusesLicense() throws IOException {
            // Creating the connection succeeds, but it never yields a license
            // that CoreProtect could save to .license
            URLConnection conn = action.createConnection(MockUrlFactory.licenseUrl("TESTKEY"), null, match);

            assertInstanceOf(AnswerConnection.class, conn);
            assertThrows(IOException.class, conn::getInputStream);
        }

        @Test
        @DisplayName("should fail translation requests, since no translations are bundled yet")
        void failsTranslateEndpoint() throws IOException {
            URLConnection conn = action.createConnection(MockUrlFactory.translateUrl(), null, match);

            assertInstanceOf(AnswerConnection.class, conn);
            assertThrows(IOException.class, conn::connect);
        }

        @Test
        @DisplayName("should work for update endpoint")
        void worksForUpdateEndpoint() throws IOException {
            URLConnection conn = action.createConnection(MockUrlFactory.updateUrl(), null, match);
            conn.setRequestProperty("User-Agent", "CoreProtect/v23.1 (by Intelli)");

            assertInstanceOf(AnswerConnection.class, conn);
            assertEquals("23.1", read(conn));
        }

        @Test
        @DisplayName("should work for stats endpoint")
        void worksForStatsEndpoint() throws IOException {
            assertEquals("", read(action.createConnection(MockUrlFactory.statsUrl(), null, match)));
        }

        @Test
        @DisplayName("should return a fresh connection each time")
        void freshConnection() throws IOException {
            URL url = MockUrlFactory.updateUrl();
            assertNotSame(action.createConnection(url, null, match), action.createConnection(url, null, match));
        }
    }

    @Nested
    @DisplayName("Given Answer")
    class GivenAnswer {

        private final RecordingAnswer answer = RecordingAnswer.replying(Response.text("answered"));
        private final AnswerAction given = new AnswerAction(answer);

        @Test
        @DisplayName("should answer with the answer it was given")
        void answersWithGivenAnswer() throws IOException {
            URL url = MockUrlFactory.createUrl("https://example.com/anything");

            assertEquals("answered", read(given.createConnection(url, null, match)));
            assertSame(url, answer.lastRequest().url());
        }

        @Test
        @DisplayName("should not ask the answer until the connection needs a reply")
        void doesNotAskEarly() throws IOException {
            given.createConnection(MockUrlFactory.updateUrl(), null, match);
            assertEquals(0, answer.calls());
        }

        @Test
        @DisplayName("should require an answer")
        void requiresAnswer() {
            assertThrows(NullPointerException.class, () -> new AnswerAction(null));
        }
    }
}
