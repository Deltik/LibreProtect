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

package net.deltik.mc.libreprotect.routing.answer;

import net.deltik.mc.libreprotect.PrivacyConstants;
import net.deltik.mc.libreprotect.routing.answer.AnswerRegistry.Endpoint;
import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import net.deltik.mc.libreprotect.testutil.RecordingAnswer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.EnumMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AnswerRegistryTest {

    private static Request request(String spec) {
        return request(spec, Map.of());
    }

    private static Request request(String spec, Map<String, String> headers) {
        return new Request(MockUrlFactory.createUrl(spec), "GET", headers, new byte[0]);
    }

    private static String text(Response response) {
        return new String(response.body(), StandardCharsets.UTF_8);
    }

    @Nested
    @DisplayName("Endpoint.of")
    class EndpointOf {

        @ParameterizedTest
        @DisplayName("should recognize the translation endpoint")
        @ValueSource(strings = {
            "http://coreprotect.net/translate/",
            "https://coreprotect.net/translate",
            "HTTP://CoreProtect.NET/Translate/"
        })
        void translation(String spec) {
            assertEquals(Endpoint.TRANSLATION, Endpoint.of(MockUrlFactory.createUrl(spec)));
        }

        @ParameterizedTest
        @DisplayName("should recognize any path on the update host")
        @ValueSource(strings = {
            "http://update.coreprotect.net/version/",
            "http://update.coreprotect.net/version-edge/",
            "https://Update.CoreProtect.net/"
        })
        void update(String spec) {
            assertEquals(Endpoint.UPDATE, Endpoint.of(MockUrlFactory.createUrl(spec)));
        }

        @ParameterizedTest
        @DisplayName("should recognize any path on the statistics host")
        @ValueSource(strings = {
            "http://stats.coreprotect.net/u/?data=25565:",
            "https://stats.coreprotect.net/submit"
        })
        void stats(String spec) {
            assertEquals(Endpoint.STATS, Endpoint.of(MockUrlFactory.createUrl(spec)));
        }

        @ParameterizedTest
        @DisplayName("should recognize nothing else")
        @ValueSource(strings = {
            "http://coreprotect.net/license/TESTKEY",
            "https://error-reporting.coreprotect.net/submit",
            "https://bStats.org/api/v2/data/bukkit",
            "http://coreprotect.net/translate/extra",
            "http://coreprotect.net/",
            "https://stats.coreprotect.net.evil.example/u/",
            "https://unknown.example.com/path"
        })
        void nothingElse(String spec) {
            assertNull(Endpoint.of(MockUrlFactory.createUrl(spec)));
        }
    }

    @Nested
    @DisplayName("Dispatch")
    class Dispatch {

        private final RecordingAnswer translation = RecordingAnswer.replying(Response.json("{\"translated\":1}"));
        private final RecordingAnswer update = RecordingAnswer.replying(Response.text("99.0"));
        private final RecordingAnswer stats = RecordingAnswer.replying(Response.text("thanks"));
        private final AnswerRegistry registry = new AnswerRegistry(
            Map.of(Endpoint.TRANSLATION, translation, Endpoint.UPDATE, update, Endpoint.STATS, stats));

        @Test
        @DisplayName("should answer each endpoint with its own answer")
        void answersEachEndpoint() throws IOException {
            assertEquals("{\"translated\":1}", text(registry.answer(request("http://coreprotect.net/translate/"))));
            assertEquals("99.0", text(registry.answer(request("http://update.coreprotect.net/version/"))));
            assertEquals("thanks", text(registry.answer(request("http://stats.coreprotect.net/u/"))));

            assertEquals(1, translation.calls());
            assertEquals(1, update.calls());
            assertEquals(1, stats.calls());
        }

        @Test
        @DisplayName("should hand the request to the answer unchanged")
        void passesRequest() throws IOException {
            Request request = request("http://update.coreprotect.net/version/");
            registry.answer(request);
            assertSame(request, update.lastRequest());
        }

        @Test
        @DisplayName("answerFor() should return the endpoint's answer")
        void answerFor() throws IOException {
            assertSame(translation, registry.answerFor(MockUrlFactory.translateUrl()));
            assertSame(update, registry.answerFor(MockUrlFactory.updateEdgeUrl()));
            assertSame(stats, registry.answerFor(MockUrlFactory.httpsStatsUrl()));
        }

        @Test
        @DisplayName("should pass the answer's IOException through")
        void passesFailureThrough() {
            IOException failure = new IOException("offline");
            AnswerRegistry failing = new AnswerRegistry(Map.of(Endpoint.UPDATE, RecordingAnswer.failing(failure)));

            assertSame(failure, assertThrows(IOException.class,
                () -> failing.answer(request("http://update.coreprotect.net/version/"))));
        }

        @Test
        @DisplayName("should fail for an endpoint that has no answer")
        void failsWithoutAnswer() {
            AnswerRegistry updatesOnly = new AnswerRegistry(Map.of(Endpoint.UPDATE, update));

            IOException ex = assertThrows(IOException.class,
                () -> updatesOnly.answer(request("http://stats.coreprotect.net/u/")));
            assertTrue(ex.getMessage().contains("can't answer requests to http://stats.coreprotect.net/u/"),
                ex.getMessage());
            assertEquals(0, stats.calls());
        }

        @Test
        @DisplayName("should keep its own copy of the answers")
        void copiesAnswers() throws IOException {
            Map<Endpoint, Answer> answers = new EnumMap<>(Endpoint.class);
            answers.put(Endpoint.UPDATE, update);
            AnswerRegistry copied = new AnswerRegistry(answers);
            answers.put(Endpoint.STATS, stats);
            answers.remove(Endpoint.UPDATE);

            assertSame(update, copied.answerFor(MockUrlFactory.updateUrl()));
            assertThrows(IOException.class, () -> copied.answerFor(MockUrlFactory.statsUrl()));
        }
    }

    @Nested
    @DisplayName("Requests It Can't Answer")
    class Unanswerable {

        private final AnswerRegistry registry = AnswerRegistry.defaults();

        @Test
        @DisplayName("should tell the operator to BLOCK the URL instead and where to report it")
        void suggestsBlock() {
            IOException ex = assertThrows(IOException.class,
                () -> registry.answer(request("https://unknown.example.com/path")));

            assertEquals(PrivacyConstants.FORK_NAME + " can't answer requests to https://unknown.example.com/path"
                + "; use BLOCK for it instead. If upstream added this endpoint, please report it at "
                + PrivacyConstants.FORK_ISSUE_URL, ex.getMessage());
        }

        @ParameterizedTest
        @DisplayName("should never answer the license endpoint")
        @ValueSource(strings = {
            "http://coreprotect.net/license/TESTKEY",
            "https://CoreProtect.net/license/12345678"
        })
        void refusesLicense(String spec) {
            assertThrows(IOException.class, () -> registry.answer(request(spec)));
            assertThrows(IOException.class, () -> registry.answerFor(MockUrlFactory.createUrl(spec)));
        }

        @Test
        @DisplayName("should leave user info, the query and the fragment out of the message")
        void leavesOutUserInfoAndQuery() {
            IOException ex = assertThrows(IOException.class,
                () -> registry.answer(request("https://user:secret@unknown.example.com/path?key=hidden#frag")));

            assertFalse(ex.getMessage().contains("secret"), ex.getMessage());
            assertFalse(ex.getMessage().contains("hidden"), ex.getMessage());
            assertFalse(ex.getMessage().contains("frag"), ex.getMessage());
        }
    }

    @Nested
    @DisplayName("defaults")
    class Defaults {

        private final AnswerRegistry registry = AnswerRegistry.defaults();

        @Test
        @DisplayName("should use LibreProtect's own answer for each endpoint")
        void ownAnswers() throws IOException {
            assertInstanceOf(TranslationAnswer.class, registry.answerFor(MockUrlFactory.translateUrl()));
            assertInstanceOf(UpdateAnswer.class, registry.answerFor(MockUrlFactory.updateUrl()));
            assertInstanceOf(StatsAnswer.class, registry.answerFor(MockUrlFactory.statsUrl()));
        }

        @Test
        @DisplayName("should answer update checks with the running version")
        void answersUpdates() throws IOException {
            Response response = registry.answer(
                request("http://update.coreprotect.net/version/", Map.of("User-Agent", "CoreProtect/v24.1 (by Intelli)")));
            assertEquals("24.1", text(response));
        }

        @Test
        @DisplayName("should answer statistics with an empty reply")
        void answersStats() throws IOException {
            assertEquals("", text(registry.answer(request("http://stats.coreprotect.net/u/?data=1"))));
        }

        @Test
        @DisplayName("should fail translation requests, since no translations are bundled yet")
        void failsTranslations() {
            assertThrows(IOException.class, () -> registry.answer(request("http://coreprotect.net/translate/")));
        }
    }
}
