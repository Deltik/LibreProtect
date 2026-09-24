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

import net.deltik.mc.libreprotect.testutil.LocalHttpServer;
import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import net.deltik.mc.libreprotect.update.TestUpdateStatus;
import net.deltik.mc.libreprotect.update.UpdateCheck;
import net.deltik.mc.libreprotect.update.UpdateSource;
import net.deltik.mc.libreprotect.update.UpdateSourceParser;
import net.deltik.mc.libreprotect.update.UpdateStatus;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class UpdateAnswerTest {

    private static final Map<String, String> CORE_PROTECT = Map.of("User-Agent", "CoreProtect/v24.1 (by Intelli)");

    @AfterEach
    void clearStatus() {
        TestUpdateStatus.reset();
    }

    private static String answer(UpdateAnswer answer, URL url, Map<String, String> headers) throws IOException {
        return new String(answer.answer(new Request(url, "GET", headers, new byte[0])).body(), StandardCharsets.UTF_8);
    }

    private static List<UpdateSource> modrinthAt(LocalHttpServer server) {
        return new UpdateSourceParser().parse(List.of(
            Map.of("type", "modrinth", "project", "libreprotect", "api", server.getBaseUrl() + "/v2")));
    }

    /** A Modrinth-like API that lists these versions as releases */
    private static LocalHttpServer modrinth(String... versions) throws IOException {
        StringBuilder body = new StringBuilder("[");
        for (String version : versions) {
            body.append(body.length() > 1 ? "," : "")
                .append("{\"version_number\":\"").append(version).append("\",\"version_type\":\"release\"}");
        }
        String json = body.append("]").toString();
        return new LocalHttpServer(exchange -> LocalHttpServer.respond(exchange, 200, json));
    }

    @Nested
    @DisplayName("Release check")
    class ReleaseCheck {

        @Test
        @DisplayName("should answer a version CoreProtect sees as newer, and record the release, when there is one")
        void newerRelease() throws IOException {
            try (LocalHttpServer server = modrinth("24.1-libre2", "24.1-libre1")) {
                UpdateAnswer answer = new UpdateAnswer(new UpdateCheck(modrinthAt(server), "24.1-libre1"));

                assertEquals("24.1.1", answer(answer, MockUrlFactory.updateUrl(), CORE_PROTECT));

                UpdateStatus.Known known = UpdateStatus.current();
                assertNotNull(known);
                assertEquals("24.1-libre2", known.version());
                assertEquals("24.1.1", known.syntheticVersion());
                assertEquals("modrinth.com/plugin/libreprotect/version/24.1-libre2", known.displayUrl());
            }
        }

        @Test
        @DisplayName("should answer the running upstream version, and forget an earlier release, when there is no newer one")
        void noNewerRelease() throws IOException {
            TestUpdateStatus.set("24.1-libre2", "https://modrinth.com/plugin/libreprotect/version/24.1-libre2", "24.1.1");
            try (LocalHttpServer server = modrinth("24.1-libre2")) {
                UpdateAnswer answer = new UpdateAnswer(new UpdateCheck(modrinthAt(server), "24.1-libre2"));

                assertEquals("24.1", answer(answer, MockUrlFactory.updateUrl(), CORE_PROTECT));
                assertNull(UpdateStatus.current());
            }
        }

        @Test
        @DisplayName("should fail, and keep the release it knew, when every source fails")
        void everySourceFails() throws IOException {
            TestUpdateStatus.set("24.1-libre2", "https://modrinth.com/plugin/libreprotect/version/24.1-libre2", "24.1.1");
            try (LocalHttpServer server = new LocalHttpServer(exchange -> LocalHttpServer.respond(exchange, 404, "{}"))) {
                UpdateAnswer answer = new UpdateAnswer(new UpdateCheck(modrinthAt(server), "24.1-libre1"));

                assertThrows(IOException.class, () -> answer(answer, MockUrlFactory.updateUrl(), CORE_PROTECT));
                assertEquals("24.1-libre2", UpdateStatus.current().version());
            }
        }

        @ParameterizedTest
        @DisplayName("should ask the sources for the release check with or without the final slash, in any case")
        @ValueSource(strings = {"http://update.coreprotect.net/version/", "http://update.coreprotect.net/version",
            "https://Update.CoreProtect.net/VERSION/"})
        void releaseCheckPaths(String url) throws IOException {
            try (LocalHttpServer server = modrinth("24.1-libre2")) {
                UpdateAnswer answer = new UpdateAnswer(new UpdateCheck(modrinthAt(server), "24.1-libre1"));

                assertEquals("24.1.1", answer(answer, MockUrlFactory.createUrl(url), CORE_PROTECT));
                assertEquals(1, server.getRequests().size());
            }
        }

        @Test
        @DisplayName("should work through an answer connection, as CoreProtect uses it")
        void throughConnection() throws IOException {
            try (LocalHttpServer server = modrinth("24.2-libre1")) {
                UpdateAnswer answer = new UpdateAnswer(new UpdateCheck(modrinthAt(server), "24.1-libre3"));
                AnswerConnection connection = new AnswerConnection(MockUrlFactory.updateUrl(), answer);
                connection.setRequestMethod("GET");
                connection.setRequestProperty("User-Agent", "CoreProtect/v24.1 (by Intelli)");
                connection.connect();

                assertEquals(HttpURLConnection.HTTP_OK, connection.getResponseCode());
                assertEquals("24.2", LocalHttpServer.read(connection));
            }
        }
    }

    @Nested
    @DisplayName("Without asking anyone")
    class Offline {

        @Test
        @DisplayName("should answer the edge check with no update, even when there is a newer release")
        void edgeCheck() throws IOException {
            try (LocalHttpServer server = modrinth("25.0-libre1")) {
                UpdateAnswer answer = new UpdateAnswer(new UpdateCheck(modrinthAt(server), "24.1-libre1"));

                assertEquals("24.1", answer(answer, MockUrlFactory.updateEdgeUrl(), CORE_PROTECT));
                assertEquals(List.of(), server.getRequests());
            }
        }

        @Test
        @DisplayName("should answer other paths with no update")
        void otherPaths() throws IOException {
            try (LocalHttpServer server = modrinth("25.0-libre1")) {
                UpdateAnswer answer = new UpdateAnswer(new UpdateCheck(modrinthAt(server), "24.1-libre1"));

                assertEquals("24.1", answer(answer, MockUrlFactory.createUrl("http://update.coreprotect.net/other"), Map.of()));
                assertEquals(List.of(), server.getRequests());
            }
        }

        @Test
        @DisplayName("should answer no update, and forget an earlier release, when update checks are off")
        void noSources() throws IOException {
            TestUpdateStatus.set("24.1-libre2", "https://modrinth.com/plugin/libreprotect/version/24.1-libre2", "24.1.1");
            UpdateAnswer answer = new UpdateAnswer(new UpdateCheck(List.of(), "24.1-libre1"));

            assertEquals("24.1", answer(answer, MockUrlFactory.updateUrl(), CORE_PROTECT));
            assertNull(UpdateStatus.current());
        }

        @Test
        @DisplayName("should not ask the sources when the running version isn't a LibreProtect version")
        void unknownRunningVersion() throws IOException {
            try (LocalHttpServer server = modrinth("25.0-libre1")) {
                UpdateAnswer answer = new UpdateAnswer(new UpdateCheck(modrinthAt(server), "unknown"));

                assertEquals("24.1", answer(answer, MockUrlFactory.updateUrl(), CORE_PROTECT));
                assertEquals(List.of(), server.getRequests());
            }
        }

        @Test
        @DisplayName("the answer without sources should reply 200 OK with plain text")
        void plainText() throws IOException {
            Response response = new UpdateAnswer().answer(
                new Request(MockUrlFactory.updateEdgeUrl(), "GET", Map.of(), new byte[0]));
            assertEquals(HttpURLConnection.HTTP_OK, response.status());
            assertTrue(response.contentType().startsWith("text/plain"), response.contentType());
        }
    }

    @Nested
    @DisplayName("No-update version when the running version is unknown")
    class UnknownRunningVersion {

        private final UpdateAnswer answer = new UpdateAnswer(new UpdateCheck(List.of(), "unknown"));

        @ParameterizedTest
        @DisplayName("should answer with the version in CoreProtect's User-Agent")
        @CsvSource(delimiter = '|', value = {
            "CoreProtect/v21.3 (by Intelli) | 21.3",
            "CoreProtect/v24.1 (by Intelli) | 24.1",
            "CoreProtect/v22.4              | 22.4"
        })
        void answersUserAgentVersion(String userAgent, String version) throws IOException {
            assertEquals(version, answer(answer, MockUrlFactory.updateUrl(), Map.of("User-Agent", userAgent)));
        }

        @Test
        @DisplayName("should find the User-Agent whatever the case of its name")
        void userAgentAnyCase() throws IOException {
            assertEquals("23.0", answer(answer, MockUrlFactory.updateUrl(),
                Map.of("user-agent", "CoreProtect/v23.0 (by Intelli)")));
        }

        @Test
        @DisplayName("should answer 0.0, so no update, without a User-Agent")
        void noUserAgent() throws IOException {
            assertEquals("0.0", answer(answer, MockUrlFactory.updateUrl(), Map.of()));
        }

        @ParameterizedTest
        @DisplayName("should answer 0.0 for a User-Agent without a version CoreProtect would read")
        @ValueSource(strings = {"Java/21", "CoreProtect", "CoreProtect/v", "CoreProtect/v (by Intelli)", "",
            "CoreProtect/v24 (by Intelli)", "CoreProtect/v24.1.1.1.1.1 (by Intelli)", "CoreProtect/v24.x (by Intelli)"})
        void noVersion(String userAgent) throws IOException {
            assertEquals("0.0", answer(answer, MockUrlFactory.updateUrl(), Map.of("User-Agent", userAgent)));
        }
    }
}
