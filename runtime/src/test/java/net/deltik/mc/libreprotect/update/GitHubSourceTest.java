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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class GitHubSourceTest {

    private final UpdateHttp http = new UpdateHttp(2_000, 2_000, 5_000);

    private Optional<Release> newest(int status, String body) throws IOException {
        try (LocalHttpServer server = new LocalHttpServer(exchange -> LocalHttpServer.respond(exchange, status, body))) {
            return new GitHubSource("Deltik/LibreProtect", server.getBaseUrl()).newestRelease(http);
        }
    }

    private static String release(String tag, String htmlUrl) {
        return "{\"url\":\"https://api.github.com/repos/Deltik/LibreProtect/releases/1\",\"tag_name\":\"" + tag + "\","
            + "\"html_url\":\"" + htmlUrl + "\",\"draft\":false,\"prerelease\":false,"
            + "\"author\":{\"login\":\"Deltik\"},\"assets\":[{\"name\":\"LibreProtect.jar\",\"size\":1}]}";
    }

    @Test
    @DisplayName("should ask for the latest release with GitHub's media type and API version, identifying only LibreProtect")
    void request() throws IOException {
        try (LocalHttpServer server = new LocalHttpServer(exchange -> LocalHttpServer.respond(exchange, 200, "{}"))) {
            new GitHubSource("Deltik/LibreProtect", server.getBaseUrl()).newestRelease(http);

            LocalHttpServer.Received request = server.getReceived().get(0);
            assertEquals("GET", request.method());
            assertEquals("/repos/Deltik/LibreProtect/releases/latest", request.uri().toString());
            assertEquals("application/vnd.github+json", request.header("Accept"));
            assertEquals("2022-11-28", request.header("X-GitHub-Api-Version"));
            assertEquals(UpdateHttp.USER_AGENT, request.header("User-Agent"));
            assertEquals(5, request.headers().size(), request.headers().toString());
        }
    }

    @Test
    @DisplayName("should read the version from the tag and link to the release page")
    void latestRelease() throws IOException {
        Release release = newest(200,
            release("v24.1-libre2", "https://github.com/Deltik/LibreProtect/releases/tag/v24.1-libre2")).orElseThrow();

        assertEquals("24.1-libre2", release.version().toString());
        assertEquals("https://github.com/Deltik/LibreProtect/releases/tag/v24.1-libre2", release.pageUrl());
    }

    @Test
    @DisplayName("should follow GitHub's redirect for a renamed repository within its API")
    void renamedRepository() throws IOException {
        try (LocalHttpServer server = new LocalHttpServer(exchange -> {
            if (exchange.getRequestURI().getPath().startsWith("/repos/")) {
                exchange.getResponseHeaders().set("Location", "http://127.0.0.1:" + exchange.getLocalAddress().getPort()
                    + "/repositories/123/releases/latest");
                LocalHttpServer.respond(exchange, 301, "{\"message\":\"Moved Permanently\"}");
            } else {
                LocalHttpServer.respond(exchange, 200, release("v24.1-libre2",
                    "https://github.com/Deltik/LibreProtect/releases/tag/v24.1-libre2"));
            }
        })) {
            Release release = new GitHubSource("Deltik/Old", server.getBaseUrl()).newestRelease(http).orElseThrow();

            assertEquals("24.1-libre2", release.version().toString());
            assertEquals(List.of("/repos/Deltik/Old/releases/latest", "/repositories/123/releases/latest"),
                server.getRequests().stream().map(Object::toString).toList());
        }
    }

    @Test
    @DisplayName("should accept a tag without the leading v")
    void tagWithoutV() throws IOException {
        assertEquals("24.1-libre2", newest(200, release("24.1-libre2",
            "https://github.com/Deltik/LibreProtect/releases/tag/24.1-libre2")).orElseThrow().version().toString());
    }

    @Test
    @DisplayName("should build the release page from the tag when the given one is too long to show")
    void buildsPageForLongLink() throws IOException {
        String htmlUrl = "https://github.com/Deltik/LibreProtect/releases/tag/v24.1-libre2/" + "x".repeat(200);

        assertEquals("https://github.com/Deltik/LibreProtect/releases/tag/v24.1-libre2",
            newest(200, release("v24.1-libre2", htmlUrl)).orElseThrow().pageUrl());
    }

    @ParameterizedTest
    @DisplayName("should build the release page from the tag when the given one isn't a plain github.com link")
    @ValueSource(strings = {"http://github.com/Deltik/LibreProtect/releases/tag/v24.1-libre2",
        "https://evil.example/releases/tag/v24.1-libre2", "https://github.com.evil.example/x",
        "https://github.com/Deltik/LibreProtect/releases/tag/v24.1-libre2?x=§c", "https://github.com/a b", ""})
    void buildsPage(String htmlUrl) throws IOException {
        assertEquals("https://github.com/Deltik/LibreProtect/releases/tag/v24.1-libre2",
            newest(200, release("v24.1-libre2", htmlUrl)).orElseThrow().pageUrl());
        assertEquals("https://github.com/Deltik/LibreProtect/releases/tag/v24.1-libre2",
            newest(200, "{\"tag_name\":\"v24.1-libre2\"}").orElseThrow().pageUrl());
    }

    @ParameterizedTest
    @DisplayName("should answer no release for drafts, prereleases and tags that aren't LibreProtect releases")
    @CsvSource(delimiter = '|', value = {
        "{\"tag_name\":\"v24.1-libre2\",\"draft\":true}",
        "{\"tag_name\":\"v24.1-libre2\",\"prerelease\":true}",
        "{\"tag_name\":\"v24.1-5-gabc1234-libre-dev\"}",
        "{\"tag_name\":\"vv24.1-libre2\"}",
        "{\"tag_name\":\"24.1\"}",
        "{\"tag_name\":null}",
        "{\"tag_name\":{\"name\":\"v24.1-libre2\"}}",
        "{}"
    })
    void noRelease(String body) throws IOException {
        assertEquals(Optional.empty(), newest(200, body));
    }

    @ParameterizedTest
    @DisplayName("should fail for statuses other than 200, such as a missing repository or a rate limit")
    @ValueSource(ints = {404, 403, 429, 500})
    void failsForStatus(int status) {
        IOException e = assertThrows(IOException.class,
            () -> newest(status, "{\"message\":\"Not Found\",\"documentation_url\":\"https://docs.github.com\"}"));
        assertTrue(e.getMessage().startsWith("HTTP " + status), e.getMessage());
    }

    @ParameterizedTest
    @DisplayName("should fail for responses that aren't a JSON object")
    @ValueSource(strings = {"", "[]", "not json", "{\"tag_name\":\"v24.1-libre2\"", "{} {}", "\"v24.1-libre2\""})
    void failsForMalformed(String body) {
        IOException e = assertThrows(IOException.class, () -> newest(200, body));
        assertTrue(e.getMessage().startsWith("malformed response"), e.getMessage());
    }

    @Test
    @DisplayName("should describe itself by repository")
    void describes() {
        GitHubSource source = new GitHubSource("Deltik/LibreProtect", GitHubSource.DEFAULT_API);
        assertEquals("github", source.type());
        assertEquals("Deltik/LibreProtect", source.repository());
        assertEquals("GitHub repository Deltik/LibreProtect", source.describe());
        assertEquals("GitHub repository Deltik/LibreProtect at https://api.github.com", source.toString());
    }
}
