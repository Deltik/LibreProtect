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
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class ModrinthSourceTest {

    private final UpdateHttp http = new UpdateHttp(2_000, 2_000, 5_000);

    private Optional<Release> newest(int status, String body) throws IOException {
        try (LocalHttpServer server = new LocalHttpServer(exchange -> LocalHttpServer.respond(exchange, status, body))) {
            return new ModrinthSource("libreprotect", server.getBaseUrl() + "/v2").newestRelease(http);
        }
    }

    private static String version(String number, String type) {
        return "{\"id\":\"x\",\"version_number\":\"" + number + "\",\"version_type\":\"" + type + "\","
            + "\"status\":\"listed\",\"loaders\":[\"paper\"],\"files\":[{\"url\":\"https://cdn.example/a.jar\"}]}";
    }

    @Test
    @DisplayName("should ask for the project's versions without changelogs, as JSON, identifying only LibreProtect")
    void request() throws IOException {
        try (LocalHttpServer server = new LocalHttpServer(exchange -> LocalHttpServer.respond(exchange, 200, "[]"))) {
            new ModrinthSource("libreprotect", server.getBaseUrl() + "/v2").newestRelease(http);

            LocalHttpServer.Received request = server.getReceived().get(0);
            assertEquals("GET", request.method());
            assertEquals("/v2/project/libreprotect/version?include_changelog=false", request.uri().toString());
            assertEquals("application/json", request.header("Accept"));
            assertEquals(UpdateHttp.USER_AGENT, request.header("User-Agent"));
            assertEquals(4, request.headers().size(), request.headers().toString());
        }
    }

    @Test
    @DisplayName("should pick the highest release, whatever the order, and link to its page")
    void highestRelease() throws IOException {
        Optional<Release> release = newest(200, "[" + String.join(",",
            version("24.1-libre2", "release"),
            version("24.1-libre10", "release"),
            version("24.1-libre9", "release"),
            version("23.0-libre40", "release")) + "]");

        assertEquals("24.1-libre10", release.orElseThrow().version().toString());
        assertEquals("https://modrinth.com/plugin/libreprotect/version/24.1-libre10", release.orElseThrow().pageUrl());
    }

    @Test
    @DisplayName("should ignore betas, alphas, unlisted versions and versions that aren't LibreProtect releases")
    void ignoresOthers() throws IOException {
        Optional<Release> release = newest(200, "[" + String.join(",",
            version("24.1-libre9", "beta"),
            version("24.1-libre8", "alpha"),
            version("24.1-5-gabc1234-libre-dev", "release"),
            version("25.0", "release"),
            version("§c24.1-libre7", "release"),
            "{\"version_number\":\"24.1-libre6\",\"version_type\":\"release\",\"status\":\"archived\"}",
            "{\"version_number\":\"24.1-libre5\",\"version_type\":\"release\",\"status\":\"draft\"}",
            "{\"version_number\":24.1,\"version_type\":\"release\"}",
            "{\"version_type\":\"release\"}",
            "{\"version_number\":[\"24.1-libre4\"],\"version_type\":\"release\"}",
            "\"24.1-libre3\"",
            "null",
            "[]",
            version("24.1-libre2", "release")) + "]");

        assertEquals("24.1-libre2", release.orElseThrow().version().toString());
    }

    @Test
    @DisplayName("should accept a release without a status")
    void noStatus() throws IOException {
        assertEquals("24.1-libre2", newest(200, "[{\"version_number\":\"24.1-libre2\",\"version_type\":\"release\"}]")
            .orElseThrow().version().toString());
    }

    @Test
    @DisplayName("should answer no release for an empty list or one without releases")
    void noRelease() throws IOException {
        assertEquals(Optional.empty(), newest(200, "[]"));
        assertEquals(Optional.empty(), newest(200, "[" + version("24.1-libre2", "beta") + "]"));
    }

    @ParameterizedTest
    @DisplayName("should fail for statuses other than 200, such as a project that isn't approved or a rate limit")
    @ValueSource(ints = {404, 403, 429, 500, 410})
    void failsForStatus(int status) {
        IOException e = assertThrows(IOException.class, () -> newest(status, "{\"error\":\"not_found\"}"));
        assertTrue(e.getMessage().startsWith("HTTP " + status), e.getMessage());
    }

    @ParameterizedTest
    @DisplayName("should fail for responses that aren't a JSON list of versions")
    @ValueSource(strings = {"", "not json", "{\"error\":\"x\"}", "[{\"version_number\":\"24.1-libre2\"", "[] []",
        "[{\"version_number\":\"24.1-libre2\",}]", "\"24.1-libre2\"", "null", "<html>Rate limited</html>"})
    void failsForMalformed(String body) {
        IOException e = assertThrows(IOException.class, () -> newest(200, body));
        assertTrue(e.getMessage().startsWith("malformed response"), e.getMessage());
    }

    @Test
    @DisplayName("should read past deeply nested values it doesn't need")
    void deeplyNested() throws IOException {
        String nested = "[".repeat(100_000) + "]".repeat(100_000);
        String body = "[{\"files\":" + nested + ",\"version_number\":\"24.1-libre2\",\"version_type\":\"release\"}]";

        try {
            assertEquals("24.1-libre2", newest(200, body).orElseThrow().version().toString());
        } catch (IOException e) {
            // Newer Gson limits nesting, which fails the source the same way as other malformed responses
            assertTrue(e.getMessage().startsWith("malformed response"), e.getMessage());
        }
    }

    @Test
    @DisplayName("should fail, not recurse, for a huge nested value")
    void hugeNesting() {
        String body = "[".repeat(UpdateHttp.MAX_RESPONSE_BYTES - 10);
        assertThrows(IOException.class, () -> newest(200, body));
    }

    @Test
    @DisplayName("should describe itself by project")
    void describes() {
        ModrinthSource source = new ModrinthSource("libreprotect", ModrinthSource.DEFAULT_API);
        assertEquals("modrinth", source.type());
        assertEquals("Modrinth project libreprotect", source.describe());
        assertEquals("Modrinth project libreprotect at https://api.modrinth.com/v2", source.toString());
    }

    @Test
    @DisplayName("should be equal by project and API")
    void equality() {
        assertEquals(new ModrinthSource("a", "https://x"), new ModrinthSource("a", "https://x"));
        assertEquals(new ModrinthSource("a", "https://x").hashCode(), new ModrinthSource("a", "https://x").hashCode());
        assertNotEquals(new ModrinthSource("a", "https://x"), new ModrinthSource("b", "https://x"));
        assertNotEquals(new ModrinthSource("a", "https://x"), new ModrinthSource("a", "https://y"));
        assertNotEquals(new ModrinthSource("a/b", "https://x"), new GitHubSource("a/b", "https://x"));
    }
}
