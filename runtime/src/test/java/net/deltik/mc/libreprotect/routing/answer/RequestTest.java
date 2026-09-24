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

import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import org.junit.jupiter.api.*;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RequestTest {

    private final URL url = MockUrlFactory.translateUrl();

    @Nested
    @DisplayName("Accessors")
    class Accessors {

        @Test
        @DisplayName("should return the URL and method it was built with")
        void urlAndMethod() {
            Request request = new Request(url, "POST", Map.of(), new byte[0]);
            assertSame(url, request.url());
            assertEquals("POST", request.method());
        }

        @Test
        @DisplayName("should return the body it was built with")
        void body() {
            Request request = new Request(url, "POST", Map.of(), "data={}".getBytes(StandardCharsets.UTF_8));
            assertEquals("data={}", new String(request.body(), StandardCharsets.UTF_8));
        }

        @Test
        @DisplayName("should allow an empty body")
        void emptyBody() {
            assertEquals(0, new Request(url, "GET", Map.of(), new byte[0]).body().length);
        }

        @Test
        @DisplayName("should require a URL, a method, headers and a body")
        void requiresArguments() {
            assertThrows(NullPointerException.class, () -> new Request(null, "GET", Map.of(), new byte[0]));
            assertThrows(NullPointerException.class, () -> new Request(url, null, Map.of(), new byte[0]));
            assertThrows(NullPointerException.class, () -> new Request(url, "GET", null, new byte[0]));
            assertThrows(NullPointerException.class, () -> new Request(url, "GET", Map.of(), null));
        }
    }

    @Nested
    @DisplayName("Headers")
    class Headers {

        private final Request request = new Request(url, "GET",
            Map.of("User-Agent", "CoreProtect/v24.1 (by Intelli)", "Accept-Charset", "UTF-8"), new byte[0]);

        @Test
        @DisplayName("header() should find a header whatever the case of its name")
        void headerCaseInsensitive() {
            assertEquals("CoreProtect/v24.1 (by Intelli)", request.header("User-Agent"));
            assertEquals("CoreProtect/v24.1 (by Intelli)", request.header("user-agent"));
            assertEquals("UTF-8", request.header("ACCEPT-CHARSET"));
        }

        @Test
        @DisplayName("header() should return null for a missing or null name")
        void headerMissing() {
            assertNull(request.header("Content-Type"));
            assertNull(request.header(null));
        }

        @Test
        @DisplayName("headers() should be case-insensitive too")
        void headersCaseInsensitive() {
            assertEquals("UTF-8", request.headers().get("accept-charset"));
            assertTrue(request.headers().containsKey("USER-AGENT"));
            assertEquals(2, request.headers().size());
        }

        @Test
        @DisplayName("headers() should be unmodifiable")
        void headersUnmodifiable() {
            assertThrows(UnsupportedOperationException.class, () -> request.headers().put("X", "y"));
        }

        @Test
        @DisplayName("should let a later header win over an earlier one that differs only in case")
        void laterHeaderWins() {
            Map<String, String> headers = new java.util.LinkedHashMap<>();
            headers.put("user-agent", "first");
            headers.put("User-Agent", "second");
            assertEquals("second", new Request(url, "GET", headers, new byte[0]).header("User-Agent"));
        }
    }

    @Nested
    @DisplayName("Immutability")
    class Immutability {

        @Test
        @DisplayName("should copy the headers it was built with")
        void copiesHeaders() {
            Map<String, String> headers = new HashMap<>();
            headers.put("User-Agent", "before");
            Request request = new Request(url, "GET", headers, new byte[0]);
            headers.put("User-Agent", "after");

            assertEquals("before", request.header("User-Agent"));
        }

        @Test
        @DisplayName("should copy the body it was built with")
        void copiesBodyIn() {
            byte[] body = {1, 2, 3};
            Request request = new Request(url, "POST", Map.of(), body);
            body[0] = 9;

            assertArrayEquals(new byte[]{1, 2, 3}, request.body());
        }

        @Test
        @DisplayName("body() should return a copy")
        void copiesBodyOut() {
            Request request = new Request(url, "POST", Map.of(), new byte[]{1, 2, 3});
            request.body()[0] = 9;

            assertArrayEquals(new byte[]{1, 2, 3}, request.body());
        }
    }
}
