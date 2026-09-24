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

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class ResponseTest {

    @Nested
    @DisplayName("Factories")
    class Factories {

        @Test
        @DisplayName("text() should make a 200 OK plain text reply in UTF-8")
        void text() {
            Response response = Response.text("naïve");

            assertEquals(HttpURLConnection.HTTP_OK, response.status());
            assertEquals("text/plain; charset=utf-8", response.contentType());
            assertArrayEquals("naïve".getBytes(StandardCharsets.UTF_8), response.body());
        }

        @Test
        @DisplayName("text() should allow an empty body")
        void emptyText() {
            assertEquals(0, Response.text("").body().length);
        }

        @Test
        @DisplayName("json() should make a 200 OK JSON reply in UTF-8")
        void json() {
            Response response = Response.json("{\"a\":\"ü\"}");

            assertEquals(HttpURLConnection.HTTP_OK, response.status());
            assertEquals("application/json; charset=utf-8", response.contentType());
            assertEquals("{\"a\":\"ü\"}", new String(response.body(), StandardCharsets.UTF_8));
        }
    }

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("should keep the status, content type and body")
        void keepsValues() {
            Response response = new Response(HttpURLConnection.HTTP_NOT_FOUND, "text/html", new byte[]{1, 2});

            assertEquals(HttpURLConnection.HTTP_NOT_FOUND, response.status());
            assertEquals("text/html", response.contentType());
            assertArrayEquals(new byte[]{1, 2}, response.body());
        }

        @ParameterizedTest
        @DisplayName("should accept any HTTP status code")
        @ValueSource(ints = {100, 204, 302, 500, 599})
        void acceptsStatus(int status) {
            assertEquals(status, new Response(status, "text/plain", new byte[0]).status());
        }

        @ParameterizedTest
        @DisplayName("should reject a number that isn't an HTTP status code")
        @ValueSource(ints = {-1, 0, 99, 600, 1000})
        void rejectsStatus(int status) {
            assertThrows(IllegalArgumentException.class, () -> new Response(status, "text/plain", new byte[0]));
        }

        @Test
        @DisplayName("should require a content type and a body")
        void requiresArguments() {
            assertThrows(NullPointerException.class, () -> new Response(200, null, new byte[0]));
            assertThrows(NullPointerException.class, () -> new Response(200, "text/plain", null));
        }
    }

    @Nested
    @DisplayName("Immutability")
    class Immutability {

        @Test
        @DisplayName("should copy the body it was built with")
        void copiesBodyIn() {
            byte[] body = {1, 2, 3};
            Response response = new Response(200, "text/plain", body);
            body[0] = 9;

            assertArrayEquals(new byte[]{1, 2, 3}, response.body());
        }

        @Test
        @DisplayName("body() should return a copy")
        void copiesBodyOut() {
            Response response = Response.text("abc");
            response.body()[0] = 'x';

            assertEquals("abc", new String(response.body(), StandardCharsets.UTF_8));
        }
    }
}
