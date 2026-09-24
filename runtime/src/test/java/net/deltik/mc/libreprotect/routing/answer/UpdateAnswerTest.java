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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class UpdateAnswerTest {

    private final UpdateAnswer answer = new UpdateAnswer();

    private String answer(Map<String, String> headers) {
        Request request = new Request(MockUrlFactory.updateUrl(), "GET", headers, new byte[0]);
        return new String(answer.answer(request).body(), StandardCharsets.UTF_8);
    }

    @ParameterizedTest
    @DisplayName("should answer with the version in CoreProtect's User-Agent")
    @CsvSource(delimiter = '|', value = {
        "CoreProtect/v21.3 (by Intelli) | 21.3",
        "CoreProtect/v24.1 (by Intelli) | 24.1",
        "CoreProtect/v22.4              | 22.4"
    })
    void answersRunningVersion(String userAgent, String version) {
        assertEquals(version, answer(Map.of("User-Agent", userAgent)));
    }

    @Test
    @DisplayName("should find the User-Agent whatever the case of its name")
    void userAgentAnyCase() {
        assertEquals("23.0", answer(Map.of("user-agent", "CoreProtect/v23.0 (by Intelli)")));
    }

    @Test
    @DisplayName("should answer 0.0, so no update, without a User-Agent")
    void noUserAgent() {
        assertEquals("0.0", answer(Map.of()));
    }

    @ParameterizedTest
    @DisplayName("should answer 0.0 for a User-Agent without CoreProtect's version")
    @ValueSource(strings = {"Java/21", "CoreProtect", "CoreProtect/v", "CoreProtect/v (by Intelli)", ""})
    void noVersion(String userAgent) {
        assertEquals("0.0", answer(Map.of("User-Agent", userAgent)));
    }

    @Test
    @DisplayName("should answer with a 200 OK plain text reply")
    void plainText() {
        Response response = answer.answer(new Request(MockUrlFactory.updateEdgeUrl(), "GET", Map.of(), new byte[0]));
        assertEquals(HttpURLConnection.HTTP_OK, response.status());
        assertTrue(response.contentType().startsWith("text/plain"), response.contentType());
    }
}
