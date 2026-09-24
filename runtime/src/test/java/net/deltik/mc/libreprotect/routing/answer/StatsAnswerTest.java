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

import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class StatsAnswerTest {

    @Test
    @DisplayName("should give an empty 200 OK reply, whatever was sent")
    void emptyReply() {
        Request request = new Request(MockUrlFactory.httpsStatsUrl(), "POST", Map.of(),
            "{\"players\":1}".getBytes(StandardCharsets.UTF_8));

        Response response = new StatsAnswer().answer(request);

        assertEquals(HttpURLConnection.HTTP_OK, response.status());
        assertEquals(0, response.body().length);
    }
}
