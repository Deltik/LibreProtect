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

package net.deltik.mc.libreprotect.testutil;

import net.deltik.mc.libreprotect.routing.answer.Answer;
import net.deltik.mc.libreprotect.routing.answer.Request;
import net.deltik.mc.libreprotect.routing.answer.Response;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * An answer for tests: it gives a fixed reply or fails with a fixed
 * exception, and records every request it is asked.
 */
public final class RecordingAnswer implements Answer {

    private final Response response;
    private final IOException failure;
    private final List<Request> requests = new ArrayList<>();

    private RecordingAnswer(Response response, IOException failure) {
        this.response = response;
        this.failure = failure;
    }

    public static RecordingAnswer replying(Response response) {
        return new RecordingAnswer(response, null);
    }

    public static RecordingAnswer failing(IOException failure) {
        return new RecordingAnswer(null, failure);
    }

    @Override
    public Response answer(Request request) throws IOException {
        requests.add(request);
        if (failure != null) {
            throw failure;
        }
        return response;
    }

    /**
     * @return how often the answer was asked
     */
    public int calls() {
        return requests.size();
    }

    /**
     * @return the request the answer was asked last
     */
    public Request lastRequest() {
        return requests.get(requests.size() - 1);
    }
}
