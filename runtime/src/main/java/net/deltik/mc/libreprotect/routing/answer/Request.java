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

import java.net.URL;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * A request as the caller built it on an {@link AnswerConnection}: the URL,
 * the method, the request properties and the bytes written to the output
 * stream.
 */
public final class Request {

    private final URL url;
    private final String method;
    private final Map<String, String> headers;
    private final byte[] body;

    /**
     * @param headers request properties; names are matched case-insensitively,
     *                and a later name wins over an earlier one that differs
     *                only in case
     * @param body    the request body, empty if the caller wrote none
     */
    public Request(URL url, String method, Map<String, String> headers, byte[] body) {
        this.url = Objects.requireNonNull(url, "url");
        this.method = Objects.requireNonNull(method, "method");
        Map<String, String> copy = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        copy.putAll(headers);
        this.headers = Collections.unmodifiableMap(copy);
        this.body = body.clone();
    }

    public URL url() {
        return url;
    }

    /**
     * @return the request method, such as {@code GET} or {@code POST}
     */
    public String method() {
        return method;
    }

    /**
     * @return the request properties, unmodifiable, with case-insensitive
     *         names
     */
    public Map<String, String> headers() {
        return headers;
    }

    /**
     * @return the value of the named request property, or {@code null} if it
     *         isn't set; the name is case-insensitive
     */
    public String header(String name) {
        return name == null ? null : headers.get(name);
    }

    /**
     * @return a copy of the request body, empty if the caller wrote none
     */
    public byte[] body() {
        return body.clone();
    }
}
