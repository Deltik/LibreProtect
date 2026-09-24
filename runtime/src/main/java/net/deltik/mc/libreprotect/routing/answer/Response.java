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

import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * The reply that an {@link Answer} gives: an HTTP status, a content type and
 * a body.
 */
public final class Response {

    static final String TEXT = "text/plain; charset=utf-8";
    static final String JSON = "application/json; charset=utf-8";

    private final int status;
    private final String contentType;
    private final byte[] body;

    /**
     * @param status an HTTP status code from 100 to 599
     */
    public Response(int status, String contentType, byte[] body) {
        if (status < 100 || status > 599) {
            throw new IllegalArgumentException("Not an HTTP status code: " + status);
        }
        this.status = status;
        this.contentType = Objects.requireNonNull(contentType, "contentType");
        this.body = body.clone();
    }

    /**
     * @return a 200 OK reply with a UTF-8 plain text body
     */
    public static Response text(String body) {
        return new Response(HttpURLConnection.HTTP_OK, TEXT, body.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * @return a 200 OK reply with a UTF-8 JSON body
     */
    public static Response json(String body) {
        return new Response(HttpURLConnection.HTTP_OK, JSON, body.getBytes(StandardCharsets.UTF_8));
    }

    public int status() {
        return status;
    }

    public String contentType() {
        return contentType;
    }

    /**
     * @return a copy of the body
     */
    public byte[] body() {
        return body.clone();
    }
}
