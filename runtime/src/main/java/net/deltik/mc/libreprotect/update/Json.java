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

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Reads update sources' JSON responses with Gson's streaming reader, which the
 * server provides.
 *
 * <p>Values that aren't needed are skipped without being built, and the
 * streaming reader doesn't recurse, so deeply nested or oversized parts of a
 * response cost no more than reading past them.
 */
final class Json {

    /** Reads the expected value from a response */
    @FunctionalInterface
    interface Reader<T> {
        T read(JsonReader reader) throws IOException;
    }

    private Json() {
    }

    /**
     * Read a whole response.
     *
     * @throws IOException if the response isn't JSON of the expected shape
     */
    static <T> T parse(String body, Reader<T> reader) throws IOException {
        try (JsonReader json = new JsonReader(new StringReader(body))) {
            T value = reader.read(json);
            if (json.peek() != JsonToken.END_DOCUMENT) {
                throw new IOException("unexpected data after the JSON value");
            }
            return value;
        } catch (IOException | RuntimeException e) {
            throw new IOException("malformed response: " + e.getMessage(), e);
        }
    }

    /**
     * Read an object and keep its string, number and boolean members with
     * the given names, as text. Other members are skipped.
     */
    static Map<String, String> scalars(JsonReader reader, Set<String> names) throws IOException {
        Map<String, String> values = new HashMap<>();
        reader.beginObject();
        while (reader.hasNext()) {
            String name = reader.nextName();
            JsonToken token = reader.peek();
            if (!names.contains(name)) {
                reader.skipValue();
            } else if (token == JsonToken.STRING || token == JsonToken.NUMBER) {
                values.put(name, reader.nextString());
            } else if (token == JsonToken.BOOLEAN) {
                values.put(name, String.valueOf(reader.nextBoolean()));
            } else {
                reader.skipValue();
                values.remove(name);
            }
        }
        reader.endObject();
        return values;
    }
}
