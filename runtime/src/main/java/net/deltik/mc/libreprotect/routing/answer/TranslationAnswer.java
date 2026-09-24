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

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.PrivacyConfig;
import net.deltik.mc.libreprotect.PrivacyConstants;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Answers CoreProtect's translation request from the translations that
 * LibreProtect bundles (see {@link TranslationBundle}), without a network
 * request.
 *
 * <p>CoreProtect posts {@code data=} and a JSON object of every phrase, by
 * phrase name, as the server shows it: CoreProtect's English, or the text
 * from {@code language.yml} where the server customized it. Two more keys
 * name the language and CoreProtect's version. CoreProtect writes each
 * {@code +} as {@code {PLUS_SIGN}} and encodes nothing else. The answer is a
 * JSON object of translated phrases, which CoreProtect shows right away and
 * saves to {@code plugins/CoreProtect/.language}.
 *
 * <p>The answer leaves out phrases that the server customized: those whose
 * text isn't CoreProtect's built-in English. CoreProtect has already applied
 * them from {@code language.yml}, and would otherwise show the bundled
 * translation instead until the next start. CoreProtect's cache loader keeps
 * them out of use by the same rule.
 *
 * <p>If no bundled language fits, the request fails, so CoreProtect stays in
 * English and saves no cache. An empty answer would be saved as a cache and
 * stop CoreProtect from asking again.
 */
public final class TranslationAnswer implements Answer {

    /** The key under which CoreProtect sends its {@code language} setting */
    static final String LANGUAGE = "DATA_LANGUAGE";

    private static final String BODY_PREFIX = "data=";
    private static final String PLUS_SIGN = "{PLUS_SIGN}";

    private final TranslationBundle bundle;
    private final Set<String> warned = ConcurrentHashMap.newKeySet();

    /**
     * Answer with the translations in the plugin JAR.
     */
    public TranslationAnswer() {
        this(TranslationBundle.bundled());
    }

    TranslationAnswer(TranslationBundle bundle) {
        this.bundle = Objects.requireNonNull(bundle, "bundle");
    }

    /**
     * @throws IOException if the request isn't CoreProtect's translation
     *         request, or no bundled language fits; the first time for each
     *         language, the latter is logged
     */
    @Override
    public Response answer(Request request) throws IOException {
        Map<String, String> sent = phrases(request.body());
        Map<String, String> translations = translate(sent);
        if (translations == null) {
            String language = sent.get(LANGUAGE);
            if (warned.add(language)) {
                LibreProtectLogger.warning("No bundled translation for '" + language + "', so messages stay in "
                    + "English. Allowing CoreProtect's translation service in " + PrivacyConfig.FILE_NAME
                    + " would machine-translate them, but it sends your language.yml phrases to coreprotect.net.");
            }
            throw new IOException(PrivacyConstants.FORK_NAME + " has no translation for '" + language + "'");
        }
        return Response.json(toJson(translations));
    }

    /**
     * @param sent the phrases of a translation request, as {@link #phrases}
     *             reads them
     * @return the bundled translation of each phrase that the request has
     *         with CoreProtect's built-in English text, by phrase name, or
     *         {@code null} if no bundled language fits the request's
     */
    Map<String, String> translate(Map<String, String> sent) throws IOException {
        String language = sent.get(LANGUAGE);
        if (language == null) {
            throw new IOException("The translation request names no language");
        }
        String code = bundle.resolve(language);
        return code == null ? null : uncustomized(sent, bundle.phrases(code));
    }

    /**
     * Leave out the translations of phrases that the server customized, and
     * of phrases that it didn't send, which CoreProtect doesn't have.
     * CoreProtect shows every translation in its answer at once, even of a
     * customized phrase; only its cache loader leaves those out, at the next
     * start.
     *
     * @param sent         the phrases of a translation request, as
     *                     {@link #phrases} reads them
     * @param translations translations by phrase name
     * @return the non-blank translations of the phrases that the request has
     *         with CoreProtect's built-in English text
     * @throws IOException if the built-in English isn't bundled
     */
    Map<String, String> uncustomized(Map<String, String> sent, Map<String, String> translations) throws IOException {
        Map<String, String> english = bundle.defaults();
        if (english == null) {
            throw new IOException(PrivacyConstants.FORK_NAME + "'s bundled translations lack CoreProtect's "
                + "built-in English, " + TranslationBundle.DEFAULTS);
        }
        Map<String, String> uncustomized = new TreeMap<>();
        translations.forEach((name, text) -> {
            // A phrase that differs from the built-in English was customized, as CoreProtect's cache loader decides
            if (!text.trim().isEmpty() && english.containsKey(name) && english.get(name).equals(sent.get(name))) {
                uncustomized.put(name, text);
            }
        });
        return uncustomized;
    }

    /**
     * Read the body of CoreProtect's translation request.
     *
     * @return every string in the request's JSON object, by key
     * @throws IOException if the body isn't {@code data=} and a JSON object
     */
    static Map<String, String> phrases(byte[] body) throws IOException {
        String text = new String(body, StandardCharsets.UTF_8);
        if (!text.startsWith(BODY_PREFIX)) {
            throw new IOException("Not a translation request: the body doesn't start with " + BODY_PREFIX);
        }
        return strings(text.substring(BODY_PREFIX.length()).replace(PLUS_SIGN, "+"));
    }

    /**
     * Read a JSON object's string values, skipping values of other types.
     * The object is streamed rather than built, so deep nesting in a hostile
     * reply can't exhaust the stack.
     *
     * @throws IOException if the text isn't exactly one JSON object
     */
    static Map<String, String> strings(String json) throws IOException {
        Map<String, String> strings = new LinkedHashMap<>();
        try (JsonReader reader = new JsonReader(new StringReader(json))) {
            reader.beginObject();
            while (reader.hasNext()) {
                String name = reader.nextName();
                if (reader.peek() == JsonToken.STRING) {
                    strings.put(name, reader.nextString());
                } else {
                    reader.skipValue();
                }
            }
            reader.endObject();
            if (reader.peek() != JsonToken.END_DOCUMENT) {
                throw new IOException("More follows the JSON object");
            }
        } catch (IllegalStateException | NumberFormatException e) {
            throw new IOException("Not a JSON object: " + e.getMessage(), e);
        }
        return strings;
    }

    /**
     * @return the strings as a JSON object on one line
     */
    static String toJson(Map<String, String> strings) {
        StringWriter json = new StringWriter();
        try (JsonWriter writer = new JsonWriter(json)) {
            writer.beginObject();
            for (Map.Entry<String, String> string : strings.entrySet()) {
                writer.name(string.getKey()).value(string.getValue());
            }
            writer.endObject();
        } catch (IOException e) {
            throw new UncheckedIOException(e); // A StringWriter doesn't fail
        }
        return json.toString();
    }
}
