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

import net.deltik.mc.libreprotect.LibreProtectLogger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Answers CoreProtect's translation request with CoreProtect's translation
 * service layered over LibreProtect's bundled translation: the service's
 * translations win, and the bundled ones fill in the rest. Like the bundled
 * answer, it leaves out the service's translations of phrases that the server
 * customized in {@code language.yml}, which CoreProtect would otherwise show
 * until its next start. If the service fails, the bundled translation answers
 * alone, so allowing the service never loses translations. If neither can
 * answer, the request fails like a failed connection, and CoreProtect saves
 * no cache.
 *
 * <p>The service gets the request exactly as CoreProtect made it: the same
 * URL, method, request properties and body.
 */
public final class LayeredTranslationAnswer implements Answer {

    /** CoreProtect's own connect timeout for this request */
    static final int CONNECT_TIMEOUT_MILLIS = 5_000;

    /** CoreProtect sets none, but a stalled service shouldn't hold back the bundled answer forever */
    static final int READ_TIMEOUT_MILLIS = 15_000;

    /** Far more than a translation of every phrase needs */
    static final int MAX_REPLY_BYTES = 1 << 20;

    private final TranslationAnswer bundled;
    private final Proxy proxy;

    /**
     * @param bundled answers from the bundled translations
     * @param proxy   the proxy that CoreProtect asked for, or {@code null} for
     *                the default
     */
    public LayeredTranslationAnswer(TranslationAnswer bundled, Proxy proxy) {
        this.bundled = Objects.requireNonNull(bundled, "bundled");
        this.proxy = proxy;
    }

    @Override
    public Response answer(Request request) throws IOException {
        Map<String, String> sent = sent(request);
        Map<String, String> translations = bundled(sent);
        Map<String, String> service;
        try {
            service = ask(request);
        } catch (IOException | RuntimeException e) {
            if (translations == null) {
                throw e;
            }
            LibreProtectLogger.debug("CoreProtect's translation service failed, so the bundled translation answers "
                + "alone: " + e);
            return Response.json(TranslationAnswer.toJson(translations));
        }
        Map<String, String> layered = translations == null ? new TreeMap<>() : new TreeMap<>(translations);
        layered.putAll(uncustomized(sent, service));
        return Response.json(TranslationAnswer.toJson(layered));
    }

    /**
     * @return the phrases of CoreProtect's request, or {@code null} if it
     *         isn't CoreProtect's translation request
     */
    private static Map<String, String> sent(Request request) {
        try {
            return TranslationAnswer.phrases(request.body());
        } catch (IOException e) {
            LibreProtectLogger.debug("Not CoreProtect's translation request: " + e.getMessage());
            return null;
        }
    }

    /**
     * @return the bundled answer, or {@code null} if there is none
     */
    private Map<String, String> bundled(Map<String, String> sent) {
        if (sent == null) {
            return null;
        }
        try {
            return bundled.translate(sent);
        } catch (IOException e) {
            LibreProtectLogger.debug("No bundled translation for this request: " + e.getMessage());
            return null;
        }
    }

    /**
     * @return the service's translations without those of phrases that the
     *         server customized, by the bundled answer's rule, or all of them
     *         if that rule can't be applied
     */
    private Map<String, String> uncustomized(Map<String, String> sent, Map<String, String> service) {
        if (sent == null) {
            return service;
        }
        try {
            return bundled.uncustomized(sent, service);
        } catch (IOException e) {
            LibreProtectLogger.debug("Can't tell customized phrases in the service's translation: " + e.getMessage());
            return service;
        }
    }

    /**
     * Send the request to CoreProtect's translation service.
     *
     * @return the service's non-blank translations, by phrase name
     * @throws IOException if the service fails or answers with anything but a
     *         JSON object
     */
    private Map<String, String> ask(Request request) throws IOException {
        URL url = request.url();
        // LibreProtect's own classes are never rewritten, so this is a real connection
        URLConnection opened = proxy == null ? url.openConnection() : url.openConnection(proxy);
        if (!(opened instanceof HttpURLConnection)) {
            throw new IOException("Not an HTTP URL: " + url.getProtocol());
        }
        HttpURLConnection connection = (HttpURLConnection) opened;
        try {
            connection.setRequestMethod(request.method());
            request.headers().forEach(connection::setRequestProperty);
            connection.setUseCaches(false);
            connection.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
            connection.setReadTimeout(READ_TIMEOUT_MILLIS);
            byte[] body = request.body();
            if (body.length > 0) {
                connection.setDoOutput(true);
                try (OutputStream out = connection.getOutputStream()) {
                    out.write(body);
                }
            }

            int status = connection.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                throw new IOException("HTTP " + status + " from " + url.getHost());
            }
            byte[] reply;
            try (InputStream in = connection.getInputStream()) {
                reply = in.readNBytes(MAX_REPLY_BYTES + 1);
            }
            if (reply.length > MAX_REPLY_BYTES) {
                throw new IOException("The reply is larger than " + MAX_REPLY_BYTES + " bytes");
            }

            Map<String, String> translations = new TreeMap<>();
            TranslationAnswer.strings(new String(reply, StandardCharsets.UTF_8).trim()).forEach((name, text) -> {
                // CoreProtect ignores blank translations, which mustn't hide bundled ones
                if (!text.trim().isEmpty()) {
                    translations.put(name, text);
                }
            });
            return translations;
        } finally {
            connection.disconnect();
        }
    }
}
