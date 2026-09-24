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

import net.deltik.mc.libreprotect.PrivacyConstants;

import java.io.IOException;
import java.net.URL;
import java.util.EnumMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Answers each request with the {@link Answer} for its endpoint.
 *
 * <p>Endpoints are recognized by host and path, case-insensitively. A request
 * to any other URL, or to an endpoint that has no answer, fails with an
 * {@link IOException}.
 *
 * <p>The license endpoint is deliberately not answerable. CoreProtect saves
 * validated keys to {@code plugins/CoreProtect/.license}, and stock CoreProtect
 * trusts that file when it is offline, so an answered license would leak out
 * of LibreProtect.
 */
public final class AnswerRegistry implements Answer {

    /**
     * CoreProtect's endpoints that LibreProtect can answer
     */
    public enum Endpoint {
        /** {@code coreprotect.net/translate/}, with or without the final slash */
        TRANSLATION,

        /** Any path on {@code update.coreprotect.net} */
        UPDATE,

        /** Any path on {@code stats.coreprotect.net} */
        STATS;

        /**
         * @return the endpoint that the URL is for, or {@code null} if none
         */
        public static Endpoint of(URL url) {
            String host = lowercase(url.getHost());
            String path = lowercase(url.getPath());

            if (host.equals("coreprotect.net") && (path.equals("/translate/") || path.equals("/translate"))) {
                return TRANSLATION;
            }
            if (host.equals("update.coreprotect.net")) {
                return UPDATE;
            }
            if (host.equals("stats.coreprotect.net")) {
                return STATS;
            }
            return null;
        }

        private static String lowercase(String value) {
            return value == null ? "" : value.toLowerCase(Locale.ROOT);
        }
    }

    private final Map<Endpoint, Answer> answers = new EnumMap<>(Endpoint.class);

    /**
     * @param answers the answer for each endpoint; requests to an endpoint
     *                that isn't in the map fail
     */
    public AnswerRegistry(Map<Endpoint, ? extends Answer> answers) {
        this.answers.putAll(answers);
    }

    /**
     * @return a registry with LibreProtect's own answer for each endpoint,
     *         which answers update checks without asking any update source
     */
    public static AnswerRegistry defaults() {
        return defaults(new UpdateAnswer());
    }

    /**
     * @param updates the answer to update checks, which asks the configured
     *                update sources
     * @return a registry with LibreProtect's own answer for each endpoint
     */
    public static AnswerRegistry defaults(UpdateAnswer updates) {
        Map<Endpoint, Answer> answers = new EnumMap<>(Endpoint.class);
        answers.put(Endpoint.TRANSLATION, new TranslationAnswer());
        answers.put(Endpoint.UPDATE, Objects.requireNonNull(updates, "updates"));
        answers.put(Endpoint.STATS, new StatsAnswer());
        return new AnswerRegistry(answers);
    }

    /**
     * @return the answer for the URL's endpoint
     * @throws IOException if LibreProtect can't answer requests to the URL
     */
    public Answer answerFor(URL url) throws IOException {
        Endpoint endpoint = Endpoint.of(url);
        Answer answer = endpoint == null ? null : answers.get(endpoint);
        if (answer == null) {
            throw new IOException(PrivacyConstants.FORK_NAME + " can't answer requests to "
                + url.getProtocol() + "://" + url.getHost() + url.getPath()
                + "; use BLOCK for it instead. If upstream added this endpoint, please report it at "
                + PrivacyConstants.FORK_ISSUE_URL);
        }
        return answer;
    }

    @Override
    public Response answer(Request request) throws IOException {
        return answerFor(request.url()).answer(request);
    }
}
