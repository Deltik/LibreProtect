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

package net.deltik.mc.libreprotect.routing.action;

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.routing.RouteAction;
import net.deltik.mc.libreprotect.routing.RouteActionType;
import net.deltik.mc.libreprotect.routing.RouteRegistry;
import net.deltik.mc.libreprotect.routing.UrlNormalizer;
import net.deltik.mc.libreprotect.routing.answer.Answer;
import net.deltik.mc.libreprotect.routing.answer.AnswerConnection;
import net.deltik.mc.libreprotect.routing.answer.AnswerRegistry;

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.util.Objects;

/**
 * Action that answers requests to CoreProtect's endpoints without connecting.
 */
public class AnswerAction implements RouteAction {

    private final Answer answer;

    /**
     * Answer with LibreProtect's own answers ({@link AnswerRegistry#defaults()}).
     */
    public AnswerAction() {
        this(AnswerRegistry.defaults());
    }

    /**
     * @param answer answers every request this action handles, usually an
     *               {@link AnswerRegistry}
     */
    public AnswerAction(Answer answer) {
        this.answer = Objects.requireNonNull(answer, "answer");
    }

    @Override
    public RouteActionType getType() {
        return RouteActionType.ANSWER;
    }

    @Override
    public URLConnection createConnection(URL url, Proxy proxy, RouteRegistry.RouteMatch match) throws IOException {
        LibreProtectLogger.debug("Answering: " + UrlNormalizer.normalize(url));
        return new AnswerConnection(url, answer);
    }
}
