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

package net.deltik.mc.libreprotect.routing;

import net.deltik.mc.libreprotect.routing.action.AnswerAction;
import net.deltik.mc.libreprotect.routing.action.BlockAction;
import net.deltik.mc.libreprotect.routing.action.PassthroughAction;
import net.deltik.mc.libreprotect.routing.action.RedirectAction;
import net.deltik.mc.libreprotect.routing.answer.Answer;
import net.deltik.mc.libreprotect.routing.answer.AnswerRegistry;

import java.util.EnumMap;
import java.util.Map;

/**
 * Provides the RouteAction for each action type. Each factory holds one
 * instance of each action; only what ANSWER answers with differs between
 * factories.
 */
public class RouteActionFactory {

    /** Built on first use, since the network policy brings its own answers */
    private static final class Defaults {
        static final RouteActionFactory INSTANCE = new RouteActionFactory(AnswerRegistry.defaults());
    }

    private final Map<RouteActionType, RouteAction> actions = new EnumMap<>(RouteActionType.class);

    /**
     * @param answers answers requests that are routed to ANSWER, usually an
     *                {@link AnswerRegistry}
     */
    public RouteActionFactory(Answer answers) {
        actions.put(RouteActionType.BLOCK, new BlockAction());
        actions.put(RouteActionType.ANSWER, new AnswerAction(answers));
        actions.put(RouteActionType.REDIRECT, new RedirectAction());
        actions.put(RouteActionType.PASSTHROUGH, new PassthroughAction());
    }

    /**
     * @return the factory whose ANSWER action uses
     *         {@link AnswerRegistry#defaults()}
     */
    public static RouteActionFactory defaults() {
        return Defaults.INSTANCE;
    }

    /**
     * Get the action handler for a given action type.
     *
     * @param type The action type
     * @return The action handler
     * @throws IllegalArgumentException if the action type is unknown
     */
    public RouteAction getAction(RouteActionType type) {
        RouteAction action = actions.get(type);
        if (action == null) {
            throw new IllegalArgumentException("Unknown action type: " + type);
        }
        return action;
    }
}
