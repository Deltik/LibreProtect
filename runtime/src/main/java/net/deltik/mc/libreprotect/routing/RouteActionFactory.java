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

import java.util.EnumMap;
import java.util.Map;

/**
 * Factory for creating RouteAction instances.
 * Uses singleton instances since actions are stateless.
 */
public class RouteActionFactory {
    private static final Map<RouteActionType, RouteAction> ACTIONS = new EnumMap<>(RouteActionType.class);

    static {
        ACTIONS.put(RouteActionType.BLOCK, new BlockAction());
        ACTIONS.put(RouteActionType.ANSWER, new AnswerAction());
        ACTIONS.put(RouteActionType.REDIRECT, new RedirectAction());
        ACTIONS.put(RouteActionType.PASSTHROUGH, new PassthroughAction());
    }

    /**
     * Get the action handler for a given action type.
     *
     * @param type The action type
     * @return The action handler
     * @throws IllegalArgumentException if the action type is unknown
     */
    public static RouteAction getAction(RouteActionType type) {
        RouteAction action = ACTIONS.get(type);
        if (action == null) {
            throw new IllegalArgumentException("Unknown action type: " + type);
        }
        return action;
    }
}
