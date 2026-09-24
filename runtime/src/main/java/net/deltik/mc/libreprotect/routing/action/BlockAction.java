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

import net.deltik.mc.libreprotect.EgressBlockedException;
import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.routing.RouteAction;
import net.deltik.mc.libreprotect.routing.RouteActionType;
import net.deltik.mc.libreprotect.routing.RouteRegistry;

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;

/**
 * Action that blocks the request by failing it as if the host were unreachable.
 *
 * <p>Throwing from {@code openConnection} instead of returning a fake
 * connection means no request is ever built, and callers take the same path
 * they take when offline.
 */
public class BlockAction implements RouteAction {

    @Override
    public RouteActionType getType() {
        return RouteActionType.BLOCK;
    }

    @Override
    public URLConnection createConnection(URL url, Proxy proxy, RouteRegistry.RouteMatch match) throws IOException {
        String reason = match.isDefault()
            ? "default action"
            : "route " + match.getRoute().getPatternString();

        EgressBlockedException blocked = new EgressBlockedException(url, reason);
        LibreProtectLogger.debug(blocked.getMessage());
        throw blocked;
    }
}
