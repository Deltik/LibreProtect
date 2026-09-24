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

/**
 * Types of actions that can be taken on a matched route.
 */
public enum RouteActionType {
    /**
     * Fail the request as if the host were unreachable
     */
    BLOCK,

    /**
     * LibreProtect answers the request itself: translations come from bundled
     * files, update checks from the configured update sources, and statistics
     * get an empty reply. Nothing is sent to CoreProtect's servers.
     */
    ANSWER,

    /**
     * Redirect to a different URL (with capture substitution)
     */
    REDIRECT,

    /**
     * Allow the request through unchanged
     */
    PASSTHROUGH
}
