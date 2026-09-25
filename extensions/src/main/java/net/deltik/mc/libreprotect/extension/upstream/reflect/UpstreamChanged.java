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

package net.deltik.mc.libreprotect.extension.upstream.reflect;

/**
 * Upstream did something that its probed shape doesn't allow, such as
 * throwing a checked exception that the member doesn't declare, or a member
 * that probing found can't be reached. Unchecked: it means upstream changed
 * under a capability that was available, which callers can't handle better
 * than any other failure.
 */
public final class UpstreamChanged extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public UpstreamChanged(String message) {
        super(message);
    }

    public UpstreamChanged(String message, Throwable cause) {
        super(message, cause);
    }
}
