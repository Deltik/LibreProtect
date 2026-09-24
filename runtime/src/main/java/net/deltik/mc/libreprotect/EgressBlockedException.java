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

package net.deltik.mc.libreprotect;

import net.deltik.mc.libreprotect.routing.UrlNormalizer;

import java.io.IOException;
import java.net.URL;

/**
 * Thrown in place of opening a connection that LibreProtect blocks.
 *
 * <p>This is an {@link IOException} so that the caller's existing
 * network-failure handling runs, exactly as if the host were unreachable.
 */
public class EgressBlockedException extends IOException {

    private static final long serialVersionUID = 1L;

    private final String reason;

    public EgressBlockedException(URL url, String reason) {
        super("Blocked by " + PrivacyConstants.FORK_NAME + " (" + reason + "): " + UrlNormalizer.normalize(url));
        this.reason = reason;
    }

    public String getReason() {
        return reason;
    }
}
