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

/**
 * Names and links that LibreProtect shows.
 *
 * <p>LibreProtect is distributed under the GNU General Public License, version
 * 3 or later. CoreProtect itself is under the Artistic License 2.0; see NOTICE.
 */
public class PrivacyConstants {

    // LibreProtect
    public static final String FORK_NAME = "LibreProtect";
    public static final String FORK_URL = "https://github.com/Deltik/LibreProtect";
    /** {@link #FORK_URL} as CoreProtect shows links in chat, without the scheme */
    public static final String FORK_DISPLAY_URL = "github.com/Deltik/LibreProtect";
    public static final String FORK_ISSUE_URL = FORK_URL + "/issues";

    // The project LibreProtect is built from
    public static final String ORIGINAL_NAME = "CoreProtect";
    public static final String ORIGINAL_AUTHOR = "Intelli";

    private PrivacyConstants() {
        // Prevent instantiation
    }
}
