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

package net.deltik.mc.libreprotect.extension.purge;

import net.deltik.mc.libreprotect.LibreProtectLogger;

/**
 * Where auto-purge's console messages go. CoreProtect has no phrases for
 * them, so they are in English.
 */
interface PurgeLog {

    /** The server console, with LibreProtect's prefix */
    PurgeLog CONSOLE = new PurgeLog() {
        @Override
        public void info(String message) {
            LibreProtectLogger.info(message);
        }

        @Override
        public void warning(String message) {
            LibreProtectLogger.warning(message);
        }
    };

    void info(String message);

    void warning(String message);
}
