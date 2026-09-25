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

package net.deltik.mc.libreprotect.extension.migration;

import net.deltik.mc.libreprotect.PrivacyConstants;
import net.deltik.mc.libreprotect.extension.common.Console;
import org.bukkit.command.CommandSender;

/**
 * {@code /co migrate-db}: copies CoreProtect's data to another database engine
 * and switches the running server over to it.
 */
public final class MigrationCommand {

    private MigrationCommand() {
    }

    /**
     * @param argumentArray the command arguments: {@code argumentArray[0]} is
     *                      {@code "migrate-db"}
     */
    public static void run(CommandSender user, String[] argumentArray) {
        Console console = new Console(user);
        console.say("Database migration is not available in " + PrivacyConstants.FORK_NAME + ".");
        console.detail("No free implementation of /co migrate-db has been created by the "
            + PrivacyConstants.FORK_NAME + " community yet.");
        console.detail("Want to help write one? See " + org.bukkit.ChatColor.WHITE + PrivacyConstants.FORK_URL);
    }
}
