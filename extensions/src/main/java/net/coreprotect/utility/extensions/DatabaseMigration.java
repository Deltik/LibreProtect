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

package net.coreprotect.utility.extensions;

import net.deltik.mc.libreprotect.extension.migration.MigrationCommand;
import org.bukkit.command.CommandSender;

/**
 * {@code /co migrate-db}, which copies CoreProtect's data to another database
 * engine.
 *
 * <p>Upstream CoreProtect's {@code net.coreprotect.utility.Extensions} loads
 * this class by name through reflection and calls
 * {@link #runCommand(CommandSender, String[])}. Upstream's own implementation
 * is only in its paid (Patreon) builds: its {@code .gitignore} excludes this
 * package from the public source. LibreProtect's implementation is
 * {@link MigrationCommand}.
 *
 * <p>The class name, package, method name and parameter types are a contract
 * with upstream. LibreProtect's build checks that upstream still references
 * them. Keep this class to the one entry point: the build reports any other
 * class or public method in this package that upstream doesn't ask for.
 *
 * @see <a href="https://github.com/Deltik/LibreProtect">LibreProtect</a>
 */
public final class DatabaseMigration {

    private DatabaseMigration() {
    }

    /**
     * Entry point, called reflectively by
     * {@code net.coreprotect.utility.Extensions#runDatabaseMigration}.
     *
     * @param user the command sender
     * @param argumentArray the command arguments: {@code argumentArray[0]} is
     *                      {@code "migrate-db"} and {@code argumentArray[1]},
     *                      if present, is the target database type
     */
    public static void runCommand(CommandSender user, String[] argumentArray) {
        MigrationCommand.run(user, argumentArray);
    }
}
