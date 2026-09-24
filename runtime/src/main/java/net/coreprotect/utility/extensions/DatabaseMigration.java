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

import net.deltik.mc.libreprotect.PrivacyConstants;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;

/**
 * Placeholder for {@code /co migrate-db}, which copies CoreProtect data
 * between SQLite and MySQL.
 *
 * <h2>Why this class exists</h2>
 *
 * <p>Upstream CoreProtect's {@code net.coreprotect.utility.Extensions} loads
 * this class by name through reflection and calls
 * {@link #runCommand(CommandSender, String[])}. The real implementation is
 * only in CoreProtect's paid (Patreon) builds: upstream's {@code .gitignore}
 * excludes this package from the public source. Without this class,
 * {@code /co migrate-db} answers "Command not found". No free implementation
 * has been created by the LibreProtect community yet, so for now this class
 * explains that.
 *
 * <p>The class name, package, method name and parameter types are a contract
 * with upstream. LibreProtect's build checks that upstream still references
 * them and fails if it doesn't.
 *
 * <h2>How to implement it</h2>
 *
 * <p>Upstream's documentation ({@code docs/database-migration.md}) describes
 * the expected behavior:
 * <ol>
 *   <li>Usage: {@code /co migrate-db <sqlite|mysql>}, from the server
 *       <b>console only</b>. Upstream's command handler does no permission
 *       check for this subcommand, so this method must reject anything that
 *       isn't a {@link org.bukkit.command.ConsoleCommandSender}.</li>
 *   <li>The operator first edits {@code use-mysql} (and the MySQL settings)
 *       in {@code plugins/CoreProtect/config.yml} and runs the command
 *       <i>without</i> {@code /co reload}. The running plugin therefore still
 *       uses the source database, and the edited file describes the target
 *       database.</li>
 *   <li>Copy every table, in batches, showing progress. As of CoreProtect
 *       v24.1 the tables are {@code art_map}, {@code block},
 *       {@code blockdata_map}, {@code chat}, {@code command},
 *       {@code container}, {@code database_lock}, {@code entity},
 *       {@code entity_map}, {@code item}, {@code material_map},
 *       {@code session}, {@code sign}, {@code skull}, {@code user},
 *       {@code username_log}, {@code version} and {@code world}. Each is
 *       prefixed by {@code table-prefix} from {@code config.yml} (default
 *       {@code co_}, and always {@code co_} on SQLite). Don't hard-code this
 *       list: the authoritative schema is upstream's
 *       {@code net.coreprotect.database.Database#createDatabaseTables}, which
 *       you can call to create the target tables.</li>
 *   <li>Preserve row IDs: the {@code *_map}, {@code user} and {@code world}
 *       tables are referenced by ID from the log tables.</li>
 *   <li>Pause CoreProtect's consumer queue while copying, so no rows are
 *       written to the source during the migration, then switch the running
 *       plugin over to the target database.</li>
 * </ol>
 *
 * <p>Useful upstream classes: {@code net.coreprotect.config.ConfigHandler}
 * (the connection pool and {@code prefix}), {@code net.coreprotect.database.Database}
 * ({@code getConnection}, {@code createDatabaseTables}),
 * {@code net.coreprotect.consumer.Consumer} (pausing), and
 * {@code net.coreprotect.utility.Chat} (messages). Using them means compiling
 * against the upstream JAR. {@code scripts/lp build} builds it into
 * {@code build/upstream/target/}.
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
        String prefix = ChatColor.DARK_AQUA + PrivacyConstants.FORK_NAME + " " + ChatColor.WHITE + "- ";
        user.sendMessage(prefix + "Database migration is not available in "
            + PrivacyConstants.FORK_NAME + ".");
        user.sendMessage(ChatColor.GRAY + "No free implementation of /co migrate-db has been created by the "
            + PrivacyConstants.FORK_NAME + " community yet.");
        user.sendMessage(ChatColor.GRAY + "Want to help write one? See " + ChatColor.WHITE + PrivacyConstants.FORK_URL);
    }
}
