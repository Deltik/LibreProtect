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

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.PrivacyConstants;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.util.Locale;

/**
 * Placeholder for CoreProtect's background service, which runs automatic
 * purging ({@code auto-purge} in {@code config.yml}).
 *
 * <h2>Why this class exists</h2>
 *
 * <p>Since v24.0, upstream CoreProtect's
 * {@code net.coreprotect.utility.Extensions} loads this class by name through
 * reflection. It calls the static {@link #start()} when the plugin enables and
 * {@link #stop()} when it disables. The real implementation is only in
 * CoreProtect's paid (Patreon) builds; upstream's {@code .gitignore} excludes
 * this package from the public source. No free implementation has been
 * created by the LibreProtect community yet. Until one is, this class tells
 * operators who set {@code auto-purge} that it isn't happening.
 *
 * <p>The class name, package, method names and signatures are a contract with
 * upstream. LibreProtect's build checks that upstream still references them
 * and fails if it doesn't.
 *
 * <h2>How to implement it</h2>
 *
 * <p>Upstream's documentation ({@code docs/auto-purge.md}) describes the
 * expected behavior:
 * <ul>
 *   <li>{@code auto-purge} holds a retention time such as {@code 30d},
 *       {@code 12w} or {@code 6mo}, with a minimum of {@code 30d}, or
 *       {@code false} to disable it.</li>
 *   <li>It runs once a day at {@code auto-purge-time} ({@code HH:mm},
 *       server-local time, default midnight).</li>
 *   <li>Rows older than the retention time are deleted in small chunks, with
 *       pauses, from the same tables as {@code /co purge}. It doesn't rebuild
 *       SQLite or optimize MySQL.</li>
 *   <li>It stops safely when the server shuts down, when a manual purge or
 *       database migration starts, or when the consumer is paused, and it
 *       resumes at the next scheduled run.</li>
 *   <li>{@code /co status} shows how many rows were purged since startup.</li>
 * </ul>
 *
 * <p>Useful upstream classes: {@code net.coreprotect.command.PurgeCommand}
 * (the list of purgeable tables and how to delete by time),
 * {@code net.coreprotect.config.Config#getGlobal()} (the parsed
 * {@code AUTO_PURGE} and {@code AUTO_PURGE_TIME} values), and
 * {@code net.coreprotect.database.Database}. Using them means compiling
 * against the upstream JAR. {@code scripts/lp build} builds it into
 * {@code build/upstream/target/}.
 *
 * @see <a href="https://github.com/Deltik/LibreProtect">LibreProtect</a>
 */
public final class BackgroundService {

    private BackgroundService() {
    }

    /**
     * Called reflectively when CoreProtect starts its background services.
     */
    public static void start() {
        String autoPurge = readAutoPurge();
        if (autoPurge != null && !autoPurge.isEmpty() && !autoPurge.equals("false")) {
            LibreProtectLogger.warning("auto-purge is set to '" + autoPurge + "', but automatic purging is not available in "
                + PrivacyConstants.FORK_NAME + ": no free implementation has been created yet. "
                + "Use /co purge instead. Want to help write one? See " + PrivacyConstants.FORK_URL);
        }
    }

    /**
     * Called reflectively when CoreProtect shuts down.
     */
    public static void stop() {
    }

    private static String readAutoPurge() {
        try {
            JavaPlugin plugin = JavaPlugin.getProvidingPlugin(BackgroundService.class);
            File configFile = new File(plugin.getDataFolder(), "config.yml");
            if (!configFile.isFile()) {
                return null;
            }
            YamlConfiguration config = new YamlConfiguration();
            config.load(configFile);
            String value = config.getString("auto-purge");
            return value == null ? null : value.trim().toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return null;
        }
    }
}
