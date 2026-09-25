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
import net.deltik.mc.libreprotect.PrivacyConstants;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.util.Locale;

/**
 * Automatic purging: deletes CoreProtect data older than {@code auto-purge}
 * once a day at {@code auto-purge-time}.
 */
public final class AutoPurgeService {

    private AutoPurgeService() {
    }

    /**
     * Start the schedule. Never throws.
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
     * Stop the schedule and any purge in progress. Never throws, and is safe
     * to call without {@link #start()}.
     */
    public static void stop() {
    }

    private static String readAutoPurge() {
        try {
            JavaPlugin plugin = JavaPlugin.getProvidingPlugin(AutoPurgeService.class);
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
