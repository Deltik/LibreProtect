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

import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.util.logging.Logger;

/**
 * Lifecycle hooks called by the plugin main class that the transformer
 * generates. That class extends CoreProtect's main class:
 *
 * <pre>
 * public class LibreProtectPlugin extends net.coreprotect.CoreProtect {
 *     public LibreProtectPlugin() { super(); Bootstrap.init(this); }
 *     public void onEnable() { super.onEnable(); Bootstrap.enabled(this); }
 * }
 * </pre>
 *
 * <p>Only JDK and Bukkit types may be used here. CoreProtect computes
 * {@code static final} edition fields from {@code CoreProtect.getInstance()},
 * which stays {@code null} until CoreProtect's own {@code onEnable}. Touching
 * CoreProtect's classes from {@link #init} would freeze those fields empty,
 * and CoreProtect would then refuse to start.
 *
 * <p>Nothing here may throw, because an exception would stop CoreProtect from
 * loading. If setup fails, {@link Egress} stays in its default state and
 * blocks every request.
 */
public final class Bootstrap {

    /** CoreProtect's settings file in the data folder, which update checks consult */
    private static final String CORE_PROTECT_CONFIG = "config.yml";

    private static volatile PrivacyConfig activeConfig;
    private static volatile File configFile;

    private Bootstrap() {
    }

    /**
     * Called from the plugin constructor, right after {@code super()}, so
     * before any of CoreProtect's code can open a connection. The server and
     * the plugin's data folder are already set at this point.
     *
     * <p>Messages go to the server's logger, as CoreProtect's own do. The
     * plugin's logger would prefix them with the plugin name, CoreProtect.
     */
    public static void init(JavaPlugin plugin) {
        try {
            init(plugin.getServer().getLogger(), plugin.getDataFolder());
        } catch (Exception | LinkageError e) {
            failClosed(e);
        }
    }

    static void init(Logger logger, File dataFolder) {
        try {
            LibreProtectLogger.initialize(logger);
            configFile = new File(dataFolder, PrivacyConfig.FILE_NAME);
            PrivacyConfig config = PrivacyConfig.load(configFile);
            LibreProtectLogger.setVerbose(config.isVerboseLogging());
            Egress.install(config.buildResolver(new File(dataFolder, CORE_PROTECT_CONFIG)));
            activeConfig = config;
        } catch (Exception | LinkageError e) {
            failClosed(e);
        }
    }

    private static void failClosed(Throwable cause) {
        Egress.uninstall();
        activeConfig = null;
        try {
            LibreProtectLogger.severe("Could not load the network policy, blocking all network requests: " + cause);
        } catch (RuntimeException | LinkageError ignored) {
            // Still blocking; nothing more we can do
        }
    }

    /**
     * Called after CoreProtect's {@code onEnable} returns. CoreProtect has
     * already introduced itself as LibreProtect by then (see
     * {@link Branding}), so this only adds the network policy.
     */
    public static void enabled(JavaPlugin plugin) {
        try {
            if (!plugin.isEnabled()) {
                return;
            }

            File file = configFile;
            if (file != null && file.getParentFile().isDirectory()) {
                try {
                    if (PrivacyConfig.writeDefaultIfMissing(file)) {
                        LibreProtectLogger.info("Wrote default network policy to " + file.getPath());
                    }
                } catch (IOException e) {
                    LibreProtectLogger.warning("Could not write " + file.getPath() + ": " + e.getMessage());
                }
            }

            PrivacyConfig config = activeConfig;
            LibreProtectLogger.info("Network policy: "
                + (config != null ? config.describe() : "failed to load, blocking all requests"));
        } catch (Exception | LinkageError e) {
            LibreProtectLogger.warning("Startup message failed: " + e);
        }
    }

    /**
     * @return the settings in effect, or {@code null} if they failed to load
     */
    public static PrivacyConfig getActiveConfig() {
        return activeConfig;
    }
}
