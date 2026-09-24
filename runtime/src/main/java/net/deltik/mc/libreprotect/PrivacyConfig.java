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

import net.deltik.mc.libreprotect.routing.Route;
import net.deltik.mc.libreprotect.routing.RouteConfigParser;
import net.deltik.mc.libreprotect.routing.RoutePreset;
import net.deltik.mc.libreprotect.routing.RouteResolver;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.InvalidConfigurationException;
import org.bukkit.configuration.file.YamlConfiguration;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * LibreProtect's network policy settings, loaded from {@value #FILE_NAME} in
 * the plugin's data folder.
 *
 * <p>LibreProtect keeps its settings in its own file instead of CoreProtect's
 * {@code config.yml}, so CoreProtect's config handling never sees or rewrites
 * them.
 *
 * <p>Any problem reading the file falls back to {@link #defaults()}, which
 * sends nothing.
 */
public final class PrivacyConfig {

    public static final String FILE_NAME = "libreprotect.yml";

    private final RoutePreset preset;
    private final List<Route> customRoutes;
    private final boolean verboseLogging;

    PrivacyConfig(RoutePreset preset, List<Route> customRoutes, boolean verboseLogging) {
        this.preset = preset;
        this.customRoutes = Collections.unmodifiableList(customRoutes);
        this.verboseLogging = verboseLogging;
    }

    /**
     * @return the privacy-first settings used when there is no usable config file
     */
    public static PrivacyConfig defaults() {
        return new PrivacyConfig(RoutePreset.PRIVACY_FIRST, Collections.emptyList(), false);
    }

    /**
     * Load settings from a file.
     *
     * @param file the settings file; a missing file yields {@link #defaults()}
     */
    public static PrivacyConfig load(File file) {
        if (!file.isFile()) {
            return defaults();
        }

        YamlConfiguration yaml = new YamlConfiguration();
        try {
            yaml.load(file);
        } catch (IOException | InvalidConfigurationException e) {
            LibreProtectLogger.severe("Could not read " + file + ", blocking all network requests: " + e.getMessage());
            return defaults();
        }
        return fromYaml(yaml);
    }

    static PrivacyConfig fromYaml(ConfigurationSection yaml) {
        String presetName = yaml.getString(PrivacyConfigSchema.PRESET.key, (String) PrivacyConfigSchema.PRESET.defaultValue);
        if (!PrivacyConfigSchema.isValidValue(PrivacyConfigSchema.PRESET.key, presetName)) {
            LibreProtectLogger.warning("Unknown preset '" + presetName + "' in " + FILE_NAME + ", using "
                + RoutePreset.PRIVACY_FIRST.getConfigName());
        }
        RoutePreset preset = RoutePreset.fromConfigName(presetName);

        Object routes = yaml.get(PrivacyConfigSchema.ROUTES.key);
        if (routes != null && !(routes instanceof List)) {
            LibreProtectLogger.warning("'" + PrivacyConfigSchema.ROUTES.key + "' in " + FILE_NAME
                + " must be a list, ignoring it");
        }
        List<Route> customRoutes = new RouteConfigParser().parseRoutes(yaml.getList(PrivacyConfigSchema.ROUTES.key));

        boolean verboseLogging = parseBoolean(
            yaml.get(PrivacyConfigSchema.VERBOSE_LOGGING.key),
            (Boolean) PrivacyConfigSchema.VERBOSE_LOGGING.defaultValue);

        return new PrivacyConfig(preset, customRoutes, verboseLogging);
    }

    private static boolean parseBoolean(Object value, boolean defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        String str = value.toString().toLowerCase(Locale.ROOT);
        return str.equals("true") || str.equals("yes") || str.equals("1");
    }

    /**
     * Write the commented default settings file if the file does not exist yet.
     *
     * @return {@code true} if the file was written
     */
    public static boolean writeDefaultIfMissing(File file) throws IOException {
        if (file.exists()) {
            return false;
        }
        Files.write(file.toPath(), PrivacyConfigSchema.generateDefaultFile().getBytes(StandardCharsets.UTF_8));
        return true;
    }

    /**
     * @return a resolver that applies these settings
     */
    public RouteResolver buildResolver() {
        return new RouteResolver(new RouteConfigParser().buildRegistry(preset, customRoutes));
    }

    public RoutePreset getPreset() {
        return preset;
    }

    public List<Route> getCustomRoutes() {
        return customRoutes;
    }

    public boolean isVerboseLogging() {
        return verboseLogging;
    }

    /**
     * @return a one-line summary for the startup log
     */
    public String describe() {
        return "preset " + preset.getConfigName()
            + ", " + customRoutes.size() + " custom route" + (customRoutes.size() == 1 ? "" : "s")
            + ", default action " + preset.getDefaultAction()
            + (verboseLogging ? ", verbose logging" : "");
    }
}
