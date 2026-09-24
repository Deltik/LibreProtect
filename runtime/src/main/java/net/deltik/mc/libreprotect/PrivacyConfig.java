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
import net.deltik.mc.libreprotect.routing.RouteActionFactory;
import net.deltik.mc.libreprotect.routing.RouteActionType;
import net.deltik.mc.libreprotect.routing.RouteConfigParser;
import net.deltik.mc.libreprotect.routing.RoutePreset;
import net.deltik.mc.libreprotect.routing.RouteRegistry;
import net.deltik.mc.libreprotect.routing.RouteResolver;
import net.deltik.mc.libreprotect.routing.answer.AnswerRegistry;
import net.deltik.mc.libreprotect.routing.answer.UpdateAnswer;
import net.deltik.mc.libreprotect.update.UpdateCheck;
import net.deltik.mc.libreprotect.update.UpdateSource;
import net.deltik.mc.libreprotect.update.UpdateSourceParser;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.InvalidConfigurationException;
import org.bukkit.configuration.file.YamlConfiguration;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.nodes.Node;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.ScalarNode;
import org.yaml.snakeyaml.nodes.Tag;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
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

    /** CoreProtect's update check, as routes see it */
    private static final String UPDATE_CHECK = "http://update.coreprotect.net/version/";

    private final RoutePreset preset;
    private final List<Route> customRoutes;
    private final List<UpdateSource> updateSources;
    private final boolean verboseLogging;

    PrivacyConfig(RoutePreset preset, List<Route> customRoutes, List<UpdateSource> updateSources,
                  boolean verboseLogging) {
        this.preset = preset;
        this.customRoutes = Collections.unmodifiableList(customRoutes);
        this.updateSources = Collections.unmodifiableList(updateSources);
        this.verboseLogging = verboseLogging;
    }

    /**
     * @return the privacy-first settings used when there is no usable config file
     */
    public static PrivacyConfig defaults() {
        return new PrivacyConfig(RoutePreset.PRIVACY_FIRST, Collections.emptyList(), defaultUpdateSources(), false);
    }

    /**
     * @return the update sources of {@link PrivacyConfigSchema#UPDATE_SOURCES}'s default value
     */
    static List<UpdateSource> defaultUpdateSources() {
        return new UpdateSourceParser().parse((List<?>) PrivacyConfigSchema.UPDATE_SOURCES.defaultValue);
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

        String text;
        YamlConfiguration yaml = new YamlConfiguration();
        try {
            text = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
            yaml.loadFromString(text);
        } catch (IOException | InvalidConfigurationException e) {
            LibreProtectLogger.severe("Could not read " + file + ", blocking all network requests: " + e.getMessage());
            return defaults();
        }
        return fromYaml(yaml, hasNullValue(text, PrivacyConfigSchema.UPDATE_SOURCES.key));
    }

    /**
     * Whether the document's top-level mapping has the key with a null
     * value, as {@code update-sources:} does once every source is commented
     * out. Bukkit drops such keys, so this looks at SnakeYAML's node tree,
     * which builds no objects.
     */
    static boolean hasNullValue(String text, String key) {
        try {
            Node root = new Yaml().compose(new StringReader(text));
            boolean nullValue = false;
            if (root instanceof MappingNode) {
                for (NodeTuple entry : ((MappingNode) root).getValue()) {
                    Node name = entry.getKeyNode();
                    if (name instanceof ScalarNode && key.equals(((ScalarNode) name).getValue())) {
                        // As in YAML, a later entry with the same key wins
                        Node value = entry.getValueNode();
                        nullValue = value instanceof ScalarNode && Tag.NULL.equals(value.getTag());
                    }
                }
            }
            return nullValue;
        } catch (RuntimeException e) {
            return false;
        }
    }

    static PrivacyConfig fromYaml(ConfigurationSection yaml) {
        return fromYaml(yaml, false);
    }

    /**
     * @param updateSourcesWithoutValue whether the file has
     *        {@code update-sources:} without a value, which the section
     *        doesn't show
     */
    static PrivacyConfig fromYaml(ConfigurationSection yaml, boolean updateSourcesWithoutValue) {
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

        List<UpdateSource> updateSources =
            parseUpdateSources(yaml.get(PrivacyConfigSchema.UPDATE_SOURCES.key), updateSourcesWithoutValue);

        boolean verboseLogging = parseBoolean(
            yaml.get(PrivacyConfigSchema.VERBOSE_LOGGING.key),
            (Boolean) PrivacyConfigSchema.VERBOSE_LOGGING.defaultValue);

        return new PrivacyConfig(preset, customRoutes, updateSources, verboseLogging);
    }

    /**
     * A missing key means the default sources. Anything that isn't a list
     * turns update checks off, as an empty list does, rather than sending
     * requests the operator may have meant to turn off.
     */
    private static List<UpdateSource> parseUpdateSources(Object value, boolean withoutValue) {
        if (value == null) {
            return withoutValue ? Collections.emptyList() : defaultUpdateSources();
        }
        if (!(value instanceof List)) {
            LibreProtectLogger.warning("'" + PrivacyConfigSchema.UPDATE_SOURCES.key + "' in " + FILE_NAME
                + " must be a list, so update checks are off");
            return Collections.emptyList();
        }
        return new UpdateSourceParser().parse((List<?>) value);
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
     * @return a resolver that applies these settings, without reading
     *         CoreProtect's settings
     */
    public RouteResolver buildResolver() {
        return buildResolver((File) null);
    }

    /**
     * @param coreProtectConfig CoreProtect's {@code config.yml}, whose
     *                          {@code check-updates} is read again before each
     *                          update check, or {@code null}
     * @return a resolver that applies these settings
     */
    public RouteResolver buildResolver(File coreProtectConfig) {
        return buildResolver(LibreProtectVersion.getForkVersion(), coreProtectConfig);
    }

    /**
     * @param runningVersion the LibreProtect version that update checks
     *                       compare releases with
     */
    RouteResolver buildResolver(String runningVersion, File coreProtectConfig) {
        UpdateAnswer updates = new UpdateAnswer(new UpdateCheck(updateSources, runningVersion,
            LibreProtectVersion.getUpstreamVersion(), coreProtectConfig));
        return new RouteResolver(registry(), new RouteActionFactory(AnswerRegistry.defaults(updates)));
    }

    private RouteRegistry registry() {
        return new RouteConfigParser().buildRegistry(preset, customRoutes);
    }

    public RoutePreset getPreset() {
        return preset;
    }

    public List<Route> getCustomRoutes() {
        return customRoutes;
    }

    /**
     * @return where update checks go when LibreProtect answers them, in
     *         order; empty if update checks are off
     */
    public List<UpdateSource> getUpdateSources() {
        return updateSources;
    }

    public boolean isVerboseLogging() {
        return verboseLogging;
    }

    /**
     * @return a one-line summary for the startup log; it counts the update
     *         sources only if LibreProtect answers update checks
     */
    public String describe() {
        boolean answersUpdates = registry().match(UPDATE_CHECK).getActionType() == RouteActionType.ANSWER;
        return "preset " + preset.getConfigName()
            + ", " + count(customRoutes.size(), "custom route")
            + ", default action " + preset.getDefaultAction()
            + (answersUpdates ? ", " + count(updateSources.size(), "update source") : "")
            + (verboseLogging ? ", verbose logging" : "");
    }

    private static String count(int count, String noun) {
        return count + " " + noun + (count == 1 ? "" : "s");
    }
}
