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
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * LibreProtect's network policy settings, loaded from {@value #FILE_NAME} in
 * the plugin's data folder.
 *
 * <p>LibreProtect keeps its settings in its own file instead of CoreProtect's
 * {@code config.yml}, so CoreProtect's config handling never sees or rewrites
 * them.
 *
 * <p>A missing file or setting means the default ({@link #defaults()}). A
 * file that doesn't give settings LibreProtect understands means
 * {@link #failClosed()}, which sends nothing (see {@link #load}).
 */
public final class PrivacyConfig {

    public static final String FILE_NAME = "libreprotect.yml";

    /** Far more than any settings need, so a larger file is a mistake, and isn't read */
    static final int MAX_FILE_BYTES = 1024 * 1024;

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
     * @return the settings of {@link PrivacyConfigSchema}'s defaults, used
     *         when there is no config file yet: the allow-updates preset and
     *         the default update sources
     */
    public static PrivacyConfig defaults() {
        return new PrivacyConfig(RoutePreset.ALLOW_UPDATES, Collections.emptyList(), defaultUpdateSources(), false);
    }

    /**
     * @return the settings used when the config file is there but doesn't
     *         give settings LibreProtect understands (see {@link #load}): the
     *         privacy-first preset without update sources, which sends nothing
     */
    public static PrivacyConfig failClosed() {
        return failClosed(false);
    }

    private static PrivacyConfig failClosed(boolean verboseLogging) {
        return new PrivacyConfig(RoutePreset.PRIVACY_FIRST, Collections.emptyList(), Collections.emptyList(),
            verboseLogging);
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
     * <p>Only a file that isn't there, not even as a link, means
     * {@link #defaults()}. Once a file is there, anything short of settings
     * LibreProtect understands means {@link #failClosed()}: a file that can't
     * be read or isn't a regular file, invalid YAML, a file without settings
     * (such as a write that was cut short), a setting LibreProtect doesn't
     * know (such as a mistyped {@code preset}), or an unknown preset.
     *
     * @param file the settings file
     */
    public static PrivacyConfig load(File file) {
        Path path = file.toPath();
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) {
            return defaults();
        }

        YamlConfiguration yaml = new YamlConfiguration();
        TopLevelKeys keys;
        try {
            String text = read(path);
            yaml.loadFromString(text);
            keys = TopLevelKeys.of(text);
        } catch (IOException | InvalidConfigurationException e) {
            LibreProtectLogger.severe("Could not read " + file + ", blocking all network requests: " + e.getMessage());
            return failClosed();
        }
        if (keys.none) {
            LibreProtectLogger.warning(file + " has no settings, blocking all network requests. Delete it to have "
                + PrivacyConstants.FORK_NAME + " write the default file at the next start");
            return failClosed();
        }
        if (!keys.unknown.isEmpty()) {
            LibreProtectLogger.warning(file + " has settings " + PrivacyConstants.FORK_NAME + " doesn't know: "
                + String.join(", ", keys.unknown) + ". Blocking all network requests until the file is fixed");
            return failClosed();
        }
        return fromYaml(yaml, keys.withoutValue);
    }

    /**
     * @return the text of a regular file, following links
     * @throws IOException if it isn't a regular file, such as a directory, a
     *         link to nothing, or a named pipe that would hold up the server's
     *         start, or if it is larger than {@value #MAX_FILE_BYTES} bytes
     */
    private static String read(Path path) throws IOException {
        if (!Files.isRegularFile(path)) {
            throw new IOException(Files.isDirectory(path) ? "it is a directory"
                : Files.isSymbolicLink(path) && Files.notExists(path) ? "it is a link to a file that doesn't exist"
                : "it isn't a regular file");
        }
        try (InputStream in = Files.newInputStream(path)) {
            byte[] bytes = in.readNBytes(MAX_FILE_BYTES + 1);
            if (bytes.length > MAX_FILE_BYTES) {
                throw new IOException("it is larger than " + MAX_FILE_BYTES / 1024 / 1024 + " MiB");
            }
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    /**
     * The keys of a document's top-level mapping, from SnakeYAML's node
     * tree, which builds no objects. Bukkit's view of the document drops keys
     * without a value and splits keys at dots, so it can't tell what the file
     * says.
     */
    static final class TopLevelKeys {

        /** Whether the document has no keys at all, like a file of only comments */
        boolean none = true;
        /**
         * The keys that aren't settings in {@link PrivacyConfigSchema},
         * described for a message, in order: {@code 'Preset'}
         */
        final Set<String> unknown = new LinkedHashSet<>();
        /**
         * The keys whose last entry has no value, as {@code update-sources:}
         * once every source is commented out
         */
        final Set<String> withoutValue = new HashSet<>();

        private TopLevelKeys() {
        }

        /**
         * @throws InvalidConfigurationException if SnakeYAML can't read the
         *         document with its default limits, which are stricter than
         *         Bukkit's
         */
        static TopLevelKeys of(String text) throws InvalidConfigurationException {
            Node root;
            try {
                root = new Yaml().compose(new StringReader(text));
            } catch (RuntimeException e) {
                throw new InvalidConfigurationException(e.getMessage(), e);
            }
            TopLevelKeys keys = new TopLevelKeys();
            if (!(root instanceof MappingNode)) {
                return keys;
            }
            for (NodeTuple entry : ((MappingNode) root).getValue()) {
                keys.none = false;
                Node name = entry.getKeyNode();
                if (!(name instanceof ScalarNode)) {
                    keys.unknown.add("a key that isn't text on line " + (name.getStartMark().getLine() + 1));
                    continue;
                }
                String key = ((ScalarNode) name).getValue();
                if (PrivacyConfigSchema.getOption(key) == null) {
                    keys.unknown.add("'" + key + "'");
                }
                // As in YAML, a later entry with the same key wins
                Node value = entry.getValueNode();
                if (value instanceof ScalarNode && Tag.NULL.equals(value.getTag())) {
                    keys.withoutValue.add(key);
                } else {
                    keys.withoutValue.remove(key);
                }
            }
            return keys;
        }
    }

    static PrivacyConfig fromYaml(ConfigurationSection yaml) {
        return fromYaml(yaml, Collections.emptySet());
    }

    /**
     * @param keysWithoutValue the file's top-level keys without a value, such
     *        as {@code update-sources:}, which the section doesn't show
     */
    static PrivacyConfig fromYaml(ConfigurationSection yaml, Set<String> keysWithoutValue) {
        boolean verboseLogging = parseBoolean(
            yaml.get(PrivacyConfigSchema.VERBOSE_LOGGING.key),
            (Boolean) PrivacyConfigSchema.VERBOSE_LOGGING.defaultValue);

        Object presetValue = yaml.get(PrivacyConfigSchema.PRESET.key);
        if (presetValue instanceof ConfigurationSection || presetValue instanceof List) {
            LibreProtectLogger.warning("'" + PrivacyConfigSchema.PRESET.key + "' in " + FILE_NAME
                + " must be a preset name, not " + (presetValue instanceof List ? "a list" : "a section")
                + ", blocking all network requests."
                + " The presets are " + String.join(", ", RoutePreset.getAvailablePresets()));
            return failClosed(verboseLogging);
        }
        // A preset without a value names no preset, as an empty one does, rather than meaning the default
        String presetName = keysWithoutValue.contains(PrivacyConfigSchema.PRESET.key) ? ""
            : yaml.getString(PrivacyConfigSchema.PRESET.key, (String) PrivacyConfigSchema.PRESET.defaultValue);
        if (!PrivacyConfigSchema.isValidValue(PrivacyConfigSchema.PRESET.key, presetName)) {
            LibreProtectLogger.warning("Unknown preset '" + presetName + "' in " + FILE_NAME
                + ", blocking all network requests."
                + " The presets are " + String.join(", ", RoutePreset.getAvailablePresets()));
            // Verbose logging still shows what is blocked while the file is being fixed
            return failClosed(verboseLogging);
        }
        RoutePreset preset = RoutePreset.fromConfigName(presetName);

        Object routes = yaml.get(PrivacyConfigSchema.ROUTES.key);
        if (routes != null && !(routes instanceof List)) {
            LibreProtectLogger.warning("'" + PrivacyConfigSchema.ROUTES.key + "' in " + FILE_NAME
                + " must be a list, ignoring it");
        }
        List<Route> customRoutes = new RouteConfigParser().parseRoutes(yaml.getList(PrivacyConfigSchema.ROUTES.key));

        List<UpdateSource> updateSources = parseUpdateSources(yaml.get(PrivacyConfigSchema.UPDATE_SOURCES.key),
            keysWithoutValue.contains(PrivacyConfigSchema.UPDATE_SOURCES.key));

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
     * Write the commented default settings file if nothing is in its place
     * yet, not even a link. Links aren't followed, so a link to nothing
     * doesn't get a file written where it points.
     *
     * @return {@code true} if the file was written
     */
    public static boolean writeDefaultIfMissing(File file) throws IOException {
        try {
            Files.write(file.toPath(), PrivacyConfigSchema.generateDefaultFile().getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE_NEW);
            return true;
        } catch (FileAlreadyExistsException e) {
            return false;
        }
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
