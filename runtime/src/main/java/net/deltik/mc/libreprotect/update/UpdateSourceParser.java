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

package net.deltik.mc.libreprotect.update;

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.PrivacyConfig;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Parses {@code update-sources} from {@code libreprotect.yml}.
 *
 * <p>Expected format:
 * <pre>
 * - type: github
 *   repository: Deltik/LibreProtect
 *   api: https://api.github.com
 * - type: modrinth
 *   project: libreprotect
 * </pre>
 *
 * <p>Each entry has a {@code type} and the settings of that type, and
 * optionally {@code api}, the base URL of the API, for a mirror. An entry
 * with a problem is skipped with a warning, and the others are kept.
 */
public final class UpdateSourceParser {

    /** A Modrinth project ID (such as {@code TGIIS09S}) or slug (such as {@code libreprotect}) */
    private static final Pattern PROJECT = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]{0,63}");
    /** A GitHub account and repository name */
    private static final Pattern REPOSITORY = Pattern.compile("[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}");

    /**
     * @param configs the {@code update-sources} list; {@code null} gives no sources
     * @return the valid sources, in order
     */
    public List<UpdateSource> parse(List<?> configs) {
        List<UpdateSource> sources = new ArrayList<>();
        if (configs == null) {
            return sources;
        }
        for (int i = 0; i < configs.size(); i++) {
            Object item = configs.get(i);
            if (!(item instanceof Map)) {
                skip(i + 1, "it isn't a map with a type and its settings");
                continue;
            }
            UpdateSource source = parseSource((Map<?, ?>) item, i + 1);
            if (source != null) {
                sources.add(source);
            }
        }
        return sources;
    }

    private UpdateSource parseSource(Map<?, ?> config, int index) {
        String type = text(config.get("type"));
        if (type == null) {
            return skip(index, "it has no 'type'");
        }
        type = type.toLowerCase(Locale.ROOT);
        if (!type.equals(ModrinthSource.TYPE) && !type.equals(GitHubSource.TYPE)) {
            return skip(index, "its type '" + type + "' isn't " + ModrinthSource.TYPE + " or " + GitHubSource.TYPE);
        }

        String api = null;
        if (config.get("api") != null) {
            api = api(text(config.get("api")));
            if (api == null) {
                return skip(index, "its api '" + config.get("api") + "' isn't an http or https URL");
            }
        }

        if (type.equals(ModrinthSource.TYPE)) {
            String project = text(config.get("project"));
            if (project == null) {
                return skip(index, "it has no 'project'");
            }
            if (!PROJECT.matcher(project).matches()) {
                return skip(index, "its project '" + project + "' isn't a Modrinth project ID or slug");
            }
            return new ModrinthSource(project, api != null ? api : ModrinthSource.DEFAULT_API);
        }

        String repository = text(config.get("repository"));
        if (repository == null) {
            return skip(index, "it has no 'repository'");
        }
        String name = repository.substring(repository.indexOf('/') + 1);
        if (!REPOSITORY.matcher(repository).matches() || name.equals(".") || name.equals("..")) {
            return skip(index, "its repository '" + repository + "' isn't shaped owner/name");
        }
        return new GitHubSource(repository, api != null ? api : GitHubSource.DEFAULT_API);
    }

    /**
     * @return the value as trimmed text, or {@code null} if it is missing or blank
     */
    private static String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }

    /**
     * @return the base URL without final slashes, or {@code null} unless it is
     *         an http or https URL with a host and without user info, query or
     *         fragment
     */
    static String api(String value) {
        if (value == null) {
            return null;
        }
        URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException e) {
            return null;
        }
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))
            || uri.getHost() == null || uri.getRawUserInfo() != null
            || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            return null;
        }
        String api = value;
        while (api.endsWith("/")) {
            api = api.substring(0, api.length() - 1);
        }
        return api;
    }

    private static UpdateSource skip(int index, String reason) {
        LibreProtectLogger.warning("Skipping update source #" + index + " in " + PrivacyConfig.FILE_NAME + ": "
            + reason);
        return null;
    }
}
