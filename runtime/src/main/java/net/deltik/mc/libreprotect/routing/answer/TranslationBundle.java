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

/*
 * Portions of this file are copied or adapted from CoreProtect
 * <https://github.com/PlayPro/CoreProtect>:
 *
 * Copyright (c) Intelli and the CoreProtect contributors
 *
 * CoreProtect is licensed under the Artistic License 2.0 (see
 * LICENSES/Artistic-2.0.txt). As section 4(c)(ii) of that license
 * permits, LibreProtect distributes these portions under the
 * GNU General Public License, version 3 or later. See NOTICE.
 */

package net.deltik.mc.libreprotect.routing.answer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;

/**
 * The translations in CoreProtect's source code, in {@code lang/}, which
 * CoreProtect's JAR leaves out. LibreProtect's build copies them unchanged
 * into {@value #DIRECTORY} of the plugin JAR, one {@code <language>.yml} per
 * language. The build also takes CoreProtect's built-in English phrases from
 * its code, into {@value #DEFAULTS}.
 *
 * <p>Each file is read once, a language file the way CoreProtect reads its
 * {@code language.yml}.
 */
final class TranslationBundle {

    /** Where the build puts the files in the plugin JAR */
    static final String DIRECTORY = "META-INF/libreprotect/lang/";

    /** CoreProtect's built-in English phrases, as Java properties, by phrase name */
    static final String DEFAULTS = "defaults.properties";

    /** Opens a bundled file by name */
    @FunctionalInterface
    interface Source {

        /**
         * @return the file's content, or {@code null} if there is no such file
         */
        InputStream open(String name) throws IOException;
    }

    private static final TranslationBundle BUNDLED = new TranslationBundle(name ->
        TranslationBundle.class.getClassLoader().getResourceAsStream(DIRECTORY + name));

    /**
     * Codes that can name a bundled language: parts of lowercase letters and
     * digits, joined by dashes. Nothing else can become a file name.
     */
    private static final Pattern CODE = Pattern.compile("[a-z0-9]{1,8}(-[a-z0-9]{1,8}){0,4}");

    /**
     * Other codes for a bundled language, as CoreProtect's documentation and
     * locales write them. Chinese needs these because the base language
     * alone doesn't say which script to use.
     */
    private static final Map<String, String> ALIASES;

    static {
        Map<String, String> aliases = new HashMap<>();
        aliases.put("zh", "zh-cn");
        aliases.put("zh-hans", "zh-cn");
        aliases.put("zh-sg", "zh-cn");
        aliases.put("zh-hant", "zh-tw");
        aliases.put("zh-hk", "zh-tw");
        aliases.put("zh-mo", "zh-tw");
        aliases.put("iw", "he");
        ALIASES = Collections.unmodifiableMap(aliases);
    }

    private final Source source;
    private final ConcurrentMap<String, Optional<Map<String, String>>> files = new ConcurrentHashMap<>();
    private volatile Map<String, String> defaults;

    TranslationBundle(Source source) {
        this.source = source;
    }

    /**
     * @return the translations in the plugin JAR
     */
    static TranslationBundle bundled() {
        return BUNDLED;
    }

    /**
     * Find the bundled language for a setting like CoreProtect's
     * {@code language}: the language itself, then an alias, such as
     * {@code zh-cn} for {@code zh}, then the same for the code without its
     * last part, such as {@code de} for {@code de-at}. Case and {@code _}
     * instead of {@code -} don't matter, nor does a dotless {@code ı}, which
     * CoreProtect's lowercasing makes of an {@code I} on a Turkish system.
     *
     * @return the bundled language's code, or {@code null} if none fits
     */
    String resolve(String language) throws IOException {
        String code = language == null ? ""
            : language.trim().toLowerCase(Locale.ROOT).replace('_', '-').replace('ı', 'i');
        if (!CODE.matcher(code).matches()) {
            return null;
        }
        while (true) {
            if (phrases(code) != null) {
                return code;
            }
            String alias = ALIASES.get(code);
            if (alias != null && phrases(alias) != null) {
                return alias;
            }
            int dash = code.lastIndexOf('-');
            if (dash < 0) {
                return null;
            }
            code = code.substring(0, dash);
        }
    }

    /**
     * @param language a bundled language's code, as {@link #resolve} returns it
     * @return the language's phrases by phrase name, unmodifiable, or
     *         {@code null} if the language isn't bundled
     */
    Map<String, String> phrases(String language) throws IOException {
        Optional<Map<String, String>> file = files.get(language);
        if (file == null) {
            try (InputStream in = source.open(language + ".yml")) {
                file = Optional.ofNullable(in == null ? null : Collections.unmodifiableMap(parse(in)));
            }
            files.putIfAbsent(language, file);
        }
        return file.orElse(null);
    }

    /**
     * @return CoreProtect's built-in English phrases by phrase name,
     *         unmodifiable, which a server sends for the phrases it didn't
     *         customize, or {@code null} if they aren't bundled
     */
    Map<String, String> defaults() throws IOException {
        Map<String, String> read = defaults;
        if (read == null) {
            try (InputStream in = source.open(DEFAULTS)) {
                if (in == null) {
                    return null;
                }
                Properties properties = new Properties();
                properties.load(new InputStreamReader(in, StandardCharsets.UTF_8));
                Map<String, String> phrases = new HashMap<>();
                properties.stringPropertyNames().forEach(name -> phrases.put(name, properties.getProperty(name)));
                read = Collections.unmodifiableMap(phrases);
            }
            defaults = read;
        }
        return read;
    }

    /**
     * Read a language file with the rules of CoreProtect's
     * {@code ConfigFile.load}: lines starting with {@code #} are comments;
     * other lines are split at the first {@code :} into a phrase name, in
     * uppercase, and its text; both are trimmed; and matching quotes around
     * the text are removed, along with their escapes.
     *
     * @return the phrases by name, in the file's order
     */
    static Map<String, String> parse(InputStream in) throws IOException {
        Map<String, String> phrases = new LinkedHashMap<>();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        for (String line = reader.readLine(); line != null; line = reader.readLine()) {
            int split = line.indexOf(':');
            if (line.startsWith("#") || split < 0) {
                continue;
            }
            String name = line.substring(0, split).trim().toUpperCase(Locale.ROOT);
            String text = line.substring(split + 1).trim();
            if (text.length() >= 2 && text.startsWith("'") && text.endsWith("'")) {
                text = text.substring(1, text.length() - 1).replace("''", "'").replace("\\'", "'")
                    .replace("\\\\", "\\");
            } else if (text.length() >= 2 && text.startsWith("\"") && text.endsWith("\"")) {
                text = text.substring(1, text.length() - 1).replace("\\\"", "\"").replace("\\\\", "\\");
            }
            phrases.put(name, text);
        }
        return phrases;
    }
}
