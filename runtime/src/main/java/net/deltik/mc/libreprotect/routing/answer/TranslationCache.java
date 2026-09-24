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

package net.deltik.mc.libreprotect.routing.answer;

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.LibreProtectVersion;
import net.deltik.mc.libreprotect.PrivacyConstants;
import net.deltik.mc.libreprotect.routing.RouteRegistry;
import net.deltik.mc.libreprotect.routing.RouteResolver;
import net.deltik.mc.libreprotect.routing.UrlNormalizer;
import net.deltik.mc.libreprotect.routing.UrlPatternMatcher;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.util.regex.Pattern;

/**
 * Keeps CoreProtect's translation cache in step with where translations come
 * from.
 *
 * <p>CoreProtect saves translations to {@value #CACHE} and asks for them
 * again only when its version, its {@code language} setting or
 * {@code language.yml} changes. Where they come from is up to the network
 * policy, so LibreProtect records in {@value #MARKER} what wrote the cache.
 * When the policy's source differs from the record and can replace what is
 * cached, LibreProtect empties the cache as it starts, the way CoreProtect's
 * {@code ConfigFile.resetCache} does, and CoreProtect translates again. A
 * source is one of:
 * <ul>
 *   <li>LibreProtect with its version, whose bundled translations answered:
 *       a new version may bundle other translations, and answering again
 *       costs nothing;</li>
 *   <li>CoreProtect's translation service, under which LibreProtect's own
 *       version doesn't count, since asking again would send a request that
 *       CoreProtect wouldn't;</li>
 *   <li>the bundled translations alone, because the service failed (see
 *       {@link LayeredTranslationAnswer}). CoreProtect saves no cache when its
 *       request fails, and so asks again at its next start; this source makes
 *       the next start do the same;</li>
 *   <li>a redirect's URL, without user info;</li>
 *   <li>translations from before LibreProtect: a cache found without a
 *       record. Only CoreProtect's translation service writes those, so
 *       when the policy passes translation requests through, the cache is
 *       recorded as the service's instead, and kept.</li>
 * </ul>
 *
 * <p>LibreProtect never discards translations that it can't replace. A
 * blocked request replaces nothing, and LibreProtect's bundle replaces only a
 * language that it bundles, and never translations from before LibreProtect.
 * The service and redirects replace anything, since an admin chose them.
 *
 * <p>An answer records what wrote the cache as it is given; a redirect, which
 * LibreProtect doesn't answer, is recorded as the plugin starts. A record
 * that can't be written leaves the cache alone, and a cache that can't be
 * emptied keeps its old record, so that neither makes every start refresh,
 * nor none.
 */
public final class TranslationCache {

    /**
     * CoreProtect's language cache in its data folder, as its
     * {@code ConfigFile.LANGUAGE_CACHE} names it. The transformer checks
     * that upstream still uses this name.
     */
    static final String CACHE = ".language";

    /** LibreProtect's record of what wrote the cached translations */
    static final String MARKER = ".libreprotect-language";

    /** The URL of CoreProtect's translation request */
    static final String TRANSLATE_URL = "http://coreprotect.net/translate/";

    static final String SERVICE = "CoreProtect's translation service";
    static final String SERVICE_FAILED = "LibreProtect's bundled translations alone, since " + SERVICE + " failed";
    static final String KEPT = "CoreProtect's translations from before LibreProtect";

    private static final String BUNDLED = PrivacyConstants.FORK_NAME + " ";
    private static final Pattern URL_SOURCE = Pattern.compile("[a-z][a-z0-9+.-]*://.*");
    /** What could split a recorded URL over lines */
    private static final Pattern LINE_BREAKS = Pattern.compile("[\\p{Cntrl}\\u0085\\u2028\\u2029]");
    private static final String HEADER = "# What wrote the translations in " + CACHE + ", as "
        + PrivacyConstants.FORK_NAME + " last saw it. When the\n# network policy gets them from somewhere else, "
        + PrivacyConstants.FORK_NAME + " empties " + CACHE + ", and CoreProtect\n# translates again.\n";

    private static volatile File marker;

    private TranslationCache() {
    }

    /**
     * Empty the cache if the installed policy gets translations from
     * somewhere else that can replace them, and record where they come
     * from. Called as the plugin loads, before CoreProtect reads its cache.
     * Never throws.
     *
     * @param dataFolder CoreProtect's data folder
     * @param resolver   the installed policy
     */
    public static void update(File dataFolder, RouteResolver resolver) {
        try {
            update(dataFolder, resolver, LibreProtectVersion.getForkVersion(), TranslationBundle.bundled());
        } catch (Exception | LinkageError e) {
            try {
                LibreProtectLogger.warning("Could not refresh CoreProtect's translations: " + e);
            } catch (RuntimeException | LinkageError ignored) {
                // CoreProtect keeps its cache
            }
        }
    }

    /**
     * @param version LibreProtect's version
     * @param bundle  LibreProtect's bundled translations
     * @see #update(File, RouteResolver)
     */
    static void update(File dataFolder, RouteResolver resolver, String version, TranslationBundle bundle)
        throws IOException {
        File markerFile = new File(dataFolder.getAbsoluteFile(), MARKER);
        marker = markerFile;
        String source = source(resolver.getRegistry(), version);
        // CoreProtect creates its folder only after this, at its first start, when there is no cache yet
        if (source == null || !dataFolder.isDirectory()) {
            return;
        }
        String recorded = recorded(markerFile);
        File cache = new File(dataFolder, CACHE);
        String language = cachedLanguage(cache);
        if (language == null) {
            if (!source.equals(recorded)) {
                record(markerFile, source);
            }
            return;
        }
        if (recorded == null) {
            // The cache is from before LibreProtect, when only CoreProtect's translation service wrote it
            if (SERVICE.equals(source) || source.startsWith(BUNDLED)) {
                record(markerFile, SERVICE.equals(source) ? SERVICE : KEPT);
                return;
            }
            recorded = KEPT;
        }
        if (source.equals(recorded)) {
            return;
        }
        if (!replaces(source, recorded, language, bundle)) {
            LibreProtectLogger.debug("Keeping the cached translations for '" + language + "' from " + recorded
                + ", which " + source + " can't replace");
            return;
        }

        record(markerFile, source);
        try {
            new FileOutputStream(cache).close();
        } catch (IOException e) {
            // The next start tries again
            record(markerFile, recorded);
            throw e;
        }
        LibreProtectLogger.info(SERVICE_FAILED.equals(recorded) && SERVICE.equals(source)
            ? "Asking " + SERVICE + " for translations again, since it failed last time"
            : "Refreshing translations, since they now come from " + source + " instead of " + recorded);
    }

    /**
     * Record what gave the translation answer that CoreProtect saves. Does
     * nothing before {@link #update} or if CoreProtect's folder is gone.
     * Never throws.
     */
    static void answered(String source) {
        File file = marker;
        if (file == null || !file.getParentFile().isDirectory()) {
            return;
        }
        try {
            record(file, source);
        } catch (IOException | RuntimeException e) {
            LibreProtectLogger.warning("Could not record in " + file.getPath() + " where translations came from: "
                + e);
        }
    }

    /**
     * @return the source that LibreProtect's bundled translations of this
     *         version are recorded as
     */
    static String bundled(String version) {
        return BUNDLED + version;
    }

    /**
     * @return where CoreProtect's translation request goes under the
     *         registry, or {@code null} if nothing can answer it
     */
    static String source(RouteRegistry registry, String version) throws IOException {
        RouteRegistry.RouteMatch match = registry.match(UrlNormalizer.normalize(URI.create(TRANSLATE_URL).toURL()));
        switch (match.getActionType()) {
            case ANSWER:
                return bundled(version);
            case PASSTHROUGH:
                return SERVICE;
            case REDIRECT:
                return redirect(match);
            default:
                return null;
        }
    }

    /**
     * @return the redirect's URL as {@code RedirectAction} parses it, which
     *         ignores surrounding whitespace, without user info and on one
     *         line, or {@code null} if it isn't a URL
     */
    private static String redirect(RouteRegistry.RouteMatch match) {
        String target = match.getRoute().getTarget();
        if (target == null || target.isEmpty()) {
            return null;
        }
        try {
            URL url = new URL(UrlPatternMatcher.substituteCaptures(target, match.getCaptures()));
            return LINE_BREAKS.matcher(UrlNormalizer.normalize(url)).replaceAll("?");
        } catch (MalformedURLException e) {
            return null;
        }
    }

    /**
     * Whether emptying the cache for the source loses nothing that the
     * source can't give back: the service and redirects, which an admin
     * chose, replace anything; the bundle replaces only a language that it
     * bundles, and never translations from before LibreProtect.
     */
    private static boolean replaces(String source, String recorded, String language, TranslationBundle bundle)
        throws IOException {
        if (!source.startsWith(BUNDLED)) {
            return true;
        }
        return !KEPT.equals(recorded) && bundle.resolve(language) != null;
    }

    /**
     * Read the record leniently: bytes that aren't UTF-8 don't stop it, and
     * a record that LibreProtect doesn't know counts as none.
     *
     * @return the recorded source, or {@code null} if there is no record
     */
    static String recorded(File file) throws IOException {
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(file.toPath());
        } catch (NoSuchFileException e) {
            return null;
        }
        for (String line : new String(bytes, StandardCharsets.UTF_8).split("\\R")) {
            String source = line.trim();
            if (!source.isEmpty() && !source.startsWith("#")) {
                boolean known = source.equals(SERVICE) || source.equals(SERVICE_FAILED) || source.equals(KEPT)
                    || source.startsWith(BUNDLED) || URL_SOURCE.matcher(source).matches();
                return known ? source : null;
            }
        }
        return null;
    }

    /**
     * @return the cached language, from the header that CoreProtect writes
     *         and checks, {@code # CoreProtect v24.1 Language Cache (de)}, or
     *         {@code null} if nothing is cached
     */
    static String cachedLanguage(File cache) throws IOException {
        if (!cache.isFile() || cache.length() == 0) {
            return null;
        }
        String header;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(cache),
            StandardCharsets.UTF_8))) {
            header = reader.readLine();
        }
        if (header == null || !header.startsWith("# CoreProtect")) {
            return null;
        }
        String[] parts = header.split(" ");
        return parts.length == 6 && parts[5].length() > 2 ? parts[5].substring(1, parts[5].length() - 1) : null;
    }

    private static synchronized void record(File file, String source) throws IOException {
        Files.write(file.toPath(), (HEADER + source + "\n").getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Forget the record's location (for tests)
     */
    static void reset() {
        marker = null;
    }
}
