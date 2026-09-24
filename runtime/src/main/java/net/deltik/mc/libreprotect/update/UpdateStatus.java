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

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The newer release that LibreProtect last told CoreProtect about, if any,
 * and the ones it told CoreProtect about before.
 *
 * <p>CoreProtect only understands its own version numbers, so
 * {@link UpdateCheck} reports a stand-in, the synthetic version, and
 * {@link UpdatePhrases} shows the release in its place wherever CoreProtect
 * shows it.
 *
 * <p>CoreProtect can show a synthetic version after a later check has
 * replaced or forgotten its release: it records the reply only after
 * LibreProtect has answered, so two checks at once can finish in either
 * order, and its notice to operators shows what it recorded 5 seconds
 * earlier. So the last few synthetic versions and their releases are kept.
 */
public final class UpdateStatus {

    /** How many synthetic versions to remember */
    static final int HISTORY = 8;

    private static volatile Known current;
    private static volatile Known lastReported;
    /** The releases reported by synthetic version, the most recent last */
    private static final Map<String, Known> REPORTED = new LinkedHashMap<>();

    private UpdateStatus() {
    }

    /**
     * A newer release and the synthetic version reported for it
     */
    public static final class Known {

        private final Release release;
        private final String syntheticVersion;

        Known(Release release, String syntheticVersion) {
            this.release = Objects.requireNonNull(release, "release");
            this.syntheticVersion = Objects.requireNonNull(syntheticVersion, "syntheticVersion");
        }

        /**
         * @return the release's version, such as {@code 24.1-libre2}
         */
        public String version() {
            return release.version().toString();
        }

        /**
         * @return the release's page, such as
         *         {@code https://modrinth.com/plugin/libreprotect/version/24.1-libre2}
         */
        public String pageUrl() {
            return release.pageUrl();
        }

        /**
         * @return the release's page without the scheme, the way CoreProtect
         *         shows links in chat
         */
        public String displayUrl() {
            return release.pageUrl().replaceFirst("^https?://", "");
        }

        /**
         * @return the version that CoreProtect was told, such as {@code 24.1.1}
         */
        public String syntheticVersion() {
            return syntheticVersion;
        }
    }

    /**
     * @return the newer release that the last successful check found, or
     *         {@code null} if it found none
     */
    public static Known current() {
        return current;
    }

    /**
     * @return the release most recently reported with this synthetic
     *         version, or {@code null} if it wasn't among the last
     *         {@value #HISTORY} reported
     */
    public static Known reported(String syntheticVersion) {
        synchronized (REPORTED) {
            return REPORTED.get(syntheticVersion);
        }
    }

    /**
     * @return the release reported most recently, even if a later check
     *         found none, or {@code null} if none was ever reported
     */
    public static Known lastReported() {
        return lastReported;
    }

    static void set(Release release, String syntheticVersion) {
        Known known = new Known(release, syntheticVersion);
        synchronized (REPORTED) {
            REPORTED.remove(syntheticVersion);
            REPORTED.put(syntheticVersion, known);
            Iterator<String> oldest = REPORTED.keySet().iterator();
            while (REPORTED.size() > HISTORY) {
                oldest.next();
                oldest.remove();
            }
            lastReported = known;
            current = known;
        }
    }

    /**
     * Forget the current release, as when a check finds nothing newer; the
     * ones reported stay known for what CoreProtect may still show
     */
    static void clear() {
        current = null;
    }

    /** Forget everything, for tests */
    static void reset() {
        synchronized (REPORTED) {
            REPORTED.clear();
            lastReported = null;
            current = null;
        }
    }
}
