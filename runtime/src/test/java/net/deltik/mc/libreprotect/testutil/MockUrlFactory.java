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

package net.deltik.mc.libreprotect.testutil;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

/**
 * Factory for creating test URLs without network access.
 */
public class MockUrlFactory {

    /**
     * Create a URL from a string spec, throwing RuntimeException on error.
     */
    public static URL createUrl(String spec) {
        try {
            return URI.create(spec).toURL();
        } catch (MalformedURLException | IllegalArgumentException e) {
            throw new RuntimeException("Invalid test URL: " + spec, e);
        }
    }

    // Common CoreProtect telemetry URLs

    /**
     * License validation endpoint.
     */
    public static URL licenseUrl() {
        return createUrl("http://coreprotect.net/license/TESTKEY");
    }

    /**
     * License validation endpoint with custom key.
     */
    public static URL licenseUrl(String key) {
        return createUrl("http://coreprotect.net/license/" + key);
    }

    /**
     * Translation endpoint.
     */
    public static URL translateUrl() {
        return createUrl("http://coreprotect.net/translate/");
    }

    /**
     * Update check endpoint.
     */
    public static URL updateUrl() {
        return createUrl("http://update.coreprotect.net/version/");
    }

    /**
     * Edge update check endpoint.
     */
    public static URL updateEdgeUrl() {
        return createUrl("http://update.coreprotect.net/version-edge/");
    }

    /**
     * Statistics endpoint.
     */
    public static URL statsUrl() {
        return createUrl("http://stats.coreprotect.net/u/");
    }

    /**
     * Error reporting endpoint.
     */
    public static URL errorReportingUrl() {
        return createUrl("https://error-reporting.coreprotect.net/submit");
    }

    /**
     * bStats submission endpoint, spelled the way bStats spells it.
     */
    public static URL bstatsUrl() {
        return createUrl("https://bStats.org/api/v2/data/bukkit");
    }

    /**
     * Unknown/external domain.
     */
    public static URL unknownUrl() {
        return createUrl("https://unknown.example.com/path");
    }

    /**
     * HTTPS variant of license URL.
     */
    public static URL httpsLicenseUrl() {
        return createUrl("https://coreprotect.net/license/TESTKEY");
    }

    /**
     * HTTPS variant of stats URL.
     */
    public static URL httpsStatsUrl() {
        return createUrl("https://stats.coreprotect.net/submit");
    }
}
