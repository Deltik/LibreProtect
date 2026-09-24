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

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Build information for this LibreProtect JAR.
 *
 * <p>The transformer writes {@value #RESOURCE} into the JAR when it builds
 * LibreProtect. It also records the commits the JAR was built from. Values
 * fall back to {@code "unknown"} when the resource is absent, as in unit
 * tests.
 */
public final class LibreProtectVersion {

    public static final String RESOURCE = "/libreprotect-build.properties";

    private static final Properties PROPERTIES = load();

    private LibreProtectVersion() {
    }

    private static Properties load() {
        Properties properties = new Properties();
        try (InputStream is = LibreProtectVersion.class.getResourceAsStream(RESOURCE)) {
            if (is != null) {
                properties.load(is);
            }
        } catch (IOException e) {
            LibreProtectLogger.warning("Failed to load build information: " + e.getMessage());
        }
        return properties;
    }

    private static String get(String key) {
        return PROPERTIES.getProperty(key, "unknown");
    }

    /**
     * @return the plugin version, such as {@code 24.1-libre1}
     */
    public static String getForkVersion() {
        return get("fork.version");
    }
}
