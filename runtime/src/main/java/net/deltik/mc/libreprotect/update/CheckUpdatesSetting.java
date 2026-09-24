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

package net.deltik.mc.libreprotect.update;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Objects;

/**
 * CoreProtect's {@code check-updates} setting, read from its
 * {@code config.yml} whenever it is needed.
 *
 * <p>CoreProtect reads the setting when it starts and on {@code /co reload},
 * but once its hourly update check is running, it keeps running until the
 * server stops, even after a reload turns the setting off. Reading the file
 * again before each check lets LibreProtect leave the update sources alone
 * as soon as the operator turns update checks off.
 *
 * <p>The file is read the way CoreProtect reads it ({@code ConfigFile.load}
 * and {@code Config.getBoolean}), not as YAML, so both agree on what it says:
 * every line that doesn't start with {@code #} is a key and a value split
 * at the first colon, the last line with the key wins, and a value is on if
 * it starts with {@code t}. Without the key, the setting is on, as it is in
 * CoreProtect.
 */
final class CheckUpdatesSetting {

    static final String KEY = "check-updates";

    private final File file;

    /**
     * @param file CoreProtect's {@code config.yml}
     */
    CheckUpdatesSetting(File file) {
        this.file = Objects.requireNonNull(file, "file");
    }

    File file() {
        return file;
    }

    /**
     * @return whether update checks are on
     * @throws IOException if the file exists but can't be read
     */
    boolean isOn() throws IOException {
        if (!file.exists()) {
            return true;
        }
        String text = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        String value = null;
        BufferedReader lines = new BufferedReader(new StringReader(text));
        for (String line = lines.readLine(); line != null; line = lines.readLine()) {
            int split = line.indexOf(':');
            if (line.startsWith("#") || split == -1 || !line.substring(0, split).trim().equals(KEY)) {
                continue;
            }
            value = unquote(line.substring(split + 1).trim());
        }
        return value == null || value.startsWith("t");
    }

    /** CoreProtect's handling of quoted values, as far as the first character goes */
    private static String unquote(String value) {
        if (value.length() >= 2 && ((value.startsWith("'") && value.endsWith("'"))
            || (value.startsWith("\"") && value.endsWith("\"")))) {
            return value.substring(1, value.length() - 1);
        }
        return value;
    }
}
