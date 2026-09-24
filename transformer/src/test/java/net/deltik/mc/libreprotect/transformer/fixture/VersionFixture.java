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

package net.deltik.mc.libreprotect.transformer.fixture;

import org.bukkit.plugin.PluginDescriptionFile;

/**
 * Mirrors the shape of upstream's {@code VersionUtils.getPluginVersion()}.
 */
public class VersionFixture {

    public static PluginDescriptionFile description =
        new PluginDescriptionFile("CoreProtect", "24.0-121-gd5cad31-libre-dev", "net.coreprotect.CoreProtect");

    public static String getPluginVersion() {
        String version = description.getVersion();
        if (version.contains("-")) {
            version = version.split("-")[0];
        }
        return version;
    }

    /** Shows the version, as {@code /co status} does: must be left alone */
    public static String shownVersion() {
        return "v" + description.getVersion();
    }

    /** Same name, but not static: must be left alone */
    public String getPluginVersion(PluginDescriptionFile other) {
        return other.getVersion();
    }
}
