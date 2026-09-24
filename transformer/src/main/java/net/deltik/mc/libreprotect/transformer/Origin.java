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

package net.deltik.mc.libreprotect.transformer;

/**
 * Where a class in the upstream JAR came from.
 */
enum Origin {
    /** Compiled from upstream CoreProtect's own source (present in the unshaded JAR). */
    UPSTREAM,
    /** A third-party library that upstream's build shaded into the JAR, such as bStats. */
    LIBRARY,
    /** A shaded library that is exempt from egress rewriting, such as a database driver. */
    EXEMPT_LIBRARY
}
