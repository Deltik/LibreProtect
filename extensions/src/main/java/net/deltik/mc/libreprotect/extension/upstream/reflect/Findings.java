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

package net.deltik.mc.libreprotect.extension.upstream.reflect;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * What probing one way found: every upstream member it resolved, in the
 * capability report's forms, and what it relies on beyond them.
 */
final class Findings {

    /** Classes, fields and methods the way needs */
    final Set<String> members = new TreeSet<>();
    /** Members the way uses where upstream has them, and whether it has them */
    final Map<String, Boolean> optional = new TreeMap<>();
    /** Upstream methods whose behavior the way relies on, and what it relies on */
    final Map<String, String> relies = new TreeMap<>();
    /** Upstream enums the way depends on, with their constants in declaration order */
    final Map<String, List<String>> enums = new TreeMap<>();
    /** Upstream's documentation the way follows, by path in its source tree */
    final Map<String, String> docs = new TreeMap<>();
}
