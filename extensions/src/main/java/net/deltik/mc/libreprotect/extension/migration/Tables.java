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

package net.deltik.mc.libreprotect.extension.migration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;

/**
 * What the migration knows about CoreProtect's tables, by unprefixed name.
 */
final class Tables {

    /** Operational state of the database itself, never copied */
    static final String DATABASE_LOCK = "database_lock";

    /** Schema versions; a ClickHouse database keeps only its own */
    static final String VERSION = "version";

    /** Tables every CoreProtect database has, without which a source isn't one */
    static final List<String> CORE = Arrays.asList(VERSION, "user", "world", "block");

    /**
     * Reference data first, which history rows point to by ID, then history
     * roughly from what's referenced to what refers to it. Unknown tables
     * go last.
     */
    private static final List<String> COPY_ORDER = Arrays.asList(
        "world", "user", "material_map", "blockdata_map", "art_map", "entity_map", VERSION,
        "username_log", "skull", "entity", "entity_spawn", "block", "container", "item", "sign", "chat", "command",
        "session", "entity_container", "entity_interaction");

    private Tables() {
    }

    /**
     * @return whether the table holds reference data (the {@code *_map}
     *         tables, {@code user}, {@code world} and {@code version}), which
     *         validation always compares in full
     */
    static boolean isReference(String table) {
        return table.endsWith("_map") || table.equals("user") || table.equals("world") || table.equals(VERSION);
    }

    /**
     * @return the tables in the order to copy them
     */
    static List<String> copyOrder(Collection<String> tables) {
        List<String> ordered = new ArrayList<>(tables);
        ordered.sort(Comparator.comparingInt(Tables::rank).thenComparing(Comparator.naturalOrder()));
        return ordered;
    }

    private static int rank(String table) {
        int index = COPY_ORDER.indexOf(table);
        return index < 0 ? COPY_ORDER.size() : index;
    }
}
