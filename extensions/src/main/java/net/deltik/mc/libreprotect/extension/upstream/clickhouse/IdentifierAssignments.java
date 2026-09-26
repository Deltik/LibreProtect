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

package net.deltik.mc.libreprotect.extension.upstream.clickhouse;

import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Family;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.IdentifierCache;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * The identifiers CoreProtect assigns in memory for the identifier maps
 * ({@code material_map}, {@code world}, ...), before their rows are written.
 *
 * <p>ClickHouse keys a map row by its row ID, and CoreProtect writes a new
 * identifier's row with the identifier as its row ID. Copied rows keep their
 * source row IDs, which can run ahead of their identifiers, so an identifier
 * that CoreProtect assigns during the migration and writes to ClickHouse
 * after activation must not equal a copied row's ID.
 */
interface IdentifierAssignments {

    /**
     * Make CoreProtect assign the map's future identifiers above
     * {@code floor}, and find which of {@code candidates} it has already
     * assigned. Both happen at once with respect to CoreProtect's own
     * assignments, so no identifier escapes both.
     *
     * @return the candidates that are assigned
     */
    List<Long> raiseAndFindAssigned(Family map, long floor, List<Long> candidates);

    /**
     * Make CoreProtect assign the map's future identifiers above {@code floor},
     * until it next loads its identifier caches, which resets each counter
     * to the largest identifier stored. It loads them when it starts and
     * reloads, not while a migration runs, and its own assignments only raise
     * the counters. Skipping identifiers leaves gaps it doesn't mind.
     */
    default void raise(Family map, long floor) {
        raiseAndFindAssigned(map, floor, Collections.emptyList());
    }

    /**
     * @param api the capability that writes ClickHouse
     * @return CoreProtect's own identifier caches, which it assigns from with
     *         the lock of {@code ConfigHandler}
     */
    static IdentifierAssignments coreProtect(ClickHouseApi api) {
        return (map, floor, candidates) -> {
            IdentifierCache cache = api.identifierCache(map.tableName());
            synchronized (api.configLock().monitor()) {
                int raised = (int) Math.min(floor, Integer.MAX_VALUE);
                cache.setCounter(Math.max(cache.counter(), raised));
                Map<Integer, String> assigned = cache.assigned();
                List<Long> found = new ArrayList<>();
                for (Long candidate : candidates) {
                    if (candidate <= Integer.MAX_VALUE && assigned.containsKey(candidate.intValue())) {
                        found.add(candidate);
                    }
                }
                return found;
            }
        };
    }
}
