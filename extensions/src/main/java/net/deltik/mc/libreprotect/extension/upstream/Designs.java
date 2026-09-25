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

package net.deltik.mc.libreprotect.extension.upstream;

import net.deltik.mc.libreprotect.extension.upstream.reflect.Design;

/**
 * The designs of CoreProtect that replaced older ways, in one place.
 */
public final class Designs {

    /**
     * CoreProtect 25's multi-engine database layer, and the database
     * lifecycle that came with it: engine types instead of
     * {@code use-mysql}, DuckDB and ClickHouse, reload and purge claims, a
     * status for unfinished migrations, and connections it tracks. Its
     * traces come from every part of it, so that renaming one, or a class
     * together with the fields of its type, still shows the design, and no
     * way of CoreProtect 24 is taken on it: CoreProtect 25 keeps many of
     * CoreProtect 24's names, such as {@code Config.MYSQL}, with other
     * meanings.
     */
    public static final Design MULTI_ENGINE = Design.of("multi-engine database layer (CoreProtect 25)",
        Names.DATABASE_TYPE,
        Names.CONFIG_HANDLER + "#databaseType",
        Names.CONFIG + "#DATABASE_TYPE",
        Names.DATABASE_CONFIG_WRITER,
        Names.DUCKDB_DATABASE,
        Names.DUCKDB_RECOVERY,
        Names.CLICKHOUSE_DATABASE,
        Names.CLICKHOUSE_JDBC_CONFIG,
        Names.OPERATION_START_RESULT,
        Names.CONSUMER + "#beginDatabaseReload",
        Names.CONSUMER + "#claimBackgroundPurge",
        Names.CONSUMER + "#isPersistenceHalted",
        Names.CONFIG_HANDLER + "#shutdownDrainRunning",
        Names.DATABASE + "#DATABASE_LOCK_MIGRATION_INCOMPLETE",
        Names.DATABASE + "#awaitConnectionDrain",
        Names.PURGE_POLICY);

    private Designs() {
    }
}
