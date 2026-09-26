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

    /**
     * CoreProtect's lookup index of its ClickHouse data, which lookups by
     * player read instead of the events: its writer stamps every row of the
     * event table with its write version, which the table then requires,
     * and adds an index row beside each row of the tables that those lookups
     * search. A purge closes the index while it deletes, and CoreProtect
     * refuses to start while a purge that didn't complete is still deleting.
     * Databases from before it are upgraded in place when CoreProtect opens
     * them. LibreProtect writes ClickHouse through that writer, so it takes
     * the same way with or without the index; it relies on the index only
     * while CoreProtect has it. Its traces come from the index, the lookups
     * that read it, the upgrade's check of the older schema and the writer
     * registration that the index is owned by.
     */
    public static final Design CLICKHOUSE_LOOKUP_INDEX = Design.of("ClickHouse lookup index",
        Names.CLICKHOUSE_LOOKUP_INDEX,
        Names.CLICKHOUSE_LOOKUP,
        Names.CLICKHOUSE_SCHEMA + "#validateLegacyPhysicalSchema",
        Names.CLICKHOUSE_WRITER_REGISTRATION + "#schemaOwner");

    private Designs() {
    }
}
