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

import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Shape;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;

import java.sql.Connection;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;

/**
 * Which of CoreProtect's tables a purge removes old rows from, by their
 * {@code time} column, as its own purge does; and which tables the schema
 * of its database has, such as CoreProtect 25's {@code entity_spawn}, whose
 * orphans a purge cleans up.
 */
public final class PurgeTables {

    public static final Capability<PurgeTables> CAPABILITY = Capability.of("auto-purge.tables",
        Choice.way("purge-policy", "CoreProtect's purge policy", Designs.MULTI_ENGINE, PurgeTables::purgePolicy),
        Choice.way("purge-command-list", "the tables of CoreProtect's purge command", PurgeTables::purgeCommandList));

    private static final String SCHEMA_TABLES = "lists every table of the schema it creates in"
        + " ConfigHandler.databaseTables";

    private final Supplier<Object> purgeable;
    private final StaticField databaseTables;
    private final boolean entitySpawns;

    private PurgeTables(Supplier<Object> purgeable, StaticField databaseTables, Upstream upstream) {
        this.purgeable = purgeable;
        this.databaseTables = databaseTables;
        // Rows link to entity_spawn only in the schema of CoreProtect 25's design
        this.entitySpawns = Designs.MULTI_ENGINE.isIn(upstream);
    }

    /**
     * CoreProtect 25: {@code PurgePolicy.getPurgeableTables()}, which its
     * purge command and ClickHouse's retention use too.
     */
    private static PurgeTables purgePolicy(Upstream upstream) throws Missing {
        StaticMethod<?, RuntimeException> tables = upstream.type(Names.PURGE_POLICY).staticMethod(
            "getPurgeableTables", List.class);
        upstream.relyOn("lists the tables whose rows older than a purge's time it removes, by their time column",
            tables);
        StaticMethod<Void, RuntimeException> create = upstream.type(Names.DATABASE).staticMethodShaped(
            "createDatabaseTables", void.class, Shape.exactly(String.class), Shape.exactly(boolean.class),
            Shape.exactly(Connection.class), Shape.enumWith("SQLITE", "MYSQL"), Shape.exactly(boolean.class));
        upstream.relyOn(SCHEMA_TABLES, create);
        return new PurgeTables(tables::call, databaseTables(upstream), upstream);
    }

    /**
     * CoreProtect 24: {@code PurgeCommand.PURGE_TABLES}, the tables of its
     * purge command.
     */
    private static PurgeTables purgeCommandList(Upstream upstream) throws Missing {
        StaticField tables = upstream.type(Names.PURGE_COMMAND).staticField("PURGE_TABLES", List.class);
        StaticMethod<Void, RuntimeException> create = upstream.type(Names.DATABASE).staticMethod(
            "createDatabaseTables", void.class, String.class, boolean.class, Connection.class, boolean.class,
            boolean.class);
        upstream.relyOn(SCHEMA_TABLES, create);
        return new PurgeTables(tables::get, databaseTables(upstream), upstream);
    }

    private static StaticField databaseTables(Upstream upstream) throws Missing {
        return upstream.type(Names.CONFIG_HANDLER).staticField("databaseTables", List.class);
    }

    /**
     * @return the unprefixed tables whose rows a purge removes by their {@code time} column
     */
    public List<String> purgeable() {
        return strings(purgeable.get());
    }

    /**
     * @return whether the schema of CoreProtect's database may have
     *         {@code entity_spawn}, whose rows others link to: false only
     *         without any trace of CoreProtect 25's design
     */
    public boolean mayLinkEntitySpawns() {
        return entitySpawns;
    }

    /**
     * @return the unprefixed tables of the schema of CoreProtect's database,
     *         as of when CoreProtect last created one. CoreProtect clears
     *         and refills them whenever it creates a schema, so a read that
     *         meets it doing so gets some of them, or none
     */
    public List<String> schema() {
        return strings(databaseTables.get());
    }

    private static List<String> strings(Object tables) {
        List<String> strings = new ArrayList<>();
        if (tables instanceof Collection) {
            // Copied in one step: CoreProtect refills databaseTables whenever it creates a schema, such as a migration's
            for (Object table : ((Collection<?>) tables).toArray()) {
                if (table != null) {
                    strings.add(table.toString());
                }
            }
        }
        return strings;
    }
}
