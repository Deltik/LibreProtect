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

import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.jdbc.SchemaCreator;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Shape;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamEnum;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * CoreProtect's own code that creates its tables, for a migration's target,
 * so the target gets exactly the schema of the CoreProtect that runs.
 *
 * <p>On SQLite and MySQL, upstream closes the connection it's given, and
 * CoreProtect 24 reports errors instead of throwing them, so the caller
 * checks the tables afterward. ClickHouse creates its schema its own way.
 */
public final class Schema {

    public static final Capability<Schema> CAPABILITY = Capability.of("migrate-db.schema",
        Choice.way("by-engine-type", "CoreProtect's schema code for each database engine", Designs.MULTI_ENGINE,
            Schema::byEngineType),
        Choice.way("by-use-mysql", "CoreProtect's schema code for SQLite and MySQL", Schema::byUseMySQL));

    private static final String RELIES = "creates every table of ConfigHandler.databaseTables in the connection's"
        + " database, through its private helpers";

    private final StaticMethod<Void, RuntimeException> create;
    /** The engine enum it takes, or {@code null} for {@code use-mysql}'s boolean */
    private final UpstreamEnum types;
    private final Set<Engine> engines;

    private Schema(StaticMethod<Void, RuntimeException> create, UpstreamEnum types, Set<Engine> engines) {
        this.create = create;
        this.types = types;
        this.engines = Collections.unmodifiableSet(engines);
    }

    /**
     * CoreProtect 25: {@code createDatabaseTables(prefix, forcePrefix,
     * connection, engine type, purge)}.
     */
    private static Schema byEngineType(Upstream upstream) throws Missing {
        StaticMethod<Void, RuntimeException> create = upstream.type(Names.DATABASE).staticMethodShaped(
            "createDatabaseTables", void.class, Shape.exactly(String.class), Shape.exactly(boolean.class),
            Shape.exactly(Connection.class), Shape.enumWith("SQLITE", "MYSQL"), Shape.exactly(boolean.class));
        UpstreamEnum types = upstream.type(create.parameterType(3)).asEnum();
        Set<Engine> engines = EnumSet.noneOf(Engine.class);
        for (String name : types.names()) {
            Engine.fromUpstreamName(name).ifPresent(engines::add);
        }
        // ClickHouseDatabase creates ClickHouse's schema; createDatabaseTables refuses it
        engines.remove(Engine.CLICKHOUSE);
        upstream.relyOn(RELIES, create);
        upstream.relyOn("tells createDatabaseTables which engine's schema to create", types.name(), "isClickHouse()Z",
            "isMySQL()Z", "isDuckDB()Z");
        // DuckDB's tables come from a class of their own, which only DuckDB targets rely on (see relyOnDuckDB)
        return new Schema(create, types, engines);
    }

    /**
     * Record what a DuckDB target relies on besides: DuckDB's tables come
     * from a class of their own, which {@code createDatabaseTables} calls.
     * Only DuckDB targets rely on it, so a change of it leaves the others.
     */
    static void relyOnDuckDB(Upstream upstream) throws Missing {
        upstream.relyOn("creates DuckDB's tables in the connection's database, leaving it open", Names.DUCKDB_DATABASE,
            "createTables(Ljava/lang/String;Ljava/sql/Connection;Z)V");
    }

    /**
     * CoreProtect 24: {@code createDatabaseTables(prefix, forcePrefix,
     * connection, mySQL, purge)}. CoreProtect 25 keeps this signature, but
     * for its legacy engines only.
     */
    private static Schema byUseMySQL(Upstream upstream) throws Missing {
        StaticMethod<Void, RuntimeException> create = upstream.type(Names.DATABASE).staticMethod(
            "createDatabaseTables", void.class, String.class, boolean.class, Connection.class, boolean.class,
            boolean.class);
        upstream.relyOn(RELIES, create);
        return new Schema(create, null, EnumSet.of(Engine.SQLITE, Engine.MYSQL));
    }

    /**
     * @return the engines whose schema this creates
     */
    public Set<Engine> engines() {
        return engines;
    }

    /**
     * @return a creator of CoreProtect's tables in a database of the engine,
     *         for a migration's target
     * @throws IllegalArgumentException if CoreProtect doesn't create that
     *                                  engine's schema this way
     */
    public SchemaCreator creator(Engine engine) {
        if (!engines.contains(engine)) {
            throw new IllegalArgumentException("CoreProtect doesn't create " + engine.displayName() + " tables"
                + " this way");
        }
        Object type = types == null ? (Object) (engine == Engine.MYSQL) : types.constant(engine.name());
        return (connection, prefix) -> create(connection, prefix, type);
    }

    private void create(Connection connection, String prefix, Object type) throws SQLException {
        try {
            create.call(prefix, true, connection, type, false);
        } catch (RuntimeException e) {
            throw new SQLException("CoreProtect couldn't create its tables: " + e.getMessage(), e);
        }
    }
}
