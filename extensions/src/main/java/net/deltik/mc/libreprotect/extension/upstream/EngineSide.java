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

import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.upstream.reflect.InstanceField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.InstanceMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;

import java.io.File;
import java.sql.SQLException;

/**
 * One engine as one side of a migration, which its
 * {@code migrate-db.source} or {@code migrate-db.target} capability gives:
 * how the migration reads or writes it, where CoreProtect has its database,
 * and for a database that CoreProtect takes over as it is, such as
 * ClickHouse's, how. What only one engine needs of CoreProtect is resolved
 * here, so that CoreProtect changing it turns off only the migrations from
 * or to that engine.
 */
public final class EngineSide {

    /** Where CoreProtect has the database of an engine, as it loaded its settings */
    @FunctionalInterface
    private interface Location {
        /**
         * @param prefix the table prefix, which embedded engines ignore
         */
        DatabaseSettings settings(String prefix);
    }

    private final Engine engine;
    private final EngineEndpoints endpoints;
    private final Location location;
    /** How CoreProtect takes a prepared database of the engine over, or {@code null} if it connects anew */
    private final StaticMethod<Void, RuntimeException> takeOver;
    /** How CoreProtect's object for a database of the engine closes, or {@code null} if it connects anew */
    private final InstanceMethod<Void, SQLException> close;
    /** How CoreProtect gives up its active database of the engine, open, or {@code null} */
    private final StaticMethod<?, SQLException> detach;
    private final boolean handsOver;

    private EngineSide(Engine engine, EngineEndpoints endpoints, Location location,
                       StaticMethod<Void, RuntimeException> takeOver, InstanceMethod<Void, SQLException> close,
                       StaticMethod<?, SQLException> detach, boolean handsOver) {
        this.engine = engine;
        this.endpoints = endpoints;
        this.location = location;
        this.takeOver = takeOver;
        this.close = close;
        this.detach = detach;
        this.handsOver = handsOver;
    }

    /**
     * @param endpoints how the migration reads or writes the engine
     * @param target whether it's the target's side, which CoreProtect uses
     *               after the switch, rather than the source's, which it may
     *               switch back to
     */
    static EngineSide probe(Upstream upstream, Engine engine, EngineEndpoints endpoints, boolean target)
        throws Missing {
        if (endpoints.engine() != engine) {
            throw new IllegalArgumentException("Endpoints for " + endpoints.engine() + ", not " + engine);
        }
        Location location = location(upstream, engine);
        StaticMethod<Void, RuntimeException> takeOver = null;
        InstanceMethod<Void, SQLException> close = null;
        StaticMethod<?, SQLException> detach = null;
        // CoreProtect connects to a database of the migration's own JDBC code anew
        boolean handsOver = target && !(endpoints instanceof JdbcEndpoints);
        if (handsOver || (!target && engine == Engine.CLICKHOUSE)) {
            takeOver = takeOver(upstream, engine);
            close = close(upstream, engine);
        }
        if (!target && engine == Engine.CLICKHOUSE) {
            detach = upstream.type(Names.DATABASE).staticMethod("detachClickHouseDatabase", Object.class)
                .throwing(SQLException.class);
            upstream.relyOn("takes the active ClickHouse database away without closing it, so that it can be"
                + " taken over again", detach);
        }
        if (!target && engine == Engine.DUCKDB) {
            // A recovery pending refuses a migration from DuckDB, and one requested meanwhile is forgotten after it
            MigrationProtocol.need(upstream, Hooks.DUCKDB_RECOVERY);
        }
        return new EngineSide(engine, endpoints, location, takeOver, close, detach, handsOver);
    }

    private static Location location(Upstream upstream, Engine engine) throws Missing {
        UpstreamClass handler = upstream.type(Names.CONFIG_HANDLER);
        switch (engine) {
            case SQLITE: {
                StaticField path = handler.staticField("path", String.class);
                StaticField sqlite = handler.staticField("sqlite", String.class);
                return prefix -> DatabaseSettings.embedded(Engine.SQLITE, new File((String) path.get()
                    + sqlite.get()));
            }
            case DUCKDB: {
                StaticField path = handler.staticField("path", String.class);
                StaticField duckDB = handler.staticField("duckdb", String.class);
                return prefix -> DatabaseSettings.embedded(Engine.DUCKDB, new File((String) path.get(),
                    (String) duckDB.get()));
            }
            case MYSQL: {
                StaticField host = handler.staticField("host", String.class);
                StaticField port = handler.staticField("port", int.class);
                StaticField database = handler.staticField("database", String.class);
                StaticField username = handler.staticField("username", String.class);
                StaticField password = handler.staticField("password", String.class);
                UpstreamClass config = upstream.type(Names.CONFIG);
                StaticMethod<?, RuntimeException> global = config.staticMethod("getGlobal", config.type());
                InstanceField tls = config.field("ENABLE_SSL", boolean.class);
                return prefix -> DatabaseSettings.server(Engine.MYSQL, (String) host.get(), port.getInt(),
                    (String) database.get(), (String) username.get(), (String) password.get(),
                    tls.getBoolean(global.call()), prefix);
            }
            default: {
                UpstreamClass config = upstream.type(Names.CONFIG);
                StaticMethod<?, RuntimeException> global = config.staticMethod("getGlobal", config.type());
                InstanceField host = config.field("CLICKHOUSE_HOST", String.class);
                InstanceField port = config.field("CLICKHOUSE_PORT", int.class);
                InstanceField database = config.field("CLICKHOUSE_DATABASE", String.class);
                InstanceField username = config.field("CLICKHOUSE_USERNAME", String.class);
                InstanceField password = config.field("CLICKHOUSE_PASSWORD", String.class);
                InstanceField tls = config.field("CLICKHOUSE_TLS", boolean.class);
                return prefix -> {
                    Object loaded = global.call();
                    return DatabaseSettings.server(Engine.CLICKHOUSE, (String) host.get(loaded),
                        port.getInt(loaded), (String) database.get(loaded), (String) username.get(loaded),
                        (String) password.get(loaded), tls.getBoolean(loaded), prefix);
                };
            }
        }
    }

    /**
     * @return how CoreProtect activates a prepared database of the engine as
     *         it is, without checking its unfinished-migration mark
     * @throws Missing if CoreProtect can't take over one of the engine
     */
    private static StaticMethod<Void, RuntimeException> takeOver(Upstream upstream, Engine engine) throws Missing {
        if (engine != Engine.CLICKHOUSE) {
            throw new Missing(upstream.name() + " can't take over a prepared " + engine.displayName() + " database");
        }
        UpstreamClass clickHouse = upstream.type(Names.CLICKHOUSE_DATABASE);
        StaticMethod<Void, RuntimeException> takeOver = upstream.type(Names.CONFIG_HANDLER).staticMethod(
            "loadMigrationDatabase", void.class, clickHouse.type());
        upstream.relyOn("activates a prepared ClickHouse database as it is, with its writer registration, without"
            + " checking its unfinished migration's status", takeOver);
        upstream.relyOn("installs a prepared ClickHouse database as the active one, closing the one before",
            Names.DATABASE, "installClickHouseDatabase(" + Names.descriptor(Names.CLICKHOUSE_DATABASE) + ")V");
        return takeOver;
    }

    /**
     * @return how CoreProtect's object for a database of the engine closes,
     *         for one that CoreProtect didn't take over, or gave up
     * @throws Missing if CoreProtect can't take over one of the engine
     */
    private static InstanceMethod<Void, SQLException> close(Upstream upstream, Engine engine) throws Missing {
        if (engine != Engine.CLICKHOUSE) {
            throw new Missing(upstream.name() + " can't take over a prepared " + engine.displayName() + " database");
        }
        InstanceMethod<Void, SQLException> close = upstream.type(Names.CLICKHOUSE_DATABASE).method("close",
            void.class).throwing(SQLException.class);
        upstream.relyOn("releases the database's writer registration and closes its connections, and does nothing"
            + " once closed, such as by CoreProtect", Names.CLICKHOUSE_DATABASE, "close()V");
        return close;
    }

    public Engine engine() {
        return engine;
    }

    /**
     * @return how the migration reads or writes the engine
     */
    EngineEndpoints endpoints() {
        return endpoints;
    }

    /**
     * @param prefix the table prefix, which embedded engines ignore
     * @return where CoreProtect has the engine's database, as it loaded its settings
     */
    DatabaseSettings settings(String prefix) {
        return location.settings(prefix);
    }

    /**
     * @return whether CoreProtect takes a prepared target of the engine
     *         over as it is, rather than connecting to it anew
     */
    boolean handsOver() {
        return handsOver;
    }

    /**
     * Make CoreProtect use a database of the engine as it is.
     *
     * @param prepared CoreProtect's own object for the database
     * @throws IllegalStateException if CoreProtect can't take over one of the engine
     */
    void takeOver(Object prepared) {
        if (takeOver == null) {
            throw new IllegalStateException("CoreProtect can't take over a " + engine.displayName() + " database");
        }
        takeOver.call(prepared);
    }

    /**
     * Take CoreProtect's active database of the engine away from it, open,
     * so that it can be taken over again when switching back.
     *
     * @return CoreProtect's object for it, or {@code null} for an engine
     *         whose database CoreProtect connects to anew
     */
    Object detach() throws SQLException {
        return detach == null ? null : detach.call();
    }

    /**
     * Close CoreProtect's object for a database of the engine that
     * CoreProtect doesn't use, from {@link #detach()} or the endpoints'
     * {@link EngineEndpoints#handOver handOver}, which releases what it
     * holds, such as ClickHouse's writer registration. Closing one that
     * CoreProtect closed already does nothing.
     *
     * @throws IllegalStateException if CoreProtect can't take over one of the engine
     */
    void close(Object database) throws SQLException {
        if (close == null) {
            throw new IllegalStateException("CoreProtect can't take over a " + engine.displayName() + " database");
        }
        close.call(database);
    }
}
