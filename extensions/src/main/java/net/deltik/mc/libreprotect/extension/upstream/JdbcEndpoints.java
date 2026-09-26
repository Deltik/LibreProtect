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

package net.deltik.mc.libreprotect.extension.upstream;

import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.RowSink;
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Connector;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Connectors;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Dialect;
import net.deltik.mc.libreprotect.extension.migration.jdbc.JdbcRowSink;
import net.deltik.mc.libreprotect.extension.migration.jdbc.JdbcRowSource;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;

import java.io.File;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.function.IntSupplier;

/**
 * Reading and writing SQLite, MySQL and DuckDB with the migration's JDBC
 * code: a source over the migration's own connections, or for DuckDB, which
 * only one instance may open, over CoreProtect's own; a target over the
 * migration's own connections, with CoreProtect's own schema code. After the
 * copy, CoreProtect connects to such a target anew, so there's nothing to
 * {@linkplain #handOver hand over}.
 */
public final class JdbcEndpoints implements EngineEndpoints {

    static final CoreProtectMigration.EndpointWays SQLITE = CoreProtectMigration.EndpointWays.of(Engine.SQLITE)
        .source("jdbc", "the migration's own SQLite connections", upstream -> source(upstream, Engine.SQLITE))
        .target("jdbc", "CoreProtect's schema code, through the migration's own SQLite connections",
            upstream -> target(upstream, Engine.SQLITE));

    static final CoreProtectMigration.EndpointWays MYSQL = CoreProtectMigration.EndpointWays.of(Engine.MYSQL)
        .source("jdbc", "the migration's own MySQL connections", upstream -> source(upstream, Engine.MYSQL))
        .target("jdbc", "CoreProtect's schema code, through the migration's own MySQL connections",
            upstream -> target(upstream, Engine.MYSQL));

    static final CoreProtectMigration.EndpointWays DUCKDB = CoreProtectMigration.EndpointWays.of(Engine.DUCKDB)
        .source("coreprotect-connection", "CoreProtect's own connection to its DuckDB database, which only it may"
            + " open", upstream -> source(upstream, Engine.DUCKDB))
        .target("jdbc", "CoreProtect's schema code and DuckDB settings, through the migration's own connection",
            upstream -> target(upstream, Engine.DUCKDB));

    private final Engine engine;
    private final StaticField databaseTables;
    /** For a DuckDB source: CoreProtect's connections, which it's read through; else {@code null} */
    private final StaticMethod<Connection, RuntimeException> coreProtectConnection;
    /** For a target: how it's created and marked unfinished, and for DuckDB, how it's opened; else {@code null} */
    private final Target target;

    private JdbcEndpoints(Engine engine, StaticField databaseTables,
                          StaticMethod<Connection, RuntimeException> coreProtectConnection, Target target) {
        this.engine = engine;
        this.databaseTables = databaseTables;
        this.coreProtectConnection = coreProtectConnection;
        this.target = target;
    }

    private static final class Target {
        final Schema schema;
        final IncompleteMarks marks;
        /** DuckDB's writes, or {@code null} for SQL */
        final DuckDBWrites duckDBWrites;
        final DuckDBSettings duckDB;

        Target(Schema schema, IncompleteMarks marks, DuckDBWrites duckDBWrites, DuckDBSettings duckDB) {
            this.schema = schema;
            this.marks = marks;
            this.duckDBWrites = duckDBWrites;
            this.duckDB = duckDB;
        }
    }

    /**
     * The settings CoreProtect opens its DuckDB database with, read when a
     * target is opened; the block size is fixed when the file is created.
     */
    private static final class DuckDBSettings {
        final IntSupplier blockSize;
        final StaticField memoryLimit;
        final StaticField threads;
        final StaticField maxTempDirectorySize;

        DuckDBSettings(Upstream upstream) throws Missing {
            blockSize = upstream.type(Names.DATABASE).intConstant("DUCKDB_BLOCK_SIZE");
            UpstreamClass handler = upstream.type(Names.CONFIG_HANDLER);
            memoryLimit = handler.staticField("duckdbMemoryLimit", String.class);
            threads = handler.staticField("duckdbThreads", int.class);
            maxTempDirectorySize = handler.staticField("duckdbMaxTempDirectorySize", String.class);
            upstream.relyOn("opens DuckDB with the settings that a target is opened with, which fix a new file's"
                + " block size", Names.DUCKDB_DATABASE, "open()V");
        }

        Properties properties(File file) {
            Properties properties = new Properties();
            properties.setProperty("default_block_size", Integer.toString(blockSize.getAsInt()));
            properties.setProperty("memory_limit", (String) memoryLimit.get());
            properties.setProperty("threads", Integer.toString(threads.getInt()));
            properties.setProperty("temp_directory", file.getAbsolutePath() + ".tmp");
            properties.setProperty("max_temp_directory_size", (String) maxTempDirectorySize.get());
            properties.setProperty("enable_external_access", "false");
            properties.setProperty("allow_unsigned_extensions", "false");
            properties.setProperty("allow_community_extensions", "false");
            properties.setProperty("autoload_known_extensions", "false");
            properties.setProperty("autoinstall_known_extensions", "false");
            return properties;
        }
    }

    private static JdbcEndpoints source(Upstream upstream, Engine engine) throws Missing {
        StaticField tables = tables(upstream);
        StaticMethod<Connection, RuntimeException> coreProtectConnection = null;
        if (engine == Engine.DUCKDB) {
            coreProtectConnection = upstream.type(Names.DATABASE).staticMethod("getConnection", Connection.class,
                boolean.class, int.class);
            upstream.relyOn("gives the thread that holds the reload's write lock a duplicate of CoreProtect's own"
                + " DuckDB connection", Names.DATABASE, "getConnection(ZZZI)Ljava/sql/Connection;");
            upstream.relyOn("hands out duplicates of the one connection to the open DuckDB file", Names.DUCKDB_DATABASE,
                "getConnection()Ljava/sql/Connection;");
        }
        return new JdbcEndpoints(engine, tables, coreProtectConnection, null);
    }

    private static JdbcEndpoints target(Upstream upstream, Engine engine) throws Missing {
        StaticField tables = tables(upstream);
        Schema schema = MigrationProtocol.need(upstream, Schema.CAPABILITY);
        if (!schema.engines().contains(engine)) {
            throw new Missing(upstream.name() + "'s schema code doesn't create " + engine.displayName() + " tables");
        }
        IncompleteMarks marks = MigrationProtocol.need(upstream, IncompleteMarks.CAPABILITY);
        DuckDBWrites duckDBWrites = null;
        DuckDBSettings duckDB = null;
        if (engine == Engine.DUCKDB) {
            Schema.relyOnDuckDB(upstream);
            duckDBWrites = MigrationProtocol.orNull(upstream, DuckDBWrites.CAPABILITY);
            duckDB = new DuckDBSettings(upstream);
        }
        return new JdbcEndpoints(engine, tables, null, new Target(schema, marks, duckDBWrites, duckDB));
    }

    private static StaticField tables(Upstream upstream) throws Missing {
        return upstream.type(Names.CONFIG_HANDLER).staticField("databaseTables", List.class);
    }

    @Override
    public Engine engine() {
        return engine;
    }

    /**
     * @throws IllegalStateException for endpoints that only write
     */
    @Override
    public RowSource openSource(DatabaseSettings settings) throws SQLException {
        check(settings);
        if (target != null) {
            throw new IllegalStateException("These " + engine.displayName() + " endpoints only write");
        }
        if (engine == Engine.DUCKDB) {
            // CoreProtect has the file open; only its own instance may use it
            return new JdbcRowSource(Dialect.DUCKDB, Connectors.nonNull(() -> coreProtectConnection.call(true, 0),
                "CoreProtect's DuckDB database"), true, true, settings.prefix(), tables());
        }
        return new JdbcRowSource(Dialect.of(engine), connector(settings), true, true, settings.prefix(), tables());
    }

    /**
     * @throws IllegalStateException for endpoints that only read
     */
    @Override
    public RowSink openSink(DatabaseSettings settings) throws SQLException {
        check(settings);
        if (target == null) {
            throw new IllegalStateException("These " + engine.displayName() + " endpoints only read");
        }
        return new JdbcRowSink(Dialect.of(engine), connector(settings), settings.prefix(), tables(),
            target.schema.creator(engine), target.marks.marker(), settings.file(),
            target.duckDBWrites == null ? null : target.duckDBWrites.bulkInsert());
    }

    /**
     * @throws UnsupportedOperationException always: CoreProtect connects to
     *                                       such a target anew
     */
    @Override
    public Object handOver(RowSink sink) {
        throw new UnsupportedOperationException("CoreProtect connects to a " + engine.displayName() + " target anew;"
            + " there's nothing to hand over");
    }

    private void check(DatabaseSettings settings) {
        if (settings.engine() != engine) {
            throw new IllegalArgumentException("Not " + engine.displayName() + " settings: " + settings);
        }
    }

    private Connector connector(DatabaseSettings settings) {
        switch (engine) {
            case SQLITE:
                return Connectors.sqlite(settings.file());
            case DUCKDB:
                return Connectors.duckdb(settings.file(), target.duckDB.properties(settings.file()));
            default:
                return Connectors.mysql(settings.host(), settings.port(), settings.database(), settings.username(),
                    settings.password(), settings.tls());
        }
    }

    /**
     * @return CoreProtect's tables, unprefixed
     */
    private List<String> tables() throws SQLException {
        Object loaded = databaseTables.get();
        List<String> tables = new ArrayList<>();
        if (loaded instanceof List) {
            for (Object table : new ArrayList<>((List<?>) loaded)) {
                tables.add(String.valueOf(table));
            }
        }
        if (tables.isEmpty()) {
            throw new SQLException("CoreProtect hasn't loaded its database");
        }
        return tables;
    }
}
