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

package net.deltik.mc.libreprotect.extension.purge;

import net.deltik.mc.libreprotect.extension.common.Engine;
import org.duckdb.DuckDBConnection;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * A SQLite or DuckDB database with CoreProtect's purgeable tables, or the
 * parts of them that purging reads, for tests.
 */
final class TestDatabase implements AutoCloseable {

    private final Engine engine;
    private final Path file;
    private final DuckDBConnection duckRoot;

    private TestDatabase(Engine engine, Path file, DuckDBConnection duckRoot) {
        this.engine = engine;
        this.file = file;
        this.duckRoot = duckRoot;
    }

    /**
     * @param engine {@link Engine#SQLITE} or {@link Engine#DUCKDB}
     */
    static TestDatabase create(Engine engine, Path directory) throws SQLException {
        if (engine == Engine.SQLITE) {
            TestDatabase database = new TestDatabase(engine, directory.resolve("database.db"), null);
            try (Connection connection = database.open(); Statement statement = connection.createStatement()) {
                statement.executeUpdate("PRAGMA journal_mode=WAL");
                for (String table : new String[]{"block", "chat", "entity_container", "entity_interaction"}) {
                    statement.executeUpdate("CREATE TABLE co_" + table + " (time INTEGER, user INTEGER,"
                        + (table.startsWith("entity_") ? " entity_spawn_rowid INTEGER NOT NULL," : "")
                        + " wid INTEGER, x INTEGER, y INTEGER, z INTEGER, type INTEGER)");
                    statement.executeUpdate("CREATE INDEX co_" + table + "_index ON co_" + table + "(wid,x,z,time)");
                }
                statement.executeUpdate("CREATE TABLE co_entity (id INTEGER PRIMARY KEY ASC, time INTEGER, data BLOB)");
                statement.executeUpdate("CREATE TABLE co_entity_spawn (id INTEGER PRIMARY KEY ASC, time INTEGER,"
                    + " block_rowid INTEGER, kill_rowid INTEGER, uuid TEXT UNIQUE, removed INTEGER)");
                statement.executeUpdate("CREATE UNIQUE INDEX co_entity_spawn_kill_rowid_index ON co_entity_spawn(kill_rowid)");
            }
            return database;
        }
        Path file = directory.resolve("database.duckdb");
        DuckDBConnection root = (DuckDBConnection) DriverManager.getConnection("jdbc:duckdb:" + file);
        TestDatabase database = new TestDatabase(engine, file, root);
        try (Statement statement = root.createStatement()) {
            for (String table : new String[]{"block", "chat", "entity_container", "entity_interaction", "entity", "entity_spawn"}) {
                statement.executeUpdate("CREATE SEQUENCE co_" + table + "_rowid_seq START 1");
            }
            for (String table : new String[]{"block", "chat", "entity_container", "entity_interaction"}) {
                statement.executeUpdate("CREATE TABLE co_" + table + " (" + rowid(table) + ", time INTEGER, \"user\" INTEGER,"
                    + (table.startsWith("entity_") ? " entity_spawn_rowid INTEGER NOT NULL," : "")
                    + " wid INTEGER, x INTEGER, y INTEGER, z INTEGER, type INTEGER)");
            }
            statement.executeUpdate("CREATE TABLE co_entity (" + rowid("entity") + ", time INTEGER, data BLOB)");
            statement.executeUpdate("CREATE TABLE co_entity_spawn (" + rowid("entity_spawn") + ", time INTEGER,"
                + " block_rowid BIGINT, kill_rowid INTEGER, uuid VARCHAR UNIQUE, removed TINYINT, UNIQUE(kill_rowid))");
        }
        return database;
    }

    private static String rowid(String table) {
        return "rowid " + (table.equals("block") ? "BIGINT" : "INTEGER") + " NOT NULL DEFAULT nextval('co_" + table + "_rowid_seq')";
    }

    Engine engine() {
        return engine;
    }

    Path file() {
        return file;
    }

    /**
     * @return a new connection, as CoreProtect would hand out
     */
    Connection open() throws SQLException {
        if (duckRoot != null) {
            return duckRoot.duplicate();
        }
        return DriverManager.getConnection("jdbc:sqlite:" + file);
    }

    /**
     * Insert rows with the given rowids and times into a table that has
     * {@code time} and nothing else required.
     */
    void insert(String table, long[] rowids, long[] times) throws SQLException {
        String extra = table.startsWith("entity_") && !table.equals("entity_spawn") ? ", entity_spawn_rowid" : "";
        String extraValue = extra.isEmpty() ? "" : ", 0";
        try (Connection connection = open();
             PreparedStatement statement = connection.prepareStatement(
                 "INSERT INTO co_" + table + " (rowid, time" + extra + ") VALUES (?, ?" + extraValue + ")")) {
            connection.setAutoCommit(false);
            for (int i = 0; i < rowids.length; i++) {
                statement.setLong(1, rowids[i]);
                statement.setLong(2, times[i]);
                statement.addBatch();
            }
            statement.executeBatch();
            connection.commit();
        }
    }

    /**
     * Insert a row for every rowid from {@code first} to {@code last}, all
     * with the same time.
     */
    void insertRange(String table, long first, long last, long time) throws SQLException {
        String extra = table.startsWith("entity_") && !table.equals("entity_spawn") ? ", entity_spawn_rowid" : "";
        String extraValue = extra.isEmpty() ? "" : ", 0";
        if (engine == Engine.DUCKDB) {
            execute("INSERT INTO co_" + table + " (rowid, time" + extra + ") SELECT range, " + time + extraValue
                + " FROM range(" + first + ", " + (last + 1) + ")");
        } else {
            execute("WITH RECURSIVE r(x) AS (SELECT " + first + " UNION ALL SELECT x + 1 FROM r WHERE x < " + last + ")"
                + " INSERT INTO co_" + table + " (rowid, time" + extra + ") SELECT x, " + time + extraValue + " FROM r");
        }
    }

    /**
     * Run statements, such as inserts of specific rows.
     */
    void execute(String... sql) throws SQLException {
        try (Connection connection = open(); Statement statement = connection.createStatement()) {
            for (String each : sql) {
                statement.executeUpdate(each);
            }
        }
    }

    /**
     * @return the rowids of a table, in order
     */
    List<Long> rowids(String table) throws SQLException {
        return longs("SELECT rowid FROM co_" + table + " ORDER BY rowid");
    }

    /**
     * @return the first column of every row
     */
    List<Long> longs(String sql) throws SQLException {
        List<Long> values = new ArrayList<>();
        try (Connection connection = open(); Statement statement = connection.createStatement();
             ResultSet results = statement.executeQuery(sql)) {
            while (results.next()) {
                long value = results.getLong(1);
                values.add(results.wasNull() ? null : value);
            }
        }
        return values;
    }

    long count(String sql) throws SQLException {
        return longs(sql).get(0);
    }

    @Override
    public void close() throws SQLException {
        if (duckRoot != null) {
            duckRoot.close();
        }
    }
}
