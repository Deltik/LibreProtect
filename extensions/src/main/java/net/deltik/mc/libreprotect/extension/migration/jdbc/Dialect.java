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

package net.deltik.mc.libreprotect.extension.migration.jdbc;

import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.Values;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.OptionalLong;
import java.util.Set;

/**
 * What differs between the relational engines when reading and writing
 * CoreProtect's tables through JDBC: catalog queries, where the row ID
 * lives, allocator state, and the {@code database_lock} table.
 *
 * <p>Every CoreProtect table has a row ID. SQLite keeps it in the implicit
 * {@code rowid}, which some tables alias as {@code id INTEGER PRIMARY KEY};
 * MySQL and DuckDB have an explicit {@code rowid} column. Elsewhere, the
 * {@code id} of the {@code *_map} and {@code world} tables is a separate,
 * ordinary column.
 */
public enum Dialect {

    SQLITE(Engine.SQLITE) {
        @Override
        String quote(String identifier) {
            return '"' + identifier.replace("\"", "\"\"") + '"';
        }

        @Override
        Set<String> existingTables(Connection connection) throws SQLException {
            return strings(connection, "SELECT name FROM sqlite_master WHERE type = 'table'");
        }

        @Override
        List<String> columns(Connection connection, String table) throws SQLException {
            List<String> columns = new ArrayList<>();
            String alias = null;
            int keys = 0;
            try (Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("PRAGMA table_info(" + quote(table) + ")")) {
                while (result.next()) {
                    String name = result.getString("name");
                    if (result.getInt("pk") > 0) {
                        keys++;
                        if ("INTEGER".equalsIgnoreCase(result.getString("type"))) {
                            alias = name;
                        }
                    }
                    columns.add(name);
                }
            }
            // A single INTEGER PRIMARY KEY column is another name for the rowid
            if (keys == 1 && alias != null) {
                columns.remove(alias);
            }
            columns.removeIf(ROWID::equalsIgnoreCase);
            return columns;
        }

        @Override
        void configure(Connection connection, boolean readOnly) throws SQLException {
            if (readOnly) {
                try (Statement statement = connection.createStatement()) {
                    statement.execute("PRAGMA query_only = 1");
                }
            }
        }

        @Override
        Object read(ResultSet result, int column) throws SQLException {
            // SQLite types each value by what it holds; getObject keeps that
            return Values.normalize(result.getObject(column));
        }

        @Override
        String lockTableDefinition(String table) {
            return "CREATE TABLE IF NOT EXISTS " + table + " (status INTEGER, time INTEGER)";
        }
    },

    MYSQL(Engine.MYSQL) {
        @Override
        String quote(String identifier) {
            return '`' + identifier.replace("`", "``") + '`';
        }

        @Override
        Set<String> existingTables(Connection connection) throws SQLException {
            return strings(connection, "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()");
        }

        @Override
        List<String> columns(Connection connection, String table) throws SQLException {
            List<String> columns = strings(connection, "SELECT COLUMN_NAME FROM information_schema.COLUMNS"
                + " WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION", table);
            return withoutRowId(columns, table);
        }

        @Override
        void configure(Connection connection, boolean readOnly) throws SQLException {
            try (Statement statement = connection.createStatement()) {
                // Strict, so a value that doesn't fit fails instead of being cut; and a row ID of 0 stays 0
                statement.execute("SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_AUTO_VALUE_ON_ZERO,NO_ENGINE_SUBSTITUTION'");
                try {
                    // MySQL 8 caches AUTO_INCREMENT in information_schema for a day by default
                    statement.execute("SET SESSION information_schema_stats_expiry = 0");
                } catch (SQLException e) {
                    // Older servers don't cache it
                }
            }
            if (readOnly) {
                connection.setReadOnly(true);
            }
        }

        @Override
        OptionalLong highWater(Connection connection, String prefix, String table) throws SQLException {
            try (PreparedStatement statement = connection.prepareStatement("SELECT AUTO_INCREMENT FROM"
                + " information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?")) {
                statement.setString(1, prefix + table);
                try (ResultSet result = statement.executeQuery()) {
                    if (result.next()) {
                        long next = result.getLong(1);
                        if (!result.wasNull()) {
                            return OptionalLong.of(next - 1);
                        }
                    }
                }
            }
            return OptionalLong.empty();
        }

        @Override
        void setHighWater(Connection connection, String prefix, String table, long highWater) throws SQLException {
            if (highWater >= 1) {
                try (Statement statement = connection.createStatement()) {
                    statement.execute("ALTER TABLE " + quote(prefix + table) + " AUTO_INCREMENT = " + (highWater + 1));
                }
            }
        }

        @Override
        String lockTableDefinition(String table) {
            return "CREATE TABLE IF NOT EXISTS " + table + "(rowid int NOT NULL AUTO_INCREMENT,PRIMARY KEY(rowid),"
                + "status tinyint,time int) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4";
        }

        @Override
        boolean abortsConnections() {
            return true;
        }
    },

    DUCKDB(Engine.DUCKDB) {
        @Override
        String quote(String identifier) {
            return '"' + identifier.replace("\"", "\"\"") + '"';
        }

        @Override
        Set<String> existingTables(Connection connection) throws SQLException {
            return strings(connection, "SELECT table_name FROM information_schema.tables"
                + " WHERE table_catalog = current_database() AND table_schema = current_schema()");
        }

        /**
         * DuckDB matches names regardless of case, like SQLite, but its
         * catalog keeps them as written.
         */
        @Override
        List<String> columns(Connection connection, String table) throws SQLException {
            List<String> columns = strings(connection, "SELECT column_name FROM information_schema.columns"
                + " WHERE table_catalog = current_database() AND table_schema = current_schema()"
                + " AND lower(table_name) = lower(?) ORDER BY ordinal_position", table);
            return withoutRowId(columns, table);
        }

        /**
         * The sequence's last value, or one less than its start if it was
         * never used. DuckDB doesn't keep the last value in the file: once
         * reopened, a sequence reports the next value it will hand out as its
         * last one, so the mark reads one higher than the last row ID handed
         * out. That's the safe direction: the target continues one row ID later.
         */
        @Override
        OptionalLong highWater(Connection connection, String prefix, String table) throws SQLException {
            try (PreparedStatement statement = connection.prepareStatement("SELECT start_value, last_value"
                + " FROM duckdb_sequences() WHERE database_name = current_database()"
                + " AND schema_name = current_schema() AND sequence_name = ?")) {
                statement.setString(1, sequence(prefix, table));
                try (ResultSet result = statement.executeQuery()) {
                    if (result.next()) {
                        long start = result.getLong(1);
                        long last = result.getLong(2);
                        return OptionalLong.of(result.wasNull() ? start - 1 : last);
                    }
                }
            }
            return OptionalLong.empty();
        }

        /**
         * DuckDB can't move a sequence once it exists, so CoreProtect's
         * sequences are created here, starting after the source's high-water
         * marks, before CoreProtect's schema code creates them from 1.
         */
        @Override
        void beforeSchema(Connection connection, String prefix, Collection<String> tables, Map<String, Long> highWater)
            throws SQLException {
            try (Statement statement = connection.createStatement()) {
                for (String table : tables) {
                    if (!table.equals(DATABASE_LOCK)) {
                        long start = Math.max(1, highWater.getOrDefault(table, 0L) + 1);
                        statement.execute("CREATE SEQUENCE " + sequence(prefix, table) + " START " + start);
                    }
                }
            }
        }

        /**
         * DuckDB starts a JDBC transaction at its first statement; start it
         * now, so that its appender writes within it too, as CoreProtect's
         * own {@code Database.beginTransaction} does.
         */
        @Override
        void beginTransaction(Connection connection) throws SQLException {
            try (Statement statement = connection.createStatement();
                 ResultSet ignored = statement.executeQuery("SELECT 1")) {
                // Started
            }
        }

        @Override
        void afterWrite(Connection connection) throws SQLException {
            try (Statement statement = connection.createStatement()) {
                statement.execute("CHECKPOINT");
            }
        }

        @Override
        String lockTableDefinition(String table) {
            return "CREATE TABLE IF NOT EXISTS " + table + " (rowid INTEGER PRIMARY KEY, status TINYINT, time INTEGER)";
        }

        @Override
        boolean schemaClosesConnection() {
            return false;
        }

        @Override
        boolean pagesByRange() {
            return true;
        }

        @Override
        int rowsPerInsert() {
            return 256;
        }
    };

    static final String ROWID = "rowid";
    static final String DATABASE_LOCK = "database_lock";

    private final Engine engine;

    Dialect(Engine engine) {
        this.engine = engine;
    }

    public Engine engine() {
        return engine;
    }

    /**
     * @return the dialect for an engine, or {@code null} for engines that
     *         aren't accessed through plain JDBC
     */
    public static Dialect of(Engine engine) {
        for (Dialect dialect : values()) {
            if (dialect.engine == engine) {
                return dialect;
            }
        }
        return null;
    }

    /**
     * @return the identifier quoted for SQL
     */
    abstract String quote(String identifier);

    /**
     * @return the names of the tables in the connection's database or schema
     */
    abstract Set<String> existingTables(Connection connection) throws SQLException;

    /**
     * @param table the prefixed table name
     * @return the table's columns other than the row ID, in the table's order;
     *         empty if the table doesn't exist
     */
    abstract List<String> columns(Connection connection, String table) throws SQLException;

    /**
     * Set up a new connection for the migration.
     *
     * @param readOnly whether the connection is only for reading, so that it
     *                 refuses to write where the engine allows that
     */
    void configure(Connection connection, boolean readOnly) throws SQLException {
    }

    /**
     * @return the highest row ID the table's allocator has handed out, or
     *         empty if the engine has no allocator state beyond the rows
     */
    OptionalLong highWater(Connection connection, String prefix, String table) throws SQLException {
        return OptionalLong.empty();
    }

    /**
     * Make the table's allocator continue after {@code highWater}, where the
     * engine has allocator state that can be set after the schema exists.
     */
    void setHighWater(Connection connection, String prefix, String table, long highWater) throws SQLException {
    }

    /**
     * Prepare what CoreProtect's schema code would otherwise create in a way
     * that doesn't keep the source's row IDs.
     */
    void beforeSchema(Connection connection, String prefix, Collection<String> tables, Map<String, Long> highWater)
        throws SQLException {
    }

    /**
     * Start the transaction of a connection that doesn't auto-commit.
     */
    void beginTransaction(Connection connection) throws SQLException {
    }

    /**
     * Make written data durable, before validation reads it back or
     * CoreProtect opens the database.
     */
    void afterWrite(Connection connection) throws SQLException {
    }

    /**
     * @return a column value in {@link net.deltik.mc.libreprotect.extension.migration.Row}'s normalized form
     */
    Object read(ResultSet result, int column) throws SQLException {
        switch (result.getMetaData().getColumnType(column)) {
            case Types.BINARY:
            case Types.VARBINARY:
            case Types.LONGVARBINARY:
            case Types.BLOB:
                return result.getBytes(column);
            default:
                return Values.normalize(result.getObject(column));
        }
    }

    /**
     * @return CoreProtect's definition of the {@code database_lock} table,
     *         the same in CoreProtect 24 and 25
     */
    abstract String lockTableDefinition(String table);

    /**
     * @return whether upstream's schema code closes the connection it's
     *         given, so it needs one of its own
     */
    boolean schemaClosesConnection() {
        return true;
    }

    /**
     * @return whether to read pages by row ID ranges, for engines without an
     *         index on the row ID, where {@code ORDER BY rowid LIMIT n} scans
     *         the rest of the table every time
     */
    boolean pagesByRange() {
        return false;
    }

    /**
     * @return how many rows to insert per statement: 1 to use JDBC batches,
     *         more for drivers that run a batch one statement at a time
     */
    int rowsPerInsert() {
        return 1;
    }

    /**
     * @return whether to abort connections from another thread when the
     *         migration has to stop: those of network engines, whose calls
     *         can wait on an unresponsive server. Calls to embedded engines
     *         end on their own, and closing their connections from another
     *         thread isn't safe.
     */
    boolean abortsConnections() {
        return false;
    }

    /**
     * @return the table names from {@link #existingTables}, lowercased:
     *         names match regardless of case on SQLite and DuckDB, and on
     *         MySQL where {@code lower_case_table_names} is set, as on
     *         Windows. A MySQL server without it that has two tables
     *         differing only in case isn't one CoreProtect made.
     */
    static Set<String> lowercase(Set<String> names) {
        Set<String> lowercase = new HashSet<>();
        for (String name : names) {
            lowercase.add(name.toLowerCase(Locale.ROOT));
        }
        return lowercase;
    }

    static String sequence(String prefix, String table) {
        return prefix + table + "_rowid_seq";
    }

    private static List<String> withoutRowId(List<String> columns, String table) throws SQLException {
        if (!columns.isEmpty() && columns.stream().noneMatch(ROWID::equalsIgnoreCase)) {
            throw new SQLException("Table " + table + " has no rowid column");
        }
        columns.removeIf(ROWID::equalsIgnoreCase);
        return columns;
    }

    private static Set<String> strings(Connection connection, String sql) throws SQLException {
        Set<String> values = new HashSet<>();
        try (Statement statement = connection.createStatement(); ResultSet result = statement.executeQuery(sql)) {
            while (result.next()) {
                values.add(result.getString(1));
            }
        }
        return values;
    }

    private static List<String> strings(Connection connection, String sql, String parameter) throws SQLException {
        List<String> values = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, parameter);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    values.add(result.getString(1));
                }
            }
        }
        return values;
    }

    @Override
    public String toString() {
        return name().toLowerCase(Locale.ROOT);
    }
}
