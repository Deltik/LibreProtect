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

package net.deltik.mc.libreprotect.extension.migration.jdbc;

import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.Row;
import net.deltik.mc.libreprotect.extension.migration.RowSink;
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import net.deltik.mc.libreprotect.extension.migration.TransientErrors;

import java.io.File;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLDataException;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Writes a migration's target in SQLite, MySQL or DuckDB, keeping every row
 * ID. The target is marked as holding an unfinished migration from before
 * CoreProtect's tables exist until activation clears the mark.
 */
public final class JdbcRowSink implements RowSink {

    /** Files an engine keeps next to a database, which would be applied to a new database of the same name */
    private static final String[] SQLITE_COMPANIONS = {"-wal", "-shm", "-journal"};
    private static final String[] DUCKDB_COMPANIONS = {".wal"};

    private final Dialect dialect;
    private final Connector connector;
    private final String prefix;
    private final List<String> knownTables;
    private final SchemaCreator schema;
    private final IncompleteMarker marker;
    private final File file;
    private final BulkInsert bulkInsert;
    private volatile Connection connection;
    private volatile Connection schemaConnection;
    private volatile boolean aborted;
    private boolean retrying;
    private boolean closed;

    /**
     * @param connector opens a connection to the target, again after one breaks
     * @param prefix the table prefix, such as {@code co_}
     * @param knownTables CoreProtect's tables, unprefixed
     * @param schema creates CoreProtect's tables
     * @param marker how to mark the target as unfinished
     * @param file the database file of an embedded engine, which must not
     *             be created before {@link #prepare}; {@code null} otherwise
     * @param bulkInsert a faster way to insert rows, or {@code null} to use SQL
     */
    public JdbcRowSink(Dialect dialect, Connector connector, String prefix, Collection<String> knownTables,
                       SchemaCreator schema, IncompleteMarker marker, File file, BulkInsert bulkInsert) {
        this.dialect = dialect;
        this.connector = connector;
        this.prefix = prefix;
        this.knownTables = Collections.unmodifiableList(new ArrayList<>(knownTables));
        this.schema = schema;
        this.marker = marker;
        this.file = file;
        this.bulkInsert = bulkInsert;
    }

    @Override
    public Engine engine() {
        return dialect.engine();
    }

    /**
     * A SQLite target must be a missing file or one without CoreProtect data,
     * a DuckDB target must be a new file, and a MySQL target must have no
     * CoreProtect data under the prefix. An existing {@code database_lock}
     * table doesn't count as data.
     */
    @Override
    public Optional<String> nonEmptyReason() throws SQLException {
        if (file != null) {
            if (dialect == Dialect.DUCKDB && file.exists()) {
                return Optional.of(file.getPath() + " already exists, and a DuckDB target must be a new file");
            }
            if (!file.exists()) {
                for (String companion : dialect == Dialect.DUCKDB ? DUCKDB_COMPANIONS : SQLITE_COMPANIONS) {
                    File leftover = new File(file.getPath() + companion);
                    if (leftover.exists()) {
                        return Optional.of(leftover.getPath() + " is left over from an earlier database");
                    }
                }
                return Optional.empty();
            }
        }
        Set<String> existing = Dialect.lowercase(dialect.existingTables(connection()));
        for (String table : knownTables) {
            if (table.equals(Dialect.DATABASE_LOCK) || !existing.contains((prefix + table).toLowerCase(Locale.ROOT))) {
                continue;
            }
            try (Statement statement = connection().createStatement();
                 ResultSet result = statement.executeQuery("SELECT 1 FROM " + dialect.quote(prefix + table)
                     + " LIMIT 1")) {
                if (result.next()) {
                    return Optional.of(file != null
                        ? file.getPath() + " has rows in table " + prefix + table
                        : "table " + prefix + table + " has rows");
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Mark the target unfinished, create DuckDB's sequences after the high-water
     * marks, then let CoreProtect create the rest of its schema, and check
     * that every table exists.
     */
    @Override
    public void prepare(Map<String, Long> highWater) throws SQLException {
        Connection target = connection();
        createMarkedLock(target);
        dialect.beforeSchema(target, prefix, knownTables, highWater);
        if (dialect.schemaClosesConnection()) {
            Connection throwaway = open();
            schemaConnection = throwaway;
            try {
                if (aborted) {
                    abort();
                    throw Connectors.aborted();
                }
                schema.create(throwaway, prefix);
            } finally {
                schemaConnection = null;
                JdbcRowSource.closeQuietly(throwaway);
            }
        } else {
            schema.create(target, prefix);
        }
        for (String table : knownTables) {
            if (dialect.columns(connection(), prefix + table).isEmpty()) {
                throw new SQLException("CoreProtect didn't create table " + prefix + table + " in the target");
            }
        }
    }

    @Override
    public List<String> columns(String table) throws SQLException {
        return dialect.columns(connection(), prefix + table);
    }

    @Override
    public void markIncomplete() throws SQLException {
        writeMarker(marker.status(), marker.time());
    }

    /**
     * Write the rows in one transaction. After a failed write, the next one
     * first deletes its row ID range, in case the failed write's commit
     * went through without the driver hearing back; so a retried write
     * never duplicates rows. A value that doesn't fit fails with the row ID.
     */
    @Override
    public void write(String table, List<String> columns, List<Row> rows) throws SQLException {
        if (rows.isEmpty()) {
            return;
        }
        Connection target = connection();
        try {
            target.setAutoCommit(false);
            dialect.beginTransaction(target);
            if (retrying) {
                deleteRange(target, table, rows);
            }
            if (bulkInsert == null || !bulkInsert.insert(target, prefix + table, columns, rows)) {
                insert(target, table, columns, rows);
            }
            target.commit();
            target.setAutoCommit(true);
            retrying = false;
        } catch (SQLException e) {
            retrying = true;
            rollbackQuietly(target);
            SQLException located = locate(target, table, columns, rows, e);
            dropIfBroken(target);
            throw located;
        }
    }

    @Override
    public void finish(Map<String, Long> highWater) throws SQLException {
        Connection target = connection();
        for (Map.Entry<String, Long> entry : highWater.entrySet()) {
            dialect.setHighWater(target, prefix, entry.getKey(), entry.getValue());
        }
        dialect.afterWrite(target);
    }

    @Override
    public RowSource readBack() throws SQLException {
        return new JdbcRowSource(dialect, this::connection, false, false, prefix, knownTables);
    }

    @Override
    public void markComplete() throws SQLException {
        writeMarker(0, (int) (System.currentTimeMillis() / 1000L));
    }

    /**
     * Abort the connections of a network engine; later calls fail.
     */
    @Override
    public void abort() {
        aborted = true;
        if (dialect.abortsConnections()) {
            Connectors.abort(connection);
            Connectors.abort(schemaConnection);
        }
    }

    /**
     * Close the connection, making DuckDB's data durable first, so that
     * CoreProtect can open the database. Does nothing when called again.
     */
    @Override
    public void close() throws SQLException {
        closed = true;
        Connection open = connection;
        connection = null;
        if (open != null) {
            try {
                if (!open.isClosed()) {
                    dialect.afterWrite(open);
                }
            } finally {
                open.close();
            }
        }
    }

    /**
     * Create the {@code database_lock} table, if it's missing, and mark it
     * unfinished. SQLite and DuckDB do both in one transaction, so that the
     * table never exists without the mark, even if the server dies between
     * them. MySQL commits a table's creation on its own, so a stop between
     * the two leaves the table empty; but then nothing else exists yet, and
     * like a missing table, an empty one counts as no data: CoreProtect fills
     * it in as unlocked, and the next migration marks it.
     */
    private void createMarkedLock(Connection target) throws SQLException {
        String definition = dialect.lockTableDefinition(dialect.quote(prefix + Dialect.DATABASE_LOCK));
        if (dialect == Dialect.MYSQL) {
            try (Statement statement = target.createStatement()) {
                statement.execute(definition);
            }
            writeMarker(marker.status(), marker.time());
            return;
        }
        try {
            target.setAutoCommit(false);
            try (Statement statement = target.createStatement()) {
                statement.execute(definition);
            }
            writeMarker(marker.status(), marker.time());
            target.commit();
            target.setAutoCommit(true);
        } catch (SQLException e) {
            rollbackQuietly(target);
            dropIfBroken(target);
            throw e;
        }
    }

    private void writeMarker(int status, int time) throws SQLException {
        String table = dialect.quote(prefix + Dialect.DATABASE_LOCK);
        Connection target = connection();
        try (PreparedStatement update = target.prepareStatement("UPDATE " + table + " SET status = ?, time = ?"
            + " WHERE rowid = 1")) {
            update.setInt(1, status);
            update.setInt(2, time);
            if (update.executeUpdate() > 0) {
                return;
            }
        }
        try (PreparedStatement insert = target.prepareStatement("INSERT INTO " + table + " (rowid, status, time)"
            + " VALUES (1, ?, ?)")) {
            insert.setInt(1, status);
            insert.setInt(2, time);
            insert.executeUpdate();
        }
    }

    private void deleteRange(Connection target, String table, List<Row> rows) throws SQLException {
        try (PreparedStatement delete = target.prepareStatement("DELETE FROM " + dialect.quote(prefix + table)
            + " WHERE rowid >= ? AND rowid <= ?")) {
            delete.setLong(1, rows.get(0).rowId());
            delete.setLong(2, rows.get(rows.size() - 1).rowId());
            delete.executeUpdate();
        }
    }

    /**
     * After a batch failed for a reason other than a lost connection, find
     * the row that fails and name it, in a transaction that's rolled back.
     */
    private SQLException locate(Connection target, String table, List<String> columns, List<Row> rows,
                                SQLException failure) {
        if (aborted || TransientErrors.isTransient(failure)) {
            return failure;
        }
        try {
            target.setAutoCommit(false);
            try {
                deleteRange(target, table, rows);
                try (PreparedStatement insert = target.prepareStatement(insert(table, columns, 1))) {
                    for (Row row : rows) {
                        bind(insert, 0, row);
                        try {
                            insert.executeUpdate();
                        } catch (SQLException e) {
                            return new SQLDataException("Row ID " + row.rowId() + " of table " + table
                                + " can't be written to the target: " + e.getMessage(), e.getSQLState(),
                                e.getErrorCode(), e);
                        }
                    }
                }
            } finally {
                rollbackQuietly(target);
            }
        } catch (SQLException e) {
            failure.addSuppressed(e);
        }
        return failure;
    }

    private void insert(Connection target, String table, List<String> columns, List<Row> rows) throws SQLException {
        int perStatement = dialect.rowsPerInsert();
        if (perStatement > 1) {
            insertMany(target, table, columns, rows, perStatement);
            return;
        }
        try (PreparedStatement insert = target.prepareStatement(insert(table, columns, 1))) {
            for (Row row : rows) {
                bind(insert, 0, row);
                insert.addBatch();
            }
            insert.executeBatch();
        }
    }

    /**
     * Insert rows through statements with several rows each, for engines
     * whose drivers run a batch one row at a time.
     */
    private void insertMany(Connection target, String table, List<String> columns, List<Row> rows, int perStatement)
        throws SQLException {
        int full = rows.size() / perStatement * perStatement;
        if (full > 0) {
            try (PreparedStatement insert = target.prepareStatement(insert(table, columns, perStatement))) {
                for (int start = 0; start < full; start += perStatement) {
                    for (int i = 0; i < perStatement; i++) {
                        bind(insert, i * (columns.size() + 1), rows.get(start + i));
                    }
                    insert.executeUpdate();
                }
            }
        }
        if (full < rows.size()) {
            try (PreparedStatement insert = target.prepareStatement(insert(table, columns, rows.size() - full))) {
                for (int i = full; i < rows.size(); i++) {
                    bind(insert, (i - full) * (columns.size() + 1), rows.get(i));
                }
                insert.executeUpdate();
            }
        }
    }

    private String insert(String table, List<String> columns, int rows) {
        StringBuilder sql = new StringBuilder("INSERT INTO ").append(dialect.quote(prefix + table)).append(" (rowid");
        StringBuilder values = new StringBuilder("(?");
        for (String column : columns) {
            sql.append(", ").append(dialect.quote(column));
            values.append(", ?");
        }
        values.append(')');
        sql.append(") VALUES ").append(values);
        for (int i = 1; i < rows; i++) {
            sql.append(", ").append(values);
        }
        return sql.toString();
    }

    /**
     * Bind a row's row ID and values to the parameters after {@code offset}.
     */
    private static void bind(PreparedStatement statement, int offset, Row row) throws SQLException {
        statement.setLong(offset + 1, row.rowId());
        Object[] values = row.values();
        for (int i = 0; i < values.length; i++) {
            Object value = values[i];
            int index = offset + i + 2;
            if (value == null) {
                statement.setNull(index, Types.NULL);
            } else if (value instanceof Long) {
                statement.setLong(index, (Long) value);
            } else if (value instanceof Double) {
                statement.setDouble(index, (Double) value);
            } else if (value instanceof String) {
                statement.setString(index, (String) value);
            } else if (value instanceof byte[]) {
                statement.setBytes(index, (byte[]) value);
            } else {
                throw new SQLDataException("Row ID " + row.rowId() + " has a value of unexpected type "
                    + value.getClass().getName());
            }
        }
    }

    private Connection connection() throws SQLException {
        if (closed) {
            throw new SQLException("The target is closed");
        }
        if (connection == null) {
            Connection opened = open();
            try {
                dialect.configure(opened, false);
                opened.setAutoCommit(true);
            } catch (SQLException e) {
                JdbcRowSource.closeQuietly(opened);
                throw e;
            }
            connection = opened;
            if (aborted) {
                abort();
                throw Connectors.aborted();
            }
        }
        return connection;
    }

    private Connection open() throws SQLException {
        if (aborted) {
            throw Connectors.aborted();
        }
        return Connectors.open(dialect, connector, () -> aborted);
    }

    private void dropIfBroken(Connection target) {
        if (aborted) {
            return;
        }
        if (connection == target && !JdbcRowSource.isValid(target)) {
            JdbcRowSource.closeQuietly(target);
            connection = null;
        } else {
            try {
                target.setAutoCommit(true);
            } catch (SQLException e) {
                JdbcRowSource.closeQuietly(target);
                connection = null;
            }
        }
    }

    private static void rollbackQuietly(Connection connection) {
        try {
            if (!connection.getAutoCommit()) {
                connection.rollback();
            }
        } catch (SQLException e) {
            // The connection is gone, and with it the transaction
        }
    }
}
