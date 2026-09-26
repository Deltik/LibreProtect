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
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import net.deltik.mc.libreprotect.extension.migration.TableStats;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.OptionalLong;
import java.util.Set;

/**
 * Reads CoreProtect's tables from SQLite, MySQL or DuckDB. It only ever
 * reads, and asks the engine to refuse writes on its connection where the
 * engine allows that.
 */
public final class JdbcRowSource implements RowSource {

    private final Dialect dialect;
    private final Connector connector;
    private final boolean ownsConnection;
    private final boolean readOnly;
    private final String prefix;
    private final List<String> knownTables;
    private final Map<String, TableStats> rangeStats = new HashMap<>();
    private final Map<String, Long> rangeSpans = new HashMap<>();
    private volatile Connection connection;
    private volatile boolean aborted;

    /**
     * @param connector opens the connection, once, and again after the
     *                  connection breaks
     * @param ownsConnection whether {@link #close()} closes the connection;
     *                       false for a connection shared with a sink
     * @param readOnly whether to make the connection refuse writes
     * @param prefix the table prefix, such as {@code co_}
     * @param knownTables CoreProtect's tables, unprefixed
     */
    public JdbcRowSource(Dialect dialect, Connector connector, boolean ownsConnection, boolean readOnly, String prefix,
                         Collection<String> knownTables) {
        this.dialect = dialect;
        this.connector = connector;
        this.ownsConnection = ownsConnection;
        this.readOnly = readOnly;
        this.prefix = prefix;
        this.knownTables = Collections.unmodifiableList(new ArrayList<>(knownTables));
    }

    @Override
    public Engine engine() {
        return dialect.engine();
    }

    /**
     * @return the known tables the database has, matching names regardless
     *         of case (see {@link Dialect#lowercase})
     */
    @Override
    public List<String> tables() throws SQLException {
        return guarded(() -> {
            Set<String> existing = Dialect.lowercase(dialect.existingTables(connection()));
            List<String> tables = new ArrayList<>();
            for (String table : knownTables) {
                if (existing.contains((prefix + table).toLowerCase(Locale.ROOT))) {
                    tables.add(table);
                }
            }
            return tables;
        });
    }

    @Override
    public List<String> columns(String table) throws SQLException {
        return guarded(() -> dialect.columns(connection(), prefix + table));
    }

    @Override
    public TableStats stats(String table) throws SQLException {
        return guarded(() -> {
            try (Statement statement = connection().createStatement();
                 ResultSet result = statement.executeQuery("SELECT COUNT(*), MIN(rowid), MAX(rowid) FROM "
                     + dialect.quote(prefix + table))) {
                result.next();
                long count = result.getLong(1);
                return count == 0 ? new TableStats(0, 0, 0) : new TableStats(count, result.getLong(2), result.getLong(3));
            }
        });
    }

    @Override
    public OptionalLong highWater(String table) throws SQLException {
        return guarded(() -> dialect.highWater(connection(), prefix, table));
    }

    @Override
    public List<Row> read(String table, List<String> columns, long afterRowId, int limit) throws SQLException {
        if (limit <= 0) {
            return Collections.emptyList();
        }
        return guarded(() -> dialect.pagesByRange()
            ? readByRange(table, columns, afterRowId, limit)
            : query(select(table, columns) + " WHERE rowid > ? ORDER BY rowid LIMIT " + limit, columns.size(),
            afterRowId));
    }

    @Override
    public List<Row> readRange(String table, List<String> columns, long fromRowId, long toRowId) throws SQLException {
        return guarded(() -> query(select(table, columns) + " WHERE rowid >= ? AND rowid <= ? ORDER BY rowid",
            columns.size(), fromRowId, toRowId));
    }

    /**
     * Read the next page as the rows in a row ID range, which an engine
     * without an index on the row ID can find from its per-block statistics,
     * widening the range until it holds rows or passes the largest row ID.
     */
    private List<Row> readByRange(String table, List<String> columns, long afterRowId, int limit) throws SQLException {
        TableStats cached = rangeStats.get(table);
        if (cached == null) {
            cached = stats(table);
            rangeStats.put(table, cached);
        }
        TableStats stats = cached;
        if (stats.count() == 0 || afterRowId >= stats.maxRowId()) {
            return Collections.emptyList();
        }
        // Start with a range that holds about a page of rows if the row IDs are spread evenly
        long span = rangeSpans.computeIfAbsent(table, ignored -> Math.max(limit, (long) Math.ceil(
            limit * ((double) stats.maxRowId() - stats.minRowId() + 1) / stats.count())));
        String sql = select(table, columns) + " WHERE rowid > ? AND rowid <= ? ORDER BY rowid LIMIT " + limit;
        long from = stats.minRowId() > Long.MIN_VALUE ? Math.max(afterRowId, stats.minRowId() - 1) : afterRowId;
        while (from < stats.maxRowId()) {
            long to = (double) stats.maxRowId() - from <= span ? stats.maxRowId() : from + span;
            List<Row> rows = query(sql, columns.size(), from, to);
            if (!rows.isEmpty()) {
                if (rows.size() < limit / 2) {
                    rangeSpans.put(table, doubled(span));
                }
                return rows;
            }
            from = to;
            span = doubled(span);
            rangeSpans.put(table, span);
        }
        return Collections.emptyList();
    }

    private static long doubled(long span) {
        return span > Long.MAX_VALUE / 4 ? span : span * 2;
    }

    private String select(String table, List<String> columns) {
        StringBuilder sql = new StringBuilder("SELECT rowid");
        for (String column : columns) {
            sql.append(", ").append(dialect.quote(column));
        }
        return sql.append(" FROM ").append(dialect.quote(prefix + table)).toString();
    }

    private List<Row> query(String sql, int columnCount, long... parameters) throws SQLException {
        List<Row> rows = new ArrayList<>();
        try (PreparedStatement statement = connection().prepareStatement(sql)) {
            for (int i = 0; i < parameters.length; i++) {
                statement.setLong(i + 1, parameters[i]);
            }
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    Object[] values = new Object[columnCount];
                    for (int i = 0; i < columnCount; i++) {
                        values[i] = dialect.read(result, i + 2);
                    }
                    rows.add(new Row(result.getLong(1), values));
                }
            }
        }
        return rows;
    }

    private Connection connection() throws SQLException {
        if (aborted) {
            throw Connectors.aborted();
        }
        if (connection == null) {
            Connection opened = Connectors.open(dialect, connector, () -> aborted);
            try {
                dialect.configure(opened, readOnly);
            } catch (SQLException e) {
                closeQuietly(opened);
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

    /**
     * Abort the connection of a network engine; later calls fail.
     */
    @Override
    public void abort() {
        aborted = true;
        if (dialect.abortsConnections() && ownsConnection) {
            Connectors.abort(connection);
        }
    }

    /** A read of the database */
    @FunctionalInterface
    private interface Read<T> {
        T run() throws SQLException;
    }

    /**
     * Run a read; if it fails and the connection broke, drop the
     * connection so that the next read, such as a retry, opens a new one.
     */
    private <T> T guarded(Read<T> read) throws SQLException {
        try {
            return read.run();
        } catch (SQLException e) {
            Connection broken = connection;
            if (ownsConnection && broken != null && !aborted && !isValid(broken)) {
                closeQuietly(broken);
                connection = null;
            }
            throw e;
        }
    }

    @Override
    public void close() throws SQLException {
        Connection open = connection;
        connection = null;
        if (open != null && ownsConnection) {
            open.close();
        }
    }

    static boolean isValid(Connection connection) {
        try {
            return !connection.isClosed() && connection.isValid(5);
        } catch (SQLException e) {
            return false;
        }
    }

    static void closeQuietly(AutoCloseable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (Exception e) {
                // Already failing; the first error is the one to report
            }
        }
    }
}
