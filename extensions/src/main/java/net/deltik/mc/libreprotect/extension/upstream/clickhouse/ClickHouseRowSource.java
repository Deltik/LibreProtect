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

package net.deltik.mc.libreprotect.extension.upstream.clickhouse;

import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.Row;
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import net.deltik.mc.libreprotect.extension.migration.TableStats;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Config;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Family;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.HighWaterMarks;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Pool;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.sql.SQLNonTransientConnectionException;
import java.sql.SQLNonTransientException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.OptionalLong;
import java.util.Set;

/**
 * Reads CoreProtect's tables from ClickHouse, through the views CoreProtect
 * defines over its event table. The views show the current version of every
 * row, so rolled-back blocks and updated entities read as CoreProtect sees
 * them.
 *
 * <p>This only reads, over its own connections, so it can read the active
 * database without a second ClickHouse writer. Not thread-safe.
 *
 * <p>ClickHouse sorts CoreProtect's events by location and time, not row ID,
 * so any query for a row ID range scans the whole table. {@link #read}
 * therefore keeps one query streaming the table in row ID order, and continues
 * it when the next call asks for the rows after the last ones it returned,
 * which reads each table once; paging with a query per page would scan the
 * table once per page. {@link #readRange} and {@link #readRanges} scan the
 * table once per query. For 2 million block rows on a local server, reading
 * the table took about 6 seconds, and a single range about 0.8 seconds.
 *
 * <p>To stream a table in row ID order, ClickHouse first sorts all of it,
 * so the first rows of a very large table take a while, and a sort larger
 * than half of the server's memory spills to its temporary disk space, which
 * then needs about as much room as the table's data. That stream has no
 * socket timeout, since nothing arrives while the server sorts; every other
 * query has CoreProtect's normal 5-minute timeout.
 *
 * <p>{@link #abort()} ends a query waiting on the server at once, from any
 * thread: it closes both connection pools, whose shutdown aborts the
 * connections in use, and every call after it fails.
 */
final class ClickHouseRowSource implements RowSource {

    /** How many duplicated values to count before saying "more than" */
    private static final int DUPLICATES_COUNTED = 100;

    /** Row ID ranges per query, well within ClickHouse's default maximum query size */
    static final int RANGES_PER_QUERY = 1000;

    private final ClickHouseApi api;
    /** For queries that finish within CoreProtect's normal timeout */
    private final Pool jdbc;
    /** For streaming a whole table, with no timeout */
    private final Pool streaming;
    private final String database;
    private final String prefix;
    private HighWaterMarks highWaterMarks;
    private boolean entitySpawnChecked;
    private Cursor cursor;
    private volatile boolean aborted;

    /**
     * @param api    CoreProtect's ClickHouse classes, for reading
     * @param config where to read, as CoreProtect connects to it
     */
    ClickHouseRowSource(ClickHouseApi api, Config config, String prefix) throws SQLException {
        if (!prefix.isEmpty()) {
            ClickHouseColumns.quote(prefix);
        }
        this.api = api;
        this.database = config.database();
        this.prefix = prefix;
        this.jdbc = api.pool(config);
        this.streaming = api.pool(config.forMigrationReads());
    }

    @Override
    public Engine engine() {
        return Engine.CLICKHOUSE;
    }

    @Override
    public List<String> tables() throws SQLException {
        Set<String> present = new HashSet<>();
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT name FROM system.tables WHERE database = ? AND startsWith(name, ?)")) {
            statement.setString(1, database);
            statement.setString(2, prefix);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    present.add(resultSet.getString(1).substring(prefix.length()));
                }
            }
        }
        List<String> tables = new ArrayList<>();
        for (Family family : api.families()) {
            if (present.contains(family.tableName())) {
                tables.add(family.tableName());
            }
        }
        return tables;
    }

    @Override
    public List<String> columns(String table) throws SQLException {
        try (Connection connection = connection()) {
            return columns(api, connection, database, prefix, table);
        }
    }

    /**
     * @return the columns of a CoreProtect view that migrations copy, in the view's order
     * @throws SQLException if the view doesn't exist
     */
    static List<String> columns(ClickHouseApi api, Connection connection, String database, String prefix,
                                String table) throws SQLException {
        ClickHouseColumns.family(api, table);
        List<String> columns = new ArrayList<>();
        boolean exists = false;
        try (PreparedStatement statement = connection.prepareStatement(
            "SELECT name FROM system.columns WHERE database = ? AND table = ? ORDER BY position")) {
            statement.setString(1, database);
            statement.setString(2, prefix + table);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    exists = true;
                    String column = resultSet.getString(1);
                    if (ClickHouseColumns.isCopied(column)) {
                        columns.add(column);
                    }
                }
            }
        }
        if (!exists) {
            throw new SQLException("ClickHouse database '" + database + "' has no table " + prefix + table);
        }
        return columns;
    }

    @Override
    public TableStats stats(String table) throws SQLException {
        String view = view(table);
        checkCopyable(table);
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT count(), min(rowid), max(rowid) FROM " + view);
             ResultSet resultSet = statement.executeQuery()) {
            resultSet.next();
            long count = resultSet.getLong(1);
            return count == 0 ? new TableStats(0, 0, 0)
                : new TableStats(count, resultSet.getLong(2), resultSet.getLong(3));
        }
    }

    /**
     * The highest row ID ClickHouse has recorded for the table: the largest
     * among its rows, including rows that were purged since. That's what
     * CoreProtect continues after when it starts on this database. Read once,
     * when first asked.
     */
    @Override
    public OptionalLong highWater(String table) throws SQLException {
        Family family = ClickHouseColumns.family(api, table);
        if (highWaterMarks == null) {
            try (Connection connection = connection()) {
                highWaterMarks = api.readHighWaterMarks(connection, database, prefix);
            }
        }
        return OptionalLong.of(highWaterMarks.compatibilityRowId(family));
    }

    @Override
    public List<Row> read(String table, List<String> columns, long afterRowId, int limit) throws SQLException {
        requireNotAborted();
        String view = view(table);
        checkCopyable(table);
        if (limit < 1) {
            return Collections.emptyList();
        }
        if (cursor == null || !cursor.continues(table, columns, afterRowId)) {
            closeCursor();
            cursor = new Cursor(table, columns, view, afterRowId);
        }
        List<Row> rows = new ArrayList<>(Math.min(limit, 10_000));
        boolean resumed = false;
        while (rows.size() < limit) {
            Row row;
            try {
                row = cursor.next();
            } catch (SQLNonTransientException | RuntimeException e) {
                // Asked for the same rows again, read the failed row again
                // instead of continuing this query past it
                closeCursor();
                throw e;
            } catch (SQLException e) {
                // The server ends a result that isn't read from for a while
                // (send_timeout), e.g. while the target retries a write
                resume(table, columns, view, resumed, e);
                resumed = true;
                continue;
            }
            if (row != null) {
                rows.add(row);
                continue;
            }
            long lastRowId = cursor.lastRowId;
            if (!hasRowsAfter(view, lastRowId)) {
                closeCursor();
                break;
            }
            // A result cut short must not pass for the end of the table
            resume(table, columns, view, resumed, new SQLException("The ClickHouse query reading " + table
                + " ended after row ID " + lastRowId + ", before the end of the table"));
            resumed = true;
        }
        return rows;
    }

    /**
     * Continue reading after the last row read, with a new query, once per
     * call to {@link #read}.
     */
    private void resume(String table, List<String> columns, String view, boolean resumed, SQLException failure)
        throws SQLException {
        long lastRowId = cursor.lastRowId;
        closeCursor();
        if (resumed) {
            throw failure;
        }
        cursor = new Cursor(table, columns, view, lastRowId);
    }

    private boolean hasRowsAfter(String view, long rowId) throws SQLException {
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement(
                 "SELECT 1 FROM " + view + " WHERE rowid > ? LIMIT 1")) {
            statement.setLong(1, rowId);
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next();
            }
        }
    }

    @Override
    public List<Row> readRange(String table, List<String> columns, long fromRowId, long toRowId)
        throws SQLException {
        return readRanges(table, columns, Collections.singletonList(new long[]{fromRowId, toRowId}));
    }

    /**
     * Read the ranges with one scan of the table per {@value #RANGES_PER_QUERY} ranges.
     */
    @Override
    public List<Row> readRanges(String table, List<String> columns, List<long[]> ranges) throws SQLException {
        String view = view(table);
        checkCopyable(table);
        List<Row> rows = new ArrayList<>();
        long lastRowId = Long.MIN_VALUE;
        for (int start = 0; start < ranges.size(); start += RANGES_PER_QUERY) {
            List<long[]> batch = ranges.subList(start, Math.min(ranges.size(), start + RANGES_PER_QUERY));
            StringBuilder sql = new StringBuilder(select(columns, view));
            for (int index = 0; index < batch.size(); index++) {
                sql.append(index == 0 ? " WHERE " : " OR ").append("(rowid >= ? AND rowid <= ?)");
            }
            try (Connection connection = connection();
                 PreparedStatement statement = connection.prepareStatement(sql + " ORDER BY rowid")) {
                int parameter = 1;
                for (long[] range : batch) {
                    statement.setLong(parameter++, range[0]);
                    statement.setLong(parameter++, range[1]);
                }
                try (ResultSet resultSet = statement.executeQuery()) {
                    ClickHouseColumns.RowReader reader =
                        new ClickHouseColumns.RowReader(table, columns, resultSet.getMetaData());
                    while (resultSet.next()) {
                        Row row = reader.read(resultSet);
                        requireAscending(table, lastRowId, row.rowId());
                        lastRowId = row.rowId();
                        rows.add(row);
                    }
                }
            }
        }
        return rows;
    }

    /**
     * Close both connection pools, which aborts their connections in use, so
     * that a query waiting on the server fails at once, and fail every call
     * from now on.
     */
    @Override
    public void abort() {
        aborted = true;
        for (Pool pool : new Pool[]{streaming, jdbc}) {
            try {
                pool.close();
            } catch (RuntimeException e) {
                // Best effort; the pool refuses new connections regardless
            }
        }
    }

    @Override
    public void close() throws SQLException {
        try {
            closeCursor();
        } finally {
            try {
                streaming.close();
            } finally {
                jdbc.close();
            }
        }
    }

    private Connection connection() throws SQLException {
        requireNotAborted();
        return jdbc.openConnection();
    }

    private Connection streamingConnection() throws SQLException {
        requireNotAborted();
        return streaming.openConnection();
    }

    private void requireNotAborted() throws SQLNonTransientConnectionException {
        if (aborted) {
            throw new SQLNonTransientConnectionException("Reading ClickHouse stopped because the migration is stopping");
        }
    }

    private String view(String table) throws SQLException {
        ClickHouseColumns.family(api, table);
        return api.qualified(database, prefix + table);
    }

    private static String select(List<String> columns, String view) throws SQLException {
        StringBuilder sql = new StringBuilder("SELECT rowid");
        for (String column : columns) {
            sql.append(", ").append(ClickHouseColumns.quote(column));
        }
        return sql.append(" FROM ").append(view).toString();
    }

    /**
     * Every other engine gives each row its own row ID, so a table where two
     * rows share one can't be copied.
     */
    private static void requireAscending(String table, long lastRowId, long rowId) throws SQLException {
        if (rowId <= lastRowId) {
            throw new SQLIntegrityConstraintViolationException("ClickHouse table " + table
                + " has more than one row with row ID " + rowId + ", which the other engines can't store");
        }
    }

    /**
     * Check what only matters when copying out of ClickHouse: the other
     * engines require each tracked entity's UUID and kill row ID to be
     * unique, which ClickHouse doesn't enforce. Rather than fail partway
     * through a copy on the target's constraint, name the duplicates up front.
     */
    private void checkCopyable(String table) throws SQLException {
        if (entitySpawnChecked || !table.equals("entity_spawn")) {
            return;
        }
        String view = view(table);
        List<String> problems = new ArrayList<>();
        try (Connection connection = connection()) {
            duplicates(connection, view, "uuid", "UUID", problems);
            duplicates(connection, view, "kill_rowid", "kill row ID", problems);
        }
        if (!problems.isEmpty()) {
            throw new SQLIntegrityConstraintViolationException("ClickHouse table entity_spawn can't be copied: "
                + "SQLite, MySQL and DuckDB require each entity's UUID and kill row ID to be unique, but "
                + String.join(" and ", problems) + ". Resolve the duplicates in ClickHouse before migrating.");
        }
        entitySpawnChecked = true;
    }

    private static void duplicates(Connection connection, String view, String column, String description,
                                   List<String> problems) throws SQLException {
        String quoted = ClickHouseColumns.quote(column);
        String sql = "SELECT toString(" + quoted + ") AS value,"
            + " arrayStringConcat(arrayMap(x -> toString(x), arraySort(groupArray(5)(rowid))), ', ')"
            + " FROM " + view + " WHERE " + quoted + " IS NOT NULL"
            + " GROUP BY value HAVING count() > 1 ORDER BY value LIMIT " + (DUPLICATES_COUNTED + 1);
        int duplicates = 0;
        String example = null;
        try (PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet resultSet = statement.executeQuery()) {
            while (resultSet.next()) {
                if (example == null) {
                    example = resultSet.getString(1) + " in rows " + resultSet.getString(2);
                }
                duplicates++;
            }
        }
        if (duplicates > 0) {
            String count = duplicates > DUPLICATES_COUNTED ? "more than " + DUPLICATES_COUNTED
                : String.format(Locale.ROOT, "%,d", duplicates);
            problems.add(count + " " + description + (duplicates == 1 ? " appears" : "s appear")
                + " in more than one row (e.g. " + example + ")");
        }
    }

    private void closeCursor() {
        if (cursor != null) {
            cursor.close();
            cursor = null;
        }
    }

    /**
     * A query streaming a table's rows in row ID order, from after a row ID
     * to the end of the table.
     *
     * <p>It starts at the row ID itself, which it expects at most one row to
     * have: the one returned before. That way two rows sharing the row ID at
     * which one page ends and a new query begins still fail the read, rather
     * than one of them being skipped.
     */
    private final class Cursor {
        private final String table;
        private final List<String> columns;
        private final Connection connection;
        private final PreparedStatement statement;
        private final ResultSet resultSet;
        private final ClickHouseColumns.RowReader reader;
        /** The row ID the query started at, whose one row was returned before */
        private final long startRowId;
        private boolean startRowSeen;
        /** The row ID of the last row returned, or the one the query started after */
        private long lastRowId;
        private boolean exhausted;

        Cursor(String table, List<String> columns, String view, long afterRowId) throws SQLException {
            this.table = table;
            this.columns = new ArrayList<>(columns);
            this.startRowId = afterRowId;
            this.lastRowId = afterRowId;
            Connection openedConnection = streamingConnection();
            PreparedStatement preparedStatement = null;
            try {
                preparedStatement = openedConnection.prepareStatement(
                    select(columns, view) + " WHERE rowid >= ? ORDER BY rowid");
                preparedStatement.setLong(1, afterRowId);
                ResultSet openedResultSet = preparedStatement.executeQuery();
                this.connection = openedConnection;
                this.statement = preparedStatement;
                this.resultSet = openedResultSet;
                this.reader = new ClickHouseColumns.RowReader(table, columns, openedResultSet.getMetaData());
            } catch (SQLException | RuntimeException e) {
                closeQuietly(preparedStatement);
                closeQuietly(openedConnection);
                throw e;
            }
        }

        boolean continues(String table, List<String> columns, long afterRowId) {
            return !exhausted && this.table.equals(table) && this.columns.equals(columns) && lastRowId == afterRowId;
        }

        /**
         * @return the next row, or {@code null} at the end of the table
         */
        Row next() throws SQLException {
            while (!exhausted) {
                if (!resultSet.next()) {
                    exhausted = true;
                    return null;
                }
                Row row = reader.read(resultSet);
                if (row.rowId() == startRowId) {
                    if (startRowSeen) {
                        requireAscending(table, startRowId, row.rowId());
                    }
                    startRowSeen = true;
                    continue;
                }
                requireAscending(table, lastRowId, row.rowId());
                lastRowId = row.rowId();
                return row;
            }
            return null;
        }

        void close() {
            // Canceling asks the server, which may not answer; after an abort the connection is gone anyway
            if (!exhausted && !aborted) {
                // Closing a result that isn't fully read ends the query early
                try {
                    statement.cancel();
                } catch (SQLException | RuntimeException e) {
                    // Closing below ends it anyway
                }
            }
            closeQuietly(resultSet);
            closeQuietly(statement);
            closeQuietly(connection);
        }
    }

    private static void closeQuietly(AutoCloseable closeable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (Exception e) {
            // The driver fails to close a result it stopped reading early, which is intended
        }
    }
}
