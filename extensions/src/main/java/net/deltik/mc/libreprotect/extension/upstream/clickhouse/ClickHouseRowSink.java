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
import net.deltik.mc.libreprotect.extension.migration.RowSink;
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import net.deltik.mc.libreprotect.extension.upstream.Codecs;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Config;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Events;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Family;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Pool;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Target;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.WriteBatch;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamChanged;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLDataException;
import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Writes a migration's rows into a new ClickHouse database through
 * CoreProtect's own ClickHouse writer, so the result is what CoreProtect
 * would have written itself: rows keep their row IDs, block metadata and
 * entity data are in CoreProtect's columnar encoding, and row ID allocation
 * continues after the source's.
 *
 * <p>Differences from the relational engines:
 * <ul>
 *   <li>{@link #prepare} opens the database as CoreProtect's single
 *       ClickHouse writer for this data directory, which the running server
 *       can take over at activation (see {@link ClickHouseEndpoints#handOver}).</li>
 *   <li>ClickHouse keeps one {@code version} row, CoreProtect's current
 *       version, which {@link #finish} writes. The {@code version} rows given
 *       to {@link #write} are skipped, so validation must not expect them.
 *       Both {@code version} and {@code database_lock} have row ID 1 on the
 *       target, which is also their high-water mark there.</li>
 *   <li>The UUIDs of {@code user} and {@code username_log} rows are stored as
 *       CoreProtect stores them: an empty UUID as none.</li>
 *   <li>Entity data is expected in the columnar encoding; data in the legacy
 *       encoding is converted rather than refused.</li>
 *   <li>A value that ClickHouse can't hold as it is, like a missing
 *       {@code time} or a number out of its column's range, fails the write
 *       with an {@link SQLDataException} naming the table, column and row ID.</li>
 * </ul>
 *
 * <p>Each call to {@link #write} is published before it returns, in batches of
 * at most {@value #MAX_BATCH_ROWS} rows. If publishing fails, calling
 * {@link #write} again publishes the same batch again, which ClickHouse
 * deduplicates, so a retry can't store rows twice. A retry must pass the
 * same rows: the sink republishes the batch it encoded the first time.
 *
 * <p>CoreProtect's writer retries a refused publication for as long as the
 * server runs. The sink lets each publication retry for {@link #PUBLISH_LIMIT},
 * and stops it at once when the server starts shutting down (see
 * {@link PublishDeadline}). Either fails it with an
 * {@link java.sql.SQLNonTransientException}, which isn't worth retrying.
 * {@link #abort()} stops it, and the rest of the sink's work, from any thread.
 */
final class ClickHouseRowSink implements RowSink {

    /** Rows per published batch, as CoreProtect's consumer publishes; ClickHouse's limit is 1,000,000 */
    static final int MAX_BATCH_ROWS = 100_000;

    /**
     * How long one publication may keep retrying: as long as CoreProtect lets
     * a single ClickHouse request take (its socket timeout), and about 80
     * times what a batch of {@value #MAX_BATCH_ROWS} block rows over 23
     * monthly partitions took to publish on a local server (3 to 4 seconds),
     * so a slow but healthy server isn't cut off. It caps retrying, not
     * progress: a publication that keeps succeeding can run past it, at worst
     * by the insert in flight plus one insert for each partition still to
     * publish, each within that 5-minute socket timeout.
     */
    static final Duration PUBLISH_LIMIT = Duration.ofMinutes(5);

    private final ClickHouseApi api;
    private final Config config;
    private final String databaseName;
    private final String prefix;
    private final Path controlDirectory;
    private final String coreVersion;
    private final IdentifierAssignments identifiers;
    private final PublishDeadline deadline;
    private final Pool jdbc;
    private final List<ClickHouseRowSource> readers = new CopyOnWriteArrayList<>();
    /** Guards the prepared database between {@link #abort()} and the threads preparing and handing it over */
    private final Object targetLock = new Object();
    private volatile Target target;
    private volatile boolean handedOver;
    private volatile boolean aborted;
    private Pending pending;
    private boolean closed;

    /**
     * @param api              CoreProtect's ClickHouse classes, for writing
     * @param controlDirectory where CoreProtect registers the ClickHouse
     *                         writer of this installation: its data folder
     * @param coreVersion      CoreProtect's internal database version, e.g. {@code 2.24.1}
     * @param deadline         what stops publications that keep retrying,
     *                         which the sink closes with itself
     */
    ClickHouseRowSink(ClickHouseApi api, Config config, String prefix, Path controlDirectory, String coreVersion,
                      IdentifierAssignments identifiers, PublishDeadline deadline) throws SQLException {
        if (!prefix.isEmpty()) {
            ClickHouseColumns.quote(prefix);
        }
        if (!api.canWrite()) {
            throw new IllegalArgumentException("ClickHouse sinks need " + ClickHouseApi.WRITES.id());
        }
        this.api = api;
        this.config = Objects.requireNonNull(config, "config");
        this.databaseName = config.database();
        this.prefix = prefix;
        this.controlDirectory = Objects.requireNonNull(controlDirectory, "controlDirectory");
        this.coreVersion = Objects.requireNonNull(coreVersion, "coreVersion");
        this.identifiers = Objects.requireNonNull(identifiers, "identifiers");
        this.deadline = Objects.requireNonNull(deadline, "deadline");
        this.jdbc = api.pool(config);
    }

    @Override
    public Engine engine() {
        return Engine.CLICKHOUSE;
    }

    /**
     * The namespace holds CoreProtect data if its event table has any rows
     * besides batch receipts, even just the version and lock rows of a server
     * that never logged anything, or if it has identifier claims from an
     * earlier installation, which CoreProtect would reuse for other values.
     * Where CoreProtect has a lookup index, the rows of the index count as
     * data of the tables that they index, since CoreProtect's lookups by
     * player find them even without the rows they index, and so does an
     * index that a purge or schema upgrade that didn't complete left closed,
     * which keeps CoreProtect's lookups from reading the index.
     * Allocator state alone (reserved ID blocks, recorded high-water marks)
     * only makes new IDs start higher, which is harmless.
     */
    @Override
    public Optional<String> nonEmptyReason() throws SQLException {
        String where = "ClickHouse database '" + databaseName + "' already has CoreProtect data with table prefix '"
            + prefix + "' (";
        String advice = "). Use a table prefix without CoreProtect data, or drop CoreProtect's tables and views"
            + " with this prefix first.";
        try (Connection connection = connection()) {
            if (exists(connection, "event_data")) {
                String events = physical("event_data");
                // A table from before CoreProtect's lookup index has none of its columns, nor index rows
                boolean current = columns(connection, "event_data").containsAll(api.eventColumns());
                Optional<String> dataFamily = current ? api.lookupIndexedFamily() : Optional.empty();
                List<String> counts = new ArrayList<>();
                try (PreparedStatement statement = connection.prepareStatement("SELECT family, "
                    + dataFamily.orElse("family") + " AS data_family, count() FROM " + events
                    + " WHERE data_family != ? GROUP BY family, data_family"
                    + " ORDER BY data_family, family != data_family")) {
                    statement.setString(1, api.batchReceiptFamily());
                    try (ResultSet resultSet = statement.executeQuery()) {
                        while (resultSet.next()) {
                            String family = resultSet.getString(1);
                            String data = resultSet.getString(2);
                            long count = resultSet.getLong(3);
                            String table = family.equals(data) ? family
                                : data.isEmpty() ? "lookup index" : data + " lookup index";
                            counts.add(table + ": " + String.format(Locale.ROOT, "%,d", count)
                                + (count == 1 ? " row" : " rows"));
                        }
                    }
                }
                Optional<String> open = current ? api.lookupIndexOpen(events) : Optional.empty();
                if (open.isPresent()) {
                    try (Statement statement = connection.createStatement();
                         ResultSet resultSet = statement.executeQuery("SELECT " + open.get())) {
                        resultSet.next();
                        if (resultSet.getLong(1) != 1) {
                            counts.add("a lookup index that a purge or schema upgrade that didn't complete left"
                                + " closed");
                        }
                    }
                }
                if (!counts.isEmpty()) {
                    return Optional.of(where + String.join(", ", counts) + advice);
                }
            }
            if (exists(connection, "identity_reservation")) {
                try (PreparedStatement statement = connection.prepareStatement("SELECT count() FROM "
                    + physical("identity_reservation") + " WHERE startsWith(sequence, 'canonical:')");
                     ResultSet resultSet = statement.executeQuery()) {
                    resultSet.next();
                    long claims = resultSet.getLong(1);
                    if (claims > 0) {
                        return Optional.of(where + String.format(Locale.ROOT, "%,d", claims)
                            + (claims == 1 ? " identifier claim" : " identifier claims")
                            + " from an earlier installation" + advice);
                    }
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Create CoreProtect's ClickHouse schema and open the database as this
     * installation's ClickHouse writer, as CoreProtect opens its own, which
     * checks the server's version and database engine first. Row ID
     * allocation continues after the rows written and the high-water marks
     * that {@link #finish} records.
     *
     * <p>CoreProtect writes a new identifier's map row with the identifier as
     * its row ID, so this also makes CoreProtect assign identifiers above
     * the source's high-water mark of each map table from now on: then an
     * identifier assigned while the copy runs can't equal a copied row ID.
     * On the source, that only skips identifiers.
     *
     * @param highWater the source's high-water marks, or largest row IDs, of
     *                  at least the map tables
     */
    @Override
    public void prepare(Map<String, Long> highWater) throws SQLException {
        requireOpen();
        requireNotAborted();
        if (target != null) {
            throw new IllegalStateException("The ClickHouse target is already prepared");
        }
        Target initialized;
        try {
            initialized = api.initialize(config, prefix, controlDirectory);
        } catch (IllegalArgumentException e) {
            throw new SQLException("Can't open ClickHouse: " + e.getMessage(), e);
        }
        synchronized (targetLock) {
            if (aborted) {
                closeQuietly(initialized);
                requireNotAborted();
            }
            target = initialized;
        }
        for (String map : ClickHouseColumns.IDENTIFIER_MAPS) {
            Long mark = highWater.get(map);
            if (mark != null && mark > 0) {
                identifiers.raise(ClickHouseColumns.family(api, map), mark);
            }
        }
    }

    @Override
    public List<String> columns(String table) throws SQLException {
        try (Connection connection = connection()) {
            return ClickHouseRowSource.columns(api, connection, databaseName, prefix, table);
        }
    }

    @Override
    public void markIncomplete() throws SQLException {
        writeDatabaseLock(api.incompleteStatus());
    }

    /**
     * @param columns the columns of the values, which ClickHouse must have;
     *                row IDs aren't among them
     */
    @Override
    public void write(String table, List<String> columns, List<Row> rows) throws SQLException {
        requireNotAborted();
        Target prepared = requirePrepared();
        Family family = ClickHouseColumns.family(api, table);
        if (family.tableName().equals("version")) {
            // ClickHouse keeps only CoreProtect's current version, which finish() writes
            return;
        }
        if (family.tableName().equals("database_lock")) {
            throw new IllegalArgumentException("database_lock isn't copied; CoreProtect keeps its own lock row");
        }
        if (rows.isEmpty()) {
            return;
        }
        Fingerprint fingerprint = new Fingerprint(table, columns, rows);
        int start = 0;
        if (pending != null) {
            if (!pending.fingerprint.equals(fingerprint)) {
                throw new IllegalStateException("The " + pending.fingerprint + " failed to be written to ClickHouse"
                    + " and must be written again before other rows");
            }
            publishPending(prepared);
            start = pending.end;
            pending = null;
        }
        while (start < rows.size()) {
            int end = Math.min(rows.size(), start + MAX_BATCH_ROWS);
            pending = new Pending(fingerprint, encode(family, table, columns, rows.subList(start, end)), end);
            publishPending(prepared);
            pending = null;
            start = end;
        }
    }

    /**
     * Record the source's allocator high-water marks, so that CoreProtect
     * continues after them, keep the identifiers CoreProtect assigns from now
     * on clear of the copied map rows, and write CoreProtect's current
     * version row.
     */
    @Override
    public void finish(Map<String, Long> highWater) throws SQLException {
        requireNotAborted();
        Target prepared = requirePrepared();
        if (pending != null) {
            throw new IllegalStateException("The " + pending.fingerprint + " failed to be written to ClickHouse");
        }
        Map<Family, Long> marks = new LinkedHashMap<>();
        for (Map.Entry<String, Long> entry : highWater.entrySet()) {
            Family family = ClickHouseColumns.family(api, entry.getKey());
            Long mark = entry.getValue();
            // ClickHouse fixes both singleton rows at row ID 1
            if (!family.tableName().equals("version") && !family.tableName().equals("database_lock")
                && mark != null && mark > 0) {
                marks.put(family, mark);
            }
        }
        try {
            deadline.run("the row ID high-water marks", () -> prepared.preserveCompatibilityHighWaterMarks(marks));
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new SQLDataException("Can't record the row ID high-water marks in ClickHouse: " + e.getMessage(), e);
        }
        guardIdentifierMaps();
        deadline.run("CoreProtect's version row", () -> prepared.ensureCoreData(coreVersion));
    }

    /**
     * @return a reader of this ClickHouse database over its own connections,
     *         closed with the sink if not before
     */
    @Override
    public RowSource readBack() throws SQLException {
        requireOpen();
        requireNotAborted();
        ClickHouseRowSource reader = new ClickHouseRowSource(api, config, prefix);
        readers.add(reader);
        if (aborted) {
            reader.abort();
        }
        return reader;
    }

    @Override
    public void markComplete() throws SQLException {
        writeDatabaseLock(api.inactiveStatus());
    }

    /**
     * Give up ownership of the prepared database, so that closing or
     * aborting the sink leaves it open for CoreProtect to take over.
     *
     * @throws IllegalStateException if the sink isn't prepared, is closed or was aborted
     */
    Target handOver() {
        synchronized (targetLock) {
            if (aborted) {
                throw new IllegalStateException("The ClickHouse target was aborted because the migration is stopping");
            }
            Target prepared = requirePrepared();
            handedOver = true;
            return prepared;
        }
    }

    /**
     * Abort the readers from {@link #readBack()} and close the sink's own
     * connections, and, unless the prepared database was handed over, stop
     * the publication running now and close that database too. That ends
     * any query or insert of the sink waiting on the server, and every call
     * from now on fails. Never throws.
     *
     * <p>A database handed over to CoreProtect is CoreProtect's: aborting
     * leaves it, its connections and its writer registration alone, and the
     * incomplete-migration mark can still be set and cleared through it, as
     * activation does.
     */
    @Override
    public void abort() {
        aborted = true;
        for (ClickHouseRowSource reader : readers) {
            reader.abort();
        }
        synchronized (targetLock) {
            if (!handedOver) {
                deadline.abort();
                Target prepared = target;
                if (prepared != null) {
                    // Also releases this installation's ClickHouse writer registration
                    closeQuietly(prepared);
                }
            }
        }
        try {
            jdbc.close();
        } catch (RuntimeException e) {
            // Best effort; the pool refuses new connections regardless
        }
    }

    private static void closeQuietly(Target database) {
        try {
            database.close();
        } catch (SQLException | RuntimeException e) {
            // Closing is best effort here; the writer registration goes with the process at worst
        }
    }

    /**
     * Close the sink's connections and readers, and the prepared database
     * unless {@link #handOver()} gave it away. Closing it releases this
     * installation's ClickHouse writer registration.
     */
    @Override
    public void close() throws SQLException {
        if (closed) {
            return;
        }
        closed = true;
        List<Exception> failures = new ArrayList<>();
        if (pending != null) {
            pending.batch.close();
            pending = null;
        }
        for (ClickHouseRowSource reader : readers) {
            try {
                reader.close();
            } catch (SQLException | RuntimeException e) {
                failures.add(e);
            }
        }
        if (target != null && !handedOver) {
            try {
                target.close();
            } catch (SQLException | RuntimeException e) {
                failures.add(e);
            }
        }
        try {
            jdbc.close();
        } catch (RuntimeException e) {
            failures.add(e);
        }
        deadline.close();
        if (!failures.isEmpty()) {
            SQLException failure = new SQLException("Failed to close the ClickHouse target", failures.get(0));
            for (Exception other : failures.subList(1, failures.size())) {
                failure.addSuppressed(other);
            }
            throw failure;
        }
    }

    /**
     * @return a batch of the rows in CoreProtect's ClickHouse layout, not yet published
     */
    WriteBatch encode(Family family, String table, List<String> columns, List<Row> rows) throws SQLException {
        WriteBatch batch = requirePrepared().newWriteBatch();
        try {
            Events events = batch.events();
            for (Row row : rows) {
                Object[] values = row.values();
                if (values.length != columns.size()) {
                    throw new IllegalArgumentException("The " + table + " row " + row.rowId() + " has "
                        + values.length + " values for " + columns.size() + " columns");
                }
                Map<String, Object> named = new LinkedHashMap<>();
                for (int index = 0; index < values.length; index++) {
                    String column = columns.get(index);
                    named.put(column, toClickHouse(family, table, column, values[index], row.rowId()));
                }
                try {
                    events.addCompatibilityRow(family, row.rowId(), named);
                } catch (SQLException | RuntimeException e) {
                    throw refusedRow(table, row.rowId(), e);
                }
            }
            return batch;
        } catch (SQLException | RuntimeException e) {
            batch.close();
            throw e;
        }
    }

    /**
     * @return the failure of a row that CoreProtect's writer refused, naming
     *         the row
     * @throws UpstreamChanged as it is, when CoreProtect itself changed,
     *                         which is no fault of the row's, and names
     *                         what changed
     */
    static SQLDataException refusedRow(String table, long rowId, Exception e) {
        if (e instanceof UpstreamChanged) {
            throw (UpstreamChanged) e;
        }
        return new SQLDataException("Can't write " + table + " row " + rowId + " to ClickHouse: " + describe(e), e);
    }

    /**
     * Convert a value to what CoreProtect's ClickHouse writer stores, and
     * refuse one that ClickHouse can't hold. Block metadata needs nothing:
     * the writer converts it itself.
     */
    static Object toClickHouse(Family family, String table, String column, Object value, long rowId)
        throws SQLException {
        Object converted = value;
        String familyTable = family.tableName();
        Codecs codecs = family.api().codecs();
        if (column.equals("data") && value instanceof byte[]
            && (familyTable.equals("entity") || familyTable.equals("entity_spawn"))
            && !codecs.isEncoded((byte[]) value)) {
            try {
                // From the legacy encoding of SQLite and MySQL to the columnar one
                converted = codecs.transcode(familyTable, column, value, Engine.SQLITE, Engine.CLICKHOUSE);
            } catch (SQLException e) {
                // What CoreProtect's conversion threw, for the row's own message
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                if (cause instanceof UpstreamChanged) {
                    throw (UpstreamChanged) cause;
                }
                throw new SQLDataException("Can't convert the entity data of " + table + " row " + rowId
                    + " for ClickHouse: " + describe(cause), e);
            }
        } else if (column.equals("uuid") && "".equals(value)
            && (familyTable.equals("user") || familyTable.equals("username_log"))) {
            converted = null;
        }
        ClickHouseColumns.requireFits(family, table, column, converted, rowId);
        return converted;
    }

    private void publishPending(Target prepared) throws SQLException {
        WriteBatch batch = pending.batch;
        try {
            deadline.run("the " + pending.fingerprint, () -> prepared.publish(batch));
        } catch (PublishDeadline.ExpiredException e) {
            throw e;
        } catch (SQLException e) {
            throw new SQLException("Failed to write the " + pending.fingerprint + " to ClickHouse: " + describe(e),
                e.getSQLState(), e.getErrorCode(), e);
        }
        batch.close();
    }

    private void writeDatabaseLock(int status) throws SQLException {
        if (!handedOver) {
            // Once CoreProtect has the database, activation still sets and clears the mark through it
            requireNotAborted();
        }
        Target prepared = requirePrepared();
        String what = status == api.incompleteStatus()
            ? "the incomplete-migration mark" : "the cleared incomplete-migration mark";
        deadline.run(what, () -> {
            try (WriteBatch batch = prepared.newWriteBatch()) {
                batch.events().addDatabaseLockVersion(1L, (int) (System.currentTimeMillis() / 1000L), status);
                prepared.publish(batch);
            }
        });
    }

    /**
     * CoreProtect writes a new identifier's map row with the identifier as its
     * row ID, and ClickHouse would merge it into a copied row with that row
     * ID. A copied row ID above every copied identifier is free for
     * CoreProtect to assign, so raise CoreProtect's counters above the copied
     * row IDs, and refuse if it has already assigned one of them while the
     * migration ran. Its row would only be written after activation.
     */
    void guardIdentifierMaps() throws SQLException {
        List<String> conflicts = new ArrayList<>();
        try (Connection connection = connection()) {
            for (String map : ClickHouseColumns.IDENTIFIER_MAPS) {
                String view = api.qualified(databaseName, prefix + map);
                long maximum;
                List<Long> freeRowIds = new ArrayList<>();
                try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT max(rowid) FROM " + view);
                     ResultSet resultSet = statement.executeQuery()) {
                    resultSet.next();
                    maximum = resultSet.getLong(1);
                }
                try (PreparedStatement statement = connection.prepareStatement("SELECT rowid FROM " + view
                    + " WHERE rowid > (SELECT ifNull(max(id), 0) FROM " + view + ") ORDER BY rowid");
                     ResultSet resultSet = statement.executeQuery()) {
                    while (resultSet.next()) {
                        freeRowIds.add(resultSet.getLong(1));
                    }
                }
                for (Long identifier : identifiers.raiseAndFindAssigned(ClickHouseColumns.family(api, map), maximum,
                    freeRowIds)) {
                    conflicts.add(map + " " + identifier);
                }
            }
        }
        if (!conflicts.isEmpty()) {
            throw new SQLException("CoreProtect assigned new identifiers during the migration (" + String.join(", ",
                conflicts) + ") that equal the row IDs of copied rows with other identifiers, which ClickHouse would"
                + " overwrite. Clear the ClickHouse target and migrate again.");
        }
    }

    private boolean exists(Connection connection, String table) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
            "SELECT 1 FROM system.tables WHERE database = ? AND name = ?")) {
            statement.setString(1, databaseName);
            statement.setString(2, prefix + table);
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next();
            }
        }
    }

    /**
     * @return the columns of one of CoreProtect's tables as ClickHouse has it
     */
    private Set<String> columns(Connection connection, String table) throws SQLException {
        Set<String> columns = new HashSet<>();
        try (PreparedStatement statement = connection.prepareStatement(
            "SELECT name FROM system.columns WHERE database = ? AND table = ?")) {
            statement.setString(1, databaseName);
            statement.setString(2, prefix + table);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    columns.add(resultSet.getString(1));
                }
            }
        }
        return columns;
    }

    private String physical(String table) {
        return api.qualified(databaseName, prefix + table);
    }

    private Target requirePrepared() {
        requireOpen();
        Target prepared = target;
        if (prepared == null) {
            throw new IllegalStateException("The ClickHouse target isn't prepared");
        }
        return prepared;
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("The ClickHouse target is closed");
        }
    }

    private Connection connection() throws SQLException {
        requireNotAborted();
        return jdbc.openConnection();
    }

    private void requireNotAborted() throws SQLNonTransientConnectionException {
        if (aborted) {
            throw new SQLNonTransientConnectionException("Writing ClickHouse stopped because the migration is"
                + " stopping");
        }
    }

    /**
     * @return the messages of an exception and its first causes, since
     *         CoreProtect's ClickHouse errors wrap the one that explains them
     */
    static String describe(Throwable e) {
        List<String> messages = new ArrayList<>();
        for (Throwable cause = e; cause != null && messages.size() < 3; cause = cause.getCause()) {
            String message = cause.getMessage();
            if (message != null && !message.isEmpty() && messages.stream().noneMatch(m -> m.contains(message))) {
                messages.add(message);
            }
            if (cause.getCause() == cause) {
                break;
            }
        }
        return messages.isEmpty() ? e.getClass().getSimpleName() : String.join(": ", messages);
    }

    /**
     * Which rows a call to {@link #write} was given, to recognize a retry.
     */
    private static final class Fingerprint {
        private final String table;
        private final List<String> columns;
        private final int count;
        private final long firstRowId;
        private final long lastRowId;

        Fingerprint(String table, List<String> columns, List<Row> rows) {
            this.table = table;
            this.columns = new ArrayList<>(columns);
            this.count = rows.size();
            this.firstRowId = rows.get(0).rowId();
            this.lastRowId = rows.get(rows.size() - 1).rowId();
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof Fingerprint)) {
                return false;
            }
            Fingerprint that = (Fingerprint) other;
            return table.equals(that.table) && columns.equals(that.columns) && count == that.count
                && firstRowId == that.firstRowId && lastRowId == that.lastRowId;
        }

        @Override
        public int hashCode() {
            return Objects.hash(table, columns, count, firstRowId, lastRowId);
        }

        @Override
        public String toString() {
            return String.format(Locale.ROOT, "%,d %s rows with row IDs %d to %d", count, table, firstRowId, lastRowId);
        }
    }

    /**
     * A batch that was encoded but not yet published completely.
     */
    private static final class Pending {
        private final Fingerprint fingerprint;
        private final WriteBatch batch;
        /** The index after the batch's last row among the rows of the call */
        private final int end;

        Pending(Fingerprint fingerprint, WriteBatch batch, int end) {
            this.fingerprint = fingerprint;
            this.batch = batch;
            this.end = end;
        }
    }
}
