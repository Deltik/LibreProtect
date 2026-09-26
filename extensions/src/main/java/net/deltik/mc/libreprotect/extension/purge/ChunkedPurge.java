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

package net.deltik.mc.libreprotect.extension.purge;

import net.deltik.mc.libreprotect.extension.common.Engine;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * One purge run: deletes every row whose {@code time} is before the cutoff
 * from CoreProtect's purgeable tables, in small chunks with pauses between
 * them, so the server stays usable. Rows at or after the cutoff are never
 * deleted: every delete is limited to {@code time >= 0 AND time < cutoff},
 * the range a manual purge uses.
 *
 * <p>Each table is walked in rowid ranges. Rowids follow insertion order on
 * SQLite, MySQL and DuckDB, which CoreProtect relies on too, so a table is
 * finished once a range's oldest row is a day past the cutoff. A range whose
 * oldest row lies more than a day in the future ends nothing: a clock that
 * once ran ahead wrote it, and older rows can follow it. Rowids copied from
 * ClickHouse by a migration interleave several writers' blocks, so there a
 * table can end early and leave a few old rows for later runs.
 *
 * <p>Each range is one statement under its own {@link Lease}, sized to hold
 * the database for less than 100 ms, followed by a pause four times as long
 * and at least {@value #MINIMUM_PAUSE_MILLIS} ms. On CoreProtect 25 the lease
 * makes rollbacks, reloads and manual purges wait, so they find the database
 * free about four fifths of the time.
 *
 * <p>SQLite reuses the rowid of a table's last row once it is deleted, and
 * MySQL before 8.0 does after a restart. CoreProtect keeps rowids of some
 * tables in other rows, so on these engines a purge keeps the newest row of
 * those tables, however old, and its rowid is never handed out again:
 * <ul>
 *   <li>{@code entity} and {@code skull}: a block row's {@code data} holds
 *       the killed entity's or the broken skull's rowid, and CoreProtect 25's
 *       {@code entity_spawn.kill_rowid} the killed entity's;</li>
 *   <li>{@code block}: CoreProtect 25's {@code entity_spawn.block_rowid};</li>
 *   <li>{@code entity_spawn}: CoreProtect 25's {@code entity_interaction}
 *       and {@code entity_container} rows.</li>
 * </ul>
 * Other tables are purged completely, so a player's last chat message doesn't
 * outlive the retention.
 *
 * <p>With CoreProtect 25's entity tracking, links to removed rows are cleared
 * afterward, and orphaned {@code entity_spawn}, {@code entity_interaction}
 * and {@code entity_container} rows older than the cutoff are removed, as a
 * manual purge does. Then DuckDB is checkpointed. ClickHouse has CoreProtect's
 * own retention, which runs as one exclusive step.
 *
 * <p>A run checks every reason to stop before anything that depends on the
 * engine, so that a database that can't be purged, such as one of an engine
 * LibreProtect doesn't know, is never touched.
 */
final class ChunkedPurge {

    /** How far rowid order may lag time order: a range this far past the cutoff ends the table */
    static final long ORDER_SLACK_SECONDS = 24L * 60 * 60;
    /** The shortest pause after each chunk */
    static final long MINIMUM_PAUSE_MILLIS = 300;
    /** Each pause is at least this many times as long as the chunk held its lease */
    static final int PAUSE_FACTOR = 4;
    /** The longest pause that {@link #PAUSE_FACTOR} leads to */
    static final long MAXIMUM_PAUSE_MILLIS = 10_000;
    /** Attempts at a chunk before its errors stop the run */
    static final int MAXIMUM_ATTEMPTS = 4;
    /** How long other database work may keep the purge waiting before it gives up */
    static final long BUSY_LIMIT_NANOS = 10L * 60 * 1_000_000_000L;
    static final long PROGRESS_INTERVAL_NANOS = 5L * 60 * 1_000_000_000L;
    /**
     * The shortest time between two rechecks of CoreProtect's tracked
     * entities while {@code entity_spawn} rows are being removed. Each
     * recheck queues one update for every loaded tracked entity.
     */
    static final long INVALIDATION_INTERVAL_NANOS = 30L * 1_000_000_000L;
    /**
     * How long a MySQL statement may wait on the network. A cancel can't
     * reach a server that stopped answering, and CoreProtect 25's shutdown
     * waits for the claim the statement holds.
     */
    static final int NETWORK_TIMEOUT_MILLIS = 60_000;
    /** Tables whose rowids other rows keep; see the class comment */
    static final Set<String> REFERENCED_TABLES = Collections.unmodifiableSet(
        new HashSet<>(Arrays.asList("block", "entity", "skull", "entity_spawn")));
    private static final long MAXIMUM_SPAN = 100_000_000L;
    private static final long MAXIMUM_BUSY_PAUSE_MILLIS = 5_000;

    private final PurgeBridge bridge;
    private final PurgeContext context;
    private final PurgeLog log;
    private final Supplier<StopReason> runChecks;
    private final long cutoff;
    private final long now;
    private final Engine engine;
    private final String prefix;
    private final Object identity;
    private final ChunkSizer sizer = new ChunkSizer();

    private long minimumPauseMillis = MINIMUM_PAUSE_MILLIS;
    private long retryDelayMillis = 1000;
    private long busyLimitNanos = BUSY_LIMIT_NANOS;
    private long removed;
    private long orphansChanged;
    private long lastHeldNanos;
    private long nextProgress;
    private long invalidationIntervalNanos = INVALIDATION_INTERVAL_NANOS;
    /** What {@link #INVALIDATION_INTERVAL_NANOS} is measured with */
    private LongSupplier invalidationClock = System::nanoTime;
    private long lastInvalidation;
    private boolean invalidated;
    private boolean invalidationPending;

    /**
     * @param runChecks reasons to stop that the bridge doesn't know about, such as a settings change
     * @param cutoff rows with a {@code time} before this, in Unix seconds, are removed
     * @param now the server's time as the run starts, in Unix seconds
     */
    ChunkedPurge(PurgeBridge bridge, PurgeContext context, PurgeLog log, Supplier<StopReason> runChecks, long cutoff,
                 long now) {
        this.bridge = Objects.requireNonNull(bridge, "bridge");
        this.context = Objects.requireNonNull(context, "context");
        this.log = Objects.requireNonNull(log, "log");
        this.runChecks = Objects.requireNonNull(runChecks, "runChecks");
        this.cutoff = cutoff;
        this.now = now;
        this.engine = bridge.activeEngine();
        this.prefix = bridge.tablePrefix();
        this.identity = bridge.databaseIdentity();
    }

    /**
     * Shorten the waits, for tests: the shortest pause after each chunk, the
     * first delay before retrying a failed chunk (doubled each time), and how
     * long the database may stay busy.
     */
    ChunkedPurge timing(long minimumPauseMillis, long retryDelayMillis, long busyLimitMillis) {
        this.minimumPauseMillis = minimumPauseMillis;
        this.retryDelayMillis = retryDelayMillis;
        this.busyLimitNanos = busyLimitMillis * 1_000_000L;
        return this;
    }

    /**
     * Change {@link #INVALIDATION_INTERVAL_NANOS}, for tests.
     */
    ChunkedPurge invalidationInterval(long millis) {
        this.invalidationIntervalNanos = millis * 1_000_000L;
        return this;
    }

    /**
     * Measure {@link #INVALIDATION_INTERVAL_NANOS} with another clock, for
     * tests whose chunks may take long on a busy machine.
     *
     * @param nanoTime a clock as {@link System#nanoTime()}
     */
    ChunkedPurge invalidationClock(LongSupplier nanoTime) {
        this.invalidationClock = Objects.requireNonNull(nanoTime, "nanoTime");
        return this;
    }

    /**
     * Purge until done or told to stop. Never throws.
     *
     * @param orphansPending whether an earlier run stopped before its orphan cleanup
     */
    PurgeResult run(boolean orphansPending) {
        long started = System.nanoTime();
        nextProgress = started + PROGRESS_INTERVAL_NANOS;
        StopReason reason = null;
        String detail = null;
        boolean orphansCleaned = false;
        try {
            // Before anything that depends on the engine, which may be one that can't be purged
            checkStop();
            if (engine == null) {
                throw stopped(StopReason.UNSUPPORTED_DATABASE, null);
            }
            if (cutoff > 0) {
                if (engine == Engine.CLICKHOUSE) {
                    purgeClickHouse();
                } else {
                    for (String table : bridge.purgeableTables()) {
                        walk(table, Kind.EXPIRED_ROWS, false, "DELETE FROM " + prefix + table
                            + " WHERE rowid > ? AND rowid <= ? AND time >= 0 AND time < ?");
                    }
                }
            }
            Boolean tracking = bridge.entitySpawnTracking();
            if (Boolean.TRUE.equals(tracking) && engine != Engine.CLICKHOUSE && (removed > 0 || orphansPending)) {
                cleanOrphans();
            }
            // Without knowing whether there are orphans, a later run looks again
            orphansCleaned = tracking != null || engine == Engine.CLICKHOUSE;
            if (engine == Engine.DUCKDB && (removed > 0 || orphansChanged > 0)) {
                checkpoint();
            }
        } catch (Stopped stopped) {
            reason = stopped.reason;
            detail = stopped.detail;
        } catch (InterruptedException e) {
            reason = context.stopRequested() ? StopReason.SHUTDOWN : StopReason.ERROR;
            detail = context.stopRequested() ? null : "interrupted";
        } catch (RuntimeException e) {
            reason = StopReason.ERROR;
            detail = e.toString();
        }
        // ClickHouse's purge told CoreProtect already, under its claim
        if ((removed > 0 || orphansChanged > 0) && reason != StopReason.SHUTDOWN && engine != Engine.CLICKHOUSE) {
            invalidate();
        }
        return new PurgeResult(removed, reason, detail, (System.nanoTime() - started) / 1_000_000L, orphansCleaned);
    }

    /**
     * Have CoreProtect recheck the entities it tracks against what is left.
     * It queues one update for every loaded tracked entity, so it isn't
     * called for every chunk.
     */
    private void invalidate() {
        try {
            bridge.purged();
        } catch (RuntimeException e) {
            log.warning("Auto-purge couldn't tell CoreProtect what it removed: " + e);
        }
        lastInvalidation = invalidationClock.getAsLong();
        invalidated = true;
        invalidationPending = false;
    }

    /**
     * CoreProtect's five orphan cleanup statements from {@code /co purge}, in
     * its order: forget links to removed kills and blocks, remove
     * interactions and container changes of entities that are gone, then
     * remove despawned entities that nothing refers to.
     *
     * <p>Unlike a manual purge, the three deletes only remove rows older
     * than the cutoff, like everything else here. A younger orphan stays
     * until a later run finds it old enough.
     */
    private void cleanOrphans() throws Stopped, InterruptedException {
        String spawn = prefix + "entity_spawn";
        String entity = prefix + "entity";
        String block = prefix + "block";
        String interaction = prefix + "entity_interaction";
        String container = prefix + "entity_container";
        String expired = " AND time >= 0 AND time < ?";
        walk("entity_spawn", Kind.LINKS, true, "UPDATE " + spawn + " SET kill_rowid=NULL WHERE rowid > ? AND rowid <= ?"
            + " AND kill_rowid IS NOT NULL AND NOT EXISTS (SELECT 1 FROM " + entity + " WHERE " + entity + ".rowid="
            + spawn + ".kill_rowid)");
        walk("entity_spawn", Kind.LINKS, true, "UPDATE " + spawn + " SET block_rowid=NULL WHERE rowid > ? AND rowid <= ?"
            + " AND block_rowid IS NOT NULL AND NOT EXISTS (SELECT 1 FROM " + block + " WHERE " + block + ".rowid="
            + spawn + ".block_rowid)");
        walk("entity_interaction", Kind.ORPHANED_ROWS, true, "DELETE FROM " + interaction + " WHERE rowid > ? AND rowid <= ?"
            + expired + " AND NOT EXISTS (SELECT 1 FROM " + spawn + " WHERE " + spawn + ".rowid=" + interaction
            + ".entity_spawn_rowid)");
        walk("entity_container", Kind.ORPHANED_ROWS, true, "DELETE FROM " + container + " WHERE rowid > ? AND rowid <= ?"
            + expired + " AND NOT EXISTS (SELECT 1 FROM " + spawn + " WHERE " + spawn + ".rowid=" + container
            + ".entity_spawn_rowid)");
        walk("entity_spawn", Kind.ORPHANED_ROWS, true, "DELETE FROM " + spawn + " WHERE rowid > ? AND rowid <= ?"
            + expired + " AND removed=1 AND block_rowid IS NULL AND kill_rowid IS NULL"
            + " AND NOT EXISTS (SELECT 1 FROM " + container + " WHERE " + container + ".entity_spawn_rowid=" + spawn + ".rowid)"
            + " AND NOT EXISTS (SELECT 1 FROM " + interaction + " WHERE " + interaction + ".entity_spawn_rowid=" + spawn + ".rowid)");
    }

    /**
     * DuckDB reclaims the space of deleted rows at a checkpoint. A failure
     * here doesn't undo the purge, so it only warns.
     */
    private void checkpoint() throws Stopped, InterruptedException {
        try {
            withLease(true, MAXIMUM_ATTEMPTS, connection -> {
                try (Statement statement = connection.createStatement()) {
                    context.track(statement);
                    try {
                        checkNotStopped();
                        statement.execute("CHECKPOINT");
                    } finally {
                        context.untrack();
                    }
                }
                return null;
            });
        } catch (Stopped stopped) {
            if (stopped.reason != StopReason.ERROR) {
                throw stopped;
            }
            log.warning("Auto-purge couldn't checkpoint the DuckDB database, so it may not shrink yet: " + stopped.detail);
        }
    }

    /**
     * One call to CoreProtect's ClickHouse retention. A failed call is never
     * repeated: its mutation may still be running on the server. As after a
     * manual purge, CoreProtect rechecks its tracked entities while the
     * claim still keeps the consumer parked.
     */
    private void purgeClickHouse() throws Stopped, InterruptedException {
        if (!bridge.databaseLock()) {
            throw new Stopped(StopReason.DATABASE_LOCK_DISABLED, null);
        }
        long count = withLease(true, 1, connection -> {
            checkNotStopped();
            long purged = bridge.purgeClickHouse(cutoff);
            if (purged > 0) {
                invalidate();
            }
            return purged;
        });
        removed += count;
        bridge.rowsPurged(count);
    }

    /** What a walk's statement does to the rows it matches */
    private enum Kind {
        /** Deletes rows older than the cutoff, finishing a day past it */
        EXPIRED_ROWS,
        /** Deletes orphaned rows older than the cutoff */
        ORPHANED_ROWS,
        /** Clears links to rows that are gone */
        LINKS
    }

    /**
     * Run {@code sql} over a table's rowids, a range at a time. Its first two
     * parameters are the range's exclusive lower and inclusive upper bound;
     * a delete's third is the cutoff.
     *
     * @param table the unprefixed table
     */
    private void walk(String table, Kind kind, boolean exclusive, String sql) throws Stopped, InterruptedException {
        String name = prefix + table;
        long[] bounds = withLease(exclusive, MAXIMUM_ATTEMPTS, connection -> bounds(connection, name));
        pace();
        if (bounds == null) {
            return;
        }
        boolean keepNewest = kind != Kind.LINKS && keepsNewestRow(table);
        long cursor = bounds[0] - 1;
        long last = keepNewest ? bounds[1] - 1 : bounds[1];
        long span = sizer.rows();
        while (cursor < last) {
            long from = cursor;
            long to = last - from > span ? from + span : last;
            boolean spawns = kind == Kind.ORPHANED_ROWS && table.equals("entity_spawn");
            Step step = withLease(exclusive, MAXIMUM_ATTEMPTS, connection -> {
                Step outcome = step(connection, table, kind, sql, from, to, last);
                if (spawns) {
                    invalidateAfterSpawns(outcome, to, last);
                }
                return outcome;
            });
            pace();
            if (step.finished) {
                return;
            }
            if (step.next != null) {
                cursor = step.next;
                continue;
            }
            if (step.narrowTo > 0) {
                span = step.narrowTo;
                continue;
            }
            if (step.changed > 0) {
                if (kind != Kind.LINKS) {
                    removed += step.changed;
                    bridge.rowsPurged(step.changed);
                }
                if (kind != Kind.EXPIRED_ROWS) {
                    orphansChanged += step.changed;
                }
            }
            sizer.record(lastHeldNanos);
            span = sizer.span(to - from, step.count, MAXIMUM_SPAN);
            cursor = to;
            reportProgress();
        }
    }

    /**
     * @return whether a purge must keep this table's newest row; see the class comment
     */
    private boolean keepsNewestRow(String table) {
        return (engine == Engine.SQLITE || engine == Engine.MYSQL) && REFERENCED_TABLES.contains(table);
    }

    /**
     * One range, under a lease: skip it if empty, narrow it if it holds too
     * many rows, end the table if it is past the cutoff, or run the statement.
     */
    private Step step(Connection connection, String table, Kind kind, String sql, long from, long to, long last)
        throws SQLException, Stopped {
        String name = prefix + table;
        boolean timed = kind == Kind.EXPIRED_ROWS;
        long[] range = query(connection, "SELECT COUNT(*)" + (timed ? ", MIN(time)" : "") + " FROM " + name
            + " WHERE rowid > ? AND rowid <= ?", from, to);
        long count = range[0];
        if (count == 0) {
            long[] next = query(connection, "SELECT MIN(rowid) FROM " + name + " WHERE rowid > ? AND rowid <= ?", to, last);
            return Step.skipTo(next == null ? last : next[0] - 1);
        }
        if (count > 2L * sizer.rows() && to - from > 1) {
            return Step.narrow(sizer.span(to - from, count, MAXIMUM_SPAN));
        }
        if (timed && range.length > 1) {
            long oldest = range[1];
            if (oldest >= cutoff + ORDER_SLACK_SECONDS && oldest <= now + ORDER_SLACK_SECONDS) {
                return Step.FINISHED;
            }
            if (oldest >= cutoff) {
                // Nothing here to delete, such as rows from a clock that ran ahead
                return Step.done(0, count);
            }
        }
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            context.track(statement);
            try {
                statement.setLong(1, from);
                statement.setLong(2, to);
                if (kind != Kind.LINKS) {
                    statement.setLong(3, cutoff);
                }
                checkNotStopped();
                return Step.done(statement.executeUpdate(), count);
            } finally {
                context.untrack();
            }
        }
    }

    /**
     * After a range of the walk that removes despawned entities, have
     * CoreProtect recheck what it caches about them while the lease still
     * holds others off: after the first range that removed some, then at
     * most once per {@link #INVALIDATION_INTERVAL_NANOS}, and after the
     * walk's last range if any were removed since.
     */
    private void invalidateAfterSpawns(Step step, long to, long last) {
        if (step.changed > 0) {
            invalidationPending = true;
        }
        boolean lastRange = step.finished || (step.next != null ? step.next >= last : step.narrowTo == 0 && to >= last);
        if (invalidationPending
            && (lastRange || !invalidated
                || invalidationClock.getAsLong() - lastInvalidation >= invalidationIntervalNanos)) {
            invalidate();
        }
    }

    /**
     * @return the table's smallest and largest rowid, or {@code null} if it is empty
     */
    private long[] bounds(Connection connection, String table) throws SQLException {
        long[] bounds = query(connection, "SELECT MIN(rowid), MAX(rowid) FROM " + table);
        return bounds == null || bounds.length < 2 ? null : bounds;
    }

    /**
     * Run a query for one row of numbers, which a stop can cancel.
     *
     * @return the row's leading non-null numbers, stopping at the first
     *         {@code NULL}, or {@code null} if there is no row or its first
     *         value is {@code NULL}
     */
    private long[] query(Connection connection, String sql, long... parameters) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            context.track(statement);
            try {
                for (int i = 0; i < parameters.length; i++) {
                    statement.setLong(i + 1, parameters[i]);
                }
                try (ResultSet results = statement.executeQuery()) {
                    if (!results.next()) {
                        return null;
                    }
                    int columns = results.getMetaData().getColumnCount();
                    long[] values = new long[columns];
                    for (int i = 0; i < columns; i++) {
                        values[i] = results.getLong(i + 1);
                        if (results.wasNull()) {
                            return i == 0 ? null : Arrays.copyOf(values, i);
                        }
                    }
                    return values;
                }
            } finally {
                context.untrack();
            }
        }
    }

    /** Database work under a lease */
    @FunctionalInterface
    private interface Work<T> {
        T run(Connection connection) throws SQLException, Stopped;
    }

    /**
     * Take a lease, check that the database is still the one the run
     * started on, and do the work. Waits while the database is busy, and
     * retries failed work: every statement is limited to its range and the
     * cutoff, so repeating one is harmless.
     *
     * @param attempts how often to try the work before its errors stop the run
     */
    private <T> T withLease(boolean exclusive, int attempts, Work<T> work) throws Stopped, InterruptedException {
        int failures = 0;
        int busy = 0;
        long busySince = 0;
        while (true) {
            checkStop();
            // The lease may hold its claim from anywhere in here, so its time counts in full
            long taken = System.nanoTime();
            Lease lease = bridge.lease(context, exclusive);
            if (!lease.isGranted()) {
                if (lease.stopReason() != null) {
                    throw stopped(lease.stopReason(), lease.stopDetail());
                }
                long waited = System.nanoTime();
                if (busy == 0) {
                    busySince = waited;
                } else if (waited - busySince > busyLimitNanos) {
                    throw new Stopped(StopReason.DATABASE_BUSY, lease.busyReason());
                }
                context.pause(Math.min(MAXIMUM_BUSY_PAUSE_MILLIS, 250L << Math.min(busy, 5)));
                busy++;
                continue;
            }
            busy = 0;
            try {
                try {
                    checkDatabase();
                    Connection connection = lease.connection();
                    if (engine == Engine.MYSQL) {
                        limitNetworkWait(connection);
                    }
                    return work.run(connection);
                } finally {
                    lease.close();
                    lastHeldNanos = System.nanoTime() - taken;
                }
            } catch (SQLException e) {
                if (context.stopRequested()) {
                    throw new Stopped(StopReason.SHUTDOWN, null);
                }
                if (bridge.requestRecovery(e)) {
                    throw new Stopped(StopReason.DATABASE_RECOVERY, e.getMessage());
                }
                if (++failures >= attempts) {
                    throw new Stopped(StopReason.ERROR, e.getMessage());
                }
                context.pause(retryDelayMillis << failures);
            }
        }
    }

    /**
     * Pause after a lease, so that others find the database free most of the time.
     */
    private void pace() throws InterruptedException {
        long held = lastHeldNanos / 1_000_000L;
        context.pause(Math.max(minimumPauseMillis, Math.min(MAXIMUM_PAUSE_MILLIS, PAUSE_FACTOR * held)));
    }

    /**
     * Fail a statement that waits on the network for longer than
     * {@link #NETWORK_TIMEOUT_MILLIS}. CoreProtect's connection pool
     * restores the connection's own timeout when it gets it back.
     */
    private static void limitNetworkWait(Connection connection) throws SQLException {
        try {
            connection.setNetworkTimeout(Runnable::run, NETWORK_TIMEOUT_MILLIS);
        } catch (SQLFeatureNotSupportedException e) {
            // Only cancellation can end a statement then
        }
    }

    private void checkStop() throws Stopped {
        checkNotStopped();
        StopReason reason = runChecks.get();
        if (reason == null) {
            reason = bridge.stopReason();
        }
        if (reason != null) {
            throw stopped(reason, null);
        }
    }

    /**
     * @param detail more about why, or {@code null}; for a database that
     *               can't be purged, the bridge says why
     */
    private Stopped stopped(StopReason reason, String detail) {
        if (detail == null && reason == StopReason.UNSUPPORTED_DATABASE) {
            try {
                detail = bridge.unavailableReason();
            } catch (RuntimeException e) {
                detail = e.toString();
            }
        }
        return new Stopped(reason, detail);
    }

    private void checkNotStopped() throws Stopped {
        if (context.stopRequested()) {
            throw new Stopped(StopReason.SHUTDOWN, null);
        }
    }

    /**
     * The run's statements name the tables of the database it started on;
     * stop if CoreProtect switched to another one, or replaced the file.
     */
    private void checkDatabase() throws Stopped {
        if (bridge.activeEngine() != engine || !prefix.equals(bridge.tablePrefix())
            || !Objects.equals(identity, bridge.databaseIdentity())) {
            throw new Stopped(StopReason.DATABASE_CHANGED, null);
        }
    }

    private void reportProgress() {
        long current = System.nanoTime();
        if (current - nextProgress >= 0) {
            nextProgress = current + PROGRESS_INTERVAL_NANOS;
            log.info(String.format(Locale.ROOT, "Auto-purge is still running and has removed %,d %s so far.",
                removed, removed == 1 ? "row" : "rows"));
        }
    }

    /** The outcome of one range */
    private static final class Step {
        static final Step FINISHED = new Step(true, null, 0, 0, 0);

        final boolean finished;
        final Long next;
        final long narrowTo;
        final int changed;
        final long count;

        private Step(boolean finished, Long next, long narrowTo, int changed, long count) {
            this.finished = finished;
            this.next = next;
            this.narrowTo = narrowTo;
            this.changed = changed;
            this.count = count;
        }

        /** The range is empty; continue after {@code cursor} */
        static Step skipTo(long cursor) {
            return new Step(false, cursor, 0, 0, 0);
        }

        /** The range holds too many rows; retry with this width */
        static Step narrow(long span) {
            return new Step(false, null, span, 0, 0);
        }

        static Step done(int changed, long count) {
            return new Step(false, null, 0, changed, count);
        }
    }

    /** Ends a run early */
    private static final class Stopped extends Exception {
        private static final long serialVersionUID = 1L;

        final StopReason reason;
        final String detail;

        Stopped(StopReason reason, String detail) {
            super(reason.name(), null, false, false);
            this.reason = reason;
            this.detail = detail;
        }
    }
}
