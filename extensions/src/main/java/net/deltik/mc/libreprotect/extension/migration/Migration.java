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

package net.deltik.mc.libreprotect.extension.migration;

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.extension.common.Console;
import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamChanged;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Random;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * One run of {@code /co migrate-db} on its own thread: check the target,
 * pause CoreProtect's database writes, copy every table to the target,
 * validate the copy, switch CoreProtect to the target, and resume. The source
 * is only read. If anything fails before the switch, CoreProtect keeps using
 * the source.
 *
 * <p>A {@link Watchdog} aborts the database work as soon as the migration has
 * to stop, such as when the server shuts down, since CoreProtect's shutdown
 * waits for the migration while it holds CoreProtect's queue.
 */
final class Migration implements Runnable {

    /** Tables with at most this many rows are always compared in full */
    static final long FULL_COMPARISON_ROWS = 100_000;
    /** How many of the values that couldn't be converted are named */
    private static final int UNCONVERTED_NAMED = 5;

    private final MigrationBridge bridge;
    private final MigrationSession session;
    private final Console console;
    private final Engine targetEngine;
    private final boolean fullValidation;
    private final LongSupplier clock;
    private final Random random;

    private DatabaseSettings sourceSettings;
    private DatabaseSettings targetSettings;
    private boolean targetWritten;
    private boolean activating;
    private long unconvertedCount;
    private final List<String> unconvertedNamed = new ArrayList<>();

    Migration(MigrationBridge bridge, MigrationSession session, Console console, Engine targetEngine,
              boolean fullValidation, LongSupplier clock, Random random) {
        this.bridge = bridge;
        this.session = session;
        this.console = console;
        this.targetEngine = targetEngine;
        this.fullValidation = fullValidation;
        this.clock = clock;
        this.random = random;
    }

    /**
     * Migrate, report the outcome, and release the claim. Never throws.
     */
    @Override
    public void run() {
        try (Watchdog watchdog = new Watchdog(session::stopReason).start()) {
            try {
                migrate(watchdog);
            } catch (MigrationException e) {
                fail(e.getMessage(), e.details());
            } catch (SQLException e) {
                String stop = session.stopReason();
                fail(stop != null ? "The migration stopped because " + stop + "."
                    : "A database error occurred: " + describe(e), new ArrayList<>());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                fail("The migration was interrupted.", new ArrayList<>());
            } catch (UpstreamChanged e) {
                LibreProtectLogger.severe("/co migrate-db found that CoreProtect changed:\n" + stackTrace(e));
                fail("CoreProtect doesn't work the way this LibreProtect build expects: " + e.getMessage(),
                    new ArrayList<>());
            } catch (RuntimeException | Error e) {
                LibreProtectLogger.severe("Unexpected error during /co migrate-db:\n" + stackTrace(e));
                fail("An unexpected error occurred: " + e, new ArrayList<>());
            }
        } finally {
            session.close();
        }
    }

    private void migrate(Watchdog watchdog) throws MigrationException, SQLException, InterruptedException {
        long started = clock.getAsLong();
        sourceSettings = session.sourceSettings();
        targetSettings = session.targetSettings();
        console.say("Migrating CoreProtect's data from the " + sourceSettings.describe() + " to the "
            + targetSettings.describe() + ".");

        StopCheck stop = this::checkStop;
        Retry retry = new Retry(stop, (what, attempt, retries, cause, delay) -> console.detail("Retrying after an"
            + " error " + what + " (" + attempt + " of " + retries + "): " + describe(cause)));
        session.preflight();
        try (RowSink sink = session.openSink(targetSettings)) {
            watchdog.watch(sink::abort);
            // The target is checked while CoreProtect keeps working
            Optional<String> unsupported = sink.unsupportedReason();
            if (unsupported.isPresent()) {
                throw new MigrationException(unsupported.get() + ".");
            }
            Optional<String> occupied = sink.nonEmptyReason();
            if (occupied.isPresent()) {
                throw new MigrationException("The target already holds CoreProtect data: " + occupied.get() + ".",
                    null, targetAdvice());
            }
            stop.check();
            console.detail("New events wait in memory until the migration finishes. Don't stop the server until it"
                + " reports the result.");
            for (String note : session.pause()) {
                console.detail(note);
            }
            stop.check();
            // Again, now that CoreProtect is held: it may have written to the target meanwhile
            occupied = sink.nonEmptyReason();
            if (occupied.isPresent()) {
                throw new MigrationException("The target already holds CoreProtect data: " + occupied.get() + ".",
                    null, targetAdvice());
            }

            List<TableCopy> tables;
            Set<String> ignored = new HashSet<>();
            ignored.add(Tables.DATABASE_LOCK);
            if (targetEngine == Engine.CLICKHOUSE) {
                // A ClickHouse database keeps only its own version row
                ignored.add(Tables.VERSION);
            }
            try (RowSource source = session.openSource()) {
                watchdog.watch(source::abort);
                // Every table's statistics before anything is written, so a source that can't be copied fails early
                List<String> present = retry.call("listing tables", source::tables);
                checkCoreTables(present);
                Map<String, TableStats> stats = new HashMap<>();
                Map<String, Long> highWater = new HashMap<>();
                List<String> names = new ArrayList<>();
                long rows = 0;
                for (String table : Tables.copyOrder(present)) {
                    if (table.equals(Tables.DATABASE_LOCK)) {
                        continue;
                    }
                    TableStats tableStats = retry.scan("counting " + table, () -> source.stats(table));
                    rows += tableStats.count();
                    if (ignored.contains(table)) {
                        continue;
                    }
                    OptionalLong allocated = retry.call("reading " + table, () -> source.highWater(table));
                    names.add(table);
                    stats.put(table, tableStats);
                    highWater.put(table, Math.max(allocated.orElse(0), tableStats.maxRowId()));
                }
                if (rows == 0) {
                    throw new MigrationException("The " + sourceSettings.describe() + " holds no CoreProtect data,"
                        + " so there's nothing to migrate. Check its settings in CoreProtect's config.yml, such as"
                        + " table-prefix.");
                }

                targetWritten = true;
                sink.prepare(highWater);
                sink.markIncomplete();
                tables = plan(source, sink, names, stats, highWater);

                long total = 0;
                for (TableCopy table : tables) {
                    total += table.sourceStats().count();
                }
                console.say("Copying " + Progress.rows(total) + " in " + tables.size()
                    + (tables.size() == 1 ? " table." : " tables."));
                long copyStarted = clock.getAsLong();
                Copier copier = new Copier(source, sink, (table, column, value) -> bridge.transcode(table, column,
                    value, sourceSettings.engine(), targetEngine), this::keepUnconverted, retry, stop, console::say,
                    clock);
                long copied = copier.copy(tables);
                retry.call("finishing the target", () -> {
                    sink.finish(highWater);
                    return null;
                });
                console.say("Copied " + Progress.rows(copied) + " in "
                    + Progress.duration(clock.getAsLong() - copyStarted) + ".");
                reportUnconverted();

                validate(source, sink, tables, ignored, retry, stop);
            }

            stop.check();
            console.say("Switching CoreProtect to the " + targetSettings.describe() + ".");
            activating = true;
            List<String> notes = session.activate(sink, targetSettings);
            activating = false;
            console.say("Migration complete. CoreProtect now uses the " + targetSettings.describe() + ", in "
                + Progress.duration(clock.getAsLong() - started) + ".");
            for (String note : notes) {
                console.detail(note);
            }
            console.detail("The migration didn't change the " + sourceSettings.describe() + ". Keep it until you've"
                + " checked the new database, then archive or remove it.");
        }
    }

    /**
     * Refuse a source without the tables every CoreProtect database has,
     * such as one whose tables have another prefix: migrating it would
     * switch CoreProtect to an empty database.
     */
    private void checkCoreTables(List<String> present) throws MigrationException {
        List<String> missing = new ArrayList<>();
        for (String table : Tables.CORE) {
            if (!present.contains(table)) {
                missing.add(sourceSettings.prefix() + table);
            }
        }
        if (!missing.isEmpty()) {
            throw new MigrationException("The " + sourceSettings.describe() + " has no table " + String.join(", ",
                missing) + ", so it isn't the CoreProtect database it should be. Check its settings in CoreProtect's"
                + " config.yml, such as table-prefix.");
        }
    }

    /**
     * Keep a value that can't be converted for the target as it is: CoreProtect
     * reads either encoding from any engine, so it reads the value on the
     * target as well, or as badly, as it reads it on the source now. A
     * ClickHouse target only takes converted entity data, so there the
     * migration fails instead.
     */
    private boolean keepUnconverted(String table, String column, long rowId, SQLException cause) {
        if (targetEngine == Engine.CLICKHOUSE) {
            return false;
        }
        unconvertedCount++;
        if (unconvertedNamed.size() < UNCONVERTED_NAMED) {
            unconvertedNamed.add(table + "." + column + " of row ID " + rowId + " (" + cause.getMessage() + ")");
        }
        return true;
    }

    private void reportUnconverted() {
        if (unconvertedCount == 0) {
            return;
        }
        String message = Progress.count(unconvertedCount) + (unconvertedCount == 1 ? " value" : " values")
            + " couldn't be converted for " + targetEngine.displayName() + " and " + (unconvertedCount == 1 ? "was"
            : "were") + " copied unchanged, so CoreProtect reads " + (unconvertedCount == 1 ? "it" : "them")
            + " as it did on the source: " + String.join("; ", unconvertedNamed)
            + (unconvertedCount > unconvertedNamed.size() ? "; ..." : "");
        console.say(message);
        LibreProtectLogger.warning("/co migrate-db: " + message);
    }

    /**
     * Match each table's source columns to the target's. Every source column
     * must exist in the target, except the key columns that ClickHouse's
     * views add, so nothing is silently left behind.
     */
    private List<TableCopy> plan(RowSource source, RowSink sink, List<String> names, Map<String, TableStats> stats,
                                 Map<String, Long> highWater) throws SQLException, MigrationException {
        List<TableCopy> tables = new ArrayList<>();
        for (String table : names) {
            Map<String, String> targetColumns = new HashMap<>();
            for (String column : sink.columns(table)) {
                targetColumns.put(column.toLowerCase(Locale.ROOT), column);
            }
            List<String> from = new ArrayList<>();
            List<String> to = new ArrayList<>();
            for (String column : source.columns(table)) {
                String match = targetColumns.get(column.toLowerCase(Locale.ROOT));
                if (match != null) {
                    from.add(column);
                    to.add(match);
                } else if (!column.startsWith("_key_")) {
                    throw new MigrationException("Table " + table + " of the target has no column " + column
                        + ", which the source has. The target's schema doesn't match this CoreProtect version.");
                }
            }
            TableStats tableStats = stats.get(table);
            boolean full = fullValidation || tableStats.count() <= FULL_COMPARISON_ROWS || Tables.isReference(table);
            tables.add(new TableCopy(table, from, to, tableStats, highWater.get(table),
                full ? null : SamplePlan.forRows(tableStats.count(), random)));
        }
        return tables;
    }

    private void validate(RowSource source, RowSink sink, List<TableCopy> tables, Set<String> ignored, Retry retry,
                          StopCheck stop) throws SQLException, MigrationException, InterruptedException {
        long selected = 0;
        for (TableCopy table : tables) {
            selected += table.comparedRows();
        }
        if (fullValidation) {
            console.say("Validating every copied row (" + Progress.rows(selected) + ").");
        } else {
            console.say("Validating the row counts, row IDs and high-water marks of every table, every row of small"
                + " and reference tables, and about 1% of the rows of larger tables (" + Progress.rows(selected)
                + ").");
        }
        try (RowSource copy = sink.readBack()) {
            long compared = new Validator(source, copy, canonical(bridge, sourceSettings.engine(), targetEngine), retry,
                stop, console::say, clock).validate(tables, ignored);
            if (targetEngine == Engine.CLICKHOUSE) {
                long versions = retry.scan("counting " + Tables.VERSION, () -> copy.stats(Tables.VERSION)).count();
                if (versions != 1) {
                    throw new MigrationException("The ClickHouse target has " + versions + " version rows instead"
                        + " of its own one.");
                }
            }
            console.say("Validation passed: " + Progress.rows(compared) + " compared, no differences.");
        }
    }

    /**
     * @return how validation brings values of both sides to one form. Between
     *         a relational and a columnar engine, that's the bridge's
     *         canonical encoding; a value that has none, which the copy kept
     *         unchanged, compares as it is. Values of engines with the same
     *         encoding compare as they are. ClickHouse can't store a NULL
     *         uuid, so there NULL and empty are the same.
     */
    static Transcoder canonical(MigrationBridge bridge, Engine from, Engine to) {
        boolean encodingsDiffer = from.isColumnar() != to.isColumnar();
        boolean clickHouse = from == Engine.CLICKHOUSE || to == Engine.CLICKHOUSE;
        return (table, column, value) -> {
            if (clickHouse && isEmpty(value) && column.equalsIgnoreCase("uuid")
                && (table.equals("user") || table.equals("username_log"))) {
                return null;
            }
            if (!encodingsDiffer) {
                return value;
            }
            try {
                return bridge.canonical(table, column, value);
            } catch (SQLException e) {
                return value;
            }
        };
    }

    private static boolean isEmpty(Object value) {
        return "".equals(value) || value instanceof byte[] && ((byte[]) value).length == 0;
    }

    private void checkStop() throws MigrationException {
        String reason = session.stopReason();
        if (reason != null) {
            throw new MigrationException("The migration stopped because " + reason + ".");
        }
    }

    private void fail(String message, List<String> details) {
        console.error("Migration failed. " + message);
        for (String detail : details) {
            console.detail(detail);
        }
        if (sourceSettings != null && !activating) {
            console.detail("CoreProtect keeps using the " + sourceSettings.describe() + ", which the migration"
                + " didn't change.");
        }
        if (targetWritten && targetSettings != null) {
            for (String advice : targetAdvice()) {
                console.detail(advice);
            }
        }
        List<String> notes;
        try {
            notes = session.afterFailure();
        } catch (RuntimeException e) {
            notes = new ArrayList<>();
        }
        for (String note : notes) {
            console.detail(note);
            LibreProtectLogger.info("/co migrate-db: " + note);
        }
    }

    /**
     * @return how to clean up the target before trying again
     */
    private List<String> targetAdvice() {
        List<String> advice = new ArrayList<>();
        if (targetSettings == null) {
            return advice;
        }
        if (targetSettings.engine() == Engine.DUCKDB) {
            advice.add("Before trying again, stop the server and move away or delete " + targetSettings.file().getPath()
                + " and any files next to it whose names start with " + targetSettings.file().getName() + ".");
        } else if (targetSettings.engine().isEmbedded()) {
            advice.add("Before trying again, move away or delete " + targetSettings.file().getPath()
                + " and any files next to it whose names start with " + targetSettings.file().getName() + ".");
        } else {
            advice.add("Before trying again, drop the tables whose names start with '" + targetSettings.prefix()
                + "' in the " + targetSettings.engine().displayName() + " database '" + targetSettings.database()
                + "', or choose a different table-prefix in CoreProtect's config.yml.");
        }
        return advice;
    }

    static String describe(SQLException e) {
        StringBuilder text = new StringBuilder(String.valueOf(e.getMessage()));
        if (e.getSQLState() != null) {
            text.append(" (SQL state ").append(e.getSQLState()).append(')');
        }
        return text.toString();
    }

    private static String stackTrace(Throwable e) {
        StringWriter writer = new StringWriter();
        e.printStackTrace(new PrintWriter(writer));
        return writer.toString();
    }
}
