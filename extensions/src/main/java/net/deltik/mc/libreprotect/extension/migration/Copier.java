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

import java.sql.SQLDataException;
import java.sql.SQLException;
import java.util.List;
import java.util.function.LongSupplier;

/**
 * Copies tables from a source to a sink in row ID order, in batches that
 * each are one transaction, keeping every row ID.
 */
final class Copier {

    /**
     * Decides about values that can't be converted for the target
     */
    @FunctionalInterface
    interface Unconverted {
        /**
         * @return whether to copy the value unchanged instead of failing
         */
        boolean keep(String table, String column, long rowId, SQLException cause);

        /** Fails on every value that can't be converted */
        Unconverted FAIL = (table, column, rowId, cause) -> false;
    }

    private final RowSource source;
    private final RowSink sink;
    private final Transcoder transcoder;
    private final Unconverted unconverted;
    private final Retry retry;
    private final StopCheck stop;
    private final Progress.Output output;
    private final LongSupplier clock;

    /**
     * @param transcoder converts values from the source's encoding to the sink's
     * @param unconverted what to do with a value that the transcoder can't convert
     * @param output where progress and per-table lines go
     * @param clock the time in nanoseconds
     */
    Copier(RowSource source, RowSink sink, Transcoder transcoder, Unconverted unconverted, Retry retry,
           StopCheck stop, Progress.Output output, LongSupplier clock) {
        this.source = source;
        this.sink = sink;
        this.transcoder = transcoder;
        this.unconverted = unconverted;
        this.retry = retry;
        this.stop = stop;
        this.output = output;
        this.clock = clock;
    }

    /**
     * Copy every table, noting the sampled ranges' row IDs along the way.
     *
     * @return how many rows were copied
     * @throws MigrationException if the source doesn't hold what it held
     *                            before the copy, or the migration has to stop
     */
    long copy(List<TableCopy> tables) throws SQLException, MigrationException, InterruptedException {
        long total = 0;
        for (TableCopy table : tables) {
            total += table.sourceStats().count();
        }
        Progress progress = new Progress(output, "Copying", "rows", total, true, clock);
        long done = 0;
        for (TableCopy table : tables) {
            done += copyTable(table, progress, done);
        }
        return done;
    }

    private long copyTable(TableCopy table, Progress progress, long doneBefore)
        throws SQLException, MigrationException, InterruptedException {
        String name = table.table();
        TableStats stats = table.sourceStats();
        if (stats.count() == 0) {
            return 0;
        }
        long started = clock.getAsLong();
        BatchSizer sizer = new BatchSizer();
        long after = stats.minRowId() == Long.MIN_VALUE ? Long.MIN_VALUE : stats.minRowId() - 1;
        long copied = 0;
        while (true) {
            stop.check();
            long batchStarted = clock.getAsLong();
            int limit = sizer.size();
            long from = after;
            List<Row> rows = retry.call("reading " + name,
                () -> source.read(name, table.sourceColumns(), from, limit));
            if (rows.isEmpty()) {
                break;
            }
            long bytes = convert(name, table.targetColumns(), rows, after);
            retry.call("writing " + name, () -> {
                sink.write(name, table.targetColumns(), rows);
                return null;
            });
            if (table.sample() != null) {
                table.sample().observe(rows);
            }
            after = rows.get(rows.size() - 1).rowId();
            copied += rows.size();
            sizer.record(rows.size(), bytes, clock.getAsLong() - batchStarted);
            progress.update(doneBefore + copied, name);
        }
        if (copied != stats.count()) {
            throw new MigrationException("Read " + Progress.rows(copied) + " of table " + name + " from the"
                + " source, but it had " + Progress.count(stats.count()) + " when the copy started. Something else"
                + " changed the source during the migration.");
        }
        output.line("Copied table " + name + ": " + Progress.rows(copied) + " in "
            + Progress.duration(clock.getAsLong() - started) + ".");
        return copied;
    }

    /**
     * Convert a batch's values for the sink, in place, and check that the
     * rows come in increasing row ID order after {@code after}.
     *
     * @return about how many bytes the rows take
     */
    private long convert(String table, List<String> columns, List<Row> rows, long after) throws SQLException {
        long bytes = 0;
        long previous = after;
        for (Row row : rows) {
            if (row.rowId() <= previous) {
                throw new SQLDataException("The source returned row ID " + row.rowId() + " of table " + table
                    + " after row ID " + previous + "; rows must come in increasing row ID order");
            }
            previous = row.rowId();
            Object[] values = row.values();
            if (values.length != columns.size()) {
                throw new SQLDataException("The source returned " + values.length + " values for row ID "
                    + row.rowId() + " of table " + table + " instead of " + columns.size());
            }
            bytes += 16;
            for (int i = 0; i < values.length; i++) {
                try {
                    values[i] = transcoder.apply(table, columns.get(i), values[i]);
                } catch (SQLException e) {
                    if (!unconverted.keep(table, columns.get(i), row.rowId(), e)) {
                        throw new SQLDataException("Can't convert column " + columns.get(i) + " of row ID "
                            + row.rowId() + " in table " + table + ": " + e.getMessage(), e);
                    }
                }
                bytes += size(values[i]);
            }
        }
        return bytes;
    }

    private static long size(Object value) {
        if (value instanceof byte[]) {
            return ((byte[]) value).length + 16L;
        }
        if (value instanceof String) {
            return 2L * ((String) value).length() + 40;
        }
        return 16;
    }
}
