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

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.OptionalLong;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * Checks that the target holds what the source holds before CoreProtect
 * switches to it: every table's row count, smallest and largest row IDs and
 * allocator high-water mark, and the contents of the selected rows. Any
 * difference throws.
 */
final class Validator {

    private static final int PAGE_ROWS = 2_000;
    /** At most about this many sampled rows are read at once */

    private final RowSource source;
    private final RowSource target;
    private final Transcoder canonical;
    private final Retry retry;
    private final StopCheck stop;
    private final Progress.Output output;
    private final LongSupplier clock;

    /**
     * @param canonical converts values of either side to a common encoding
     *                  before comparing them, or {@link Transcoder#NONE}
     */
    Validator(RowSource source, RowSource target, Transcoder canonical, Retry retry, StopCheck stop,
              Progress.Output output, LongSupplier clock) {
        this.source = source;
        this.target = target;
        this.canonical = canonical;
        this.retry = retry;
        this.stop = stop;
        this.output = output;
        this.clock = clock;
    }

    /**
     * @param tables what was copied
     * @param ignored tables of the target that the migration doesn't fill,
     *                such as {@code database_lock}
     * @return how many rows were compared
     * @throws MigrationException describing the first difference found
     */
    long validate(List<TableCopy> tables, Collection<String> ignored)
        throws SQLException, MigrationException, InterruptedException {
        checkStatistics(tables, ignored);
        long selected = 0;
        for (TableCopy table : tables) {
            selected += table.comparedRows();
        }
        Progress progress = new Progress(output, "Validating", "rows compared", selected, false, clock);
        long compared = 0;
        for (TableCopy table : tables) {
            compared += table.sample() == null
                ? compareAll(table, progress, compared)
                : compareSample(table, progress, compared);
        }
        return compared;
    }

    private void checkStatistics(List<TableCopy> tables, Collection<String> ignored)
        throws SQLException, MigrationException, InterruptedException {
        Set<String> copied = new HashSet<>();
        for (TableCopy table : tables) {
            stop.check();
            String name = table.table();
            copied.add(name);
            TableStats now = retry.scan("counting " + name, () -> source.stats(name));
            if (!now.equals(table.sourceStats())) {
                throw new MigrationException("Table " + name + " of the source changed during the migration: it had "
                    + table.sourceStats() + " and now has " + now + ". Something else writes to the source.");
            }
            TableStats copy = retry.scan("counting " + name, () -> target.stats(name));
            if (!copy.equals(now)) {
                throw new MigrationException("Table " + name + " differs: the source has " + now
                    + ", but the target has " + copy + ".");
            }
            OptionalLong highWater = retry.call("reading " + name, () -> target.highWater(name));
            if (highWater.isPresent() && highWater.getAsLong() < table.highWater()) {
                throw new MigrationException("Table " + name + " of the target would hand out row IDs from "
                    + (highWater.getAsLong() + 1) + ", but the source has used row IDs up to " + table.highWater() + ".");
            }
        }
        for (String name : retry.call("listing tables", target::tables)) {
            if (!copied.contains(name) && !ignored.contains(name)) {
                TableStats extra = retry.scan("counting " + name, () -> target.stats(name));
                if (extra.count() != 0) {
                    throw new MigrationException("Table " + name + " of the target has " + extra
                        + ", but none of them come from the source.");
                }
            }
        }
    }

    /**
     * Compare every row, reading both sides in row ID order, each continuing
     * where its last read ended: a page of the source, then the target's
     * rows up to the page's last row ID. Engines may return pages of
     * different sizes, so the target's rows are buffered.
     */
    private long compareAll(TableCopy table, Progress progress, long doneBefore)
        throws SQLException, MigrationException, InterruptedException {
        String name = table.table();
        long after = table.sourceStats().minRowId() == Long.MIN_VALUE
            ? Long.MIN_VALUE : table.sourceStats().minRowId() - 1;
        Cursor copy = new Cursor(name, table.targetColumns(), after);
        long compared = 0;
        while (compared < table.sourceStats().count()) {
            stop.check();
            long from = after;
            List<Row> expected = retry.call("reading " + name,
                () -> source.read(name, table.sourceColumns(), from, PAGE_ROWS));
            if (expected.isEmpty()) {
                break;
            }
            after = expected.get(expected.size() - 1).rowId();
            compareRows(table, expected, copy.through(after));
            compared += expected.size();
            progress.update(doneBefore + compared, name);
        }
        if (compared != table.sourceStats().count()) {
            throw new MigrationException("Compared " + Progress.rows(compared) + " of table " + name
                + ", but the source has " + Progress.count(table.sourceStats().count()) + ".");
        }
        return compared;
    }

    /**
     * Compare the sampled ranges, one read of each side per range.
     */
    private long compareSample(TableCopy table, Progress progress, long doneBefore)
        throws SQLException, MigrationException, InterruptedException {
        String name = table.table();
        long compared = 0;
        for (SamplePlan.Range range : table.sample().ranges()) {
            stop.check();
            List<Row> expected = retry.call("reading " + name,
                () -> source.readRange(name, table.sourceColumns(), range.fromRowId(), range.toRowId()));
            if (expected.size() != range.rows()) {
                throw new MigrationException("Table " + name + " of the source has " + expected.size()
                    + " rows in " + range + " now, not " + range.rows() + ". Something else writes to the source.");
            }
            List<Row> actual = retry.call("reading " + name,
                () -> target.readRange(name, table.targetColumns(), range.fromRowId(), range.toRowId()));
            compareRows(table, expected, actual);
            compared += range.rows();
            progress.update(doneBefore + compared, name);
        }
        return compared;
    }

    /**
     * Reads one of the target's tables in row ID order, in pages, and hands
     * out its rows up to a given row ID.
     */
    private final class Cursor {
        private final String table;
        private final List<String> columns;
        private long after;
        private List<Row> page = new ArrayList<>();
        private int next;
        private boolean exhausted;

        Cursor(String table, List<String> columns, long after) {
            this.table = table;
            this.columns = columns;
            this.after = after;
        }

        /**
         * @return the rows after the ones handed out before, up to and including {@code rowId}
         */
        List<Row> through(long rowId) throws SQLException, MigrationException, InterruptedException {
            List<Row> rows = new ArrayList<>();
            while (true) {
                while (next < page.size() && page.get(next).rowId() <= rowId) {
                    rows.add(page.get(next++));
                }
                if (next < page.size() || exhausted) {
                    return rows;
                }
                long from = after;
                page = retry.call("reading " + table, () -> target.read(table, columns, from, PAGE_ROWS));
                next = 0;
                if (page.isEmpty()) {
                    exhausted = true;
                } else {
                    after = page.get(page.size() - 1).rowId();
                }
            }
        }
    }

    private void compareRows(TableCopy table, List<Row> expected, List<Row> actual) throws SQLException, MigrationException {
        String name = table.table();
        List<String> columns = table.targetColumns();
        for (int i = 0; i < expected.size(); i++) {
            Row want = expected.get(i);
            Row have = i < actual.size() ? actual.get(i) : null;
            if (have == null || have.rowId() > want.rowId()) {
                throw new MigrationException("Row ID " + want.rowId() + " of table " + name + " is missing from the target.");
            }
            if (have.rowId() < want.rowId()) {
                throw new MigrationException("Row ID " + have.rowId() + " of table " + name
                    + " is in the target, but not in the source.");
            }
            for (int column = 0; column < columns.size(); column++) {
                String columnName = columns.get(column);
                Object wanted = canonical.apply(name, columnName, want.values()[column]);
                Object had = canonical.apply(name, columnName, have.values()[column]);
                if (!Values.same(wanted, had)) {
                    throw new MigrationException("Row ID " + want.rowId() + " of table " + name + " differs in column "
                        + columnName + ": the source has " + Values.describe(wanted) + ", the target "
                        + Values.describe(had) + ".");
                }
            }
        }
        if (actual.size() > expected.size()) {
            throw new MigrationException("Row ID " + actual.get(expected.size()).rowId() + " of table " + name
                + " is in the target, but not in the source.");
        }
    }
}
