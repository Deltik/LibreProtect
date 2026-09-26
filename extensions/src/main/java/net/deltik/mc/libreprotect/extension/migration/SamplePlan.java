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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * Which rows of a large table sampled validation compares: random contiguous
 * ranges of about a thousand rows, about 1% of every million rows copied.
 * The ranges are chosen by position among the rows actually copied, not by
 * row ID, so gaps left by deleted rows don't skew them. Their row IDs are
 * noted while the rows are copied, and only those ranges are read back.
 */
final class SamplePlan {

    static final long WINDOW_ROWS = 1_000_000;
    static final double FRACTION = 0.01;
    static final long RANGE_ROWS = 1_000;

    /** Rows to compare, by row ID, inclusive */
    static final class Range {
        private final long fromRowId;
        private final long toRowId;
        private final long rows;

        Range(long fromRowId, long toRowId, long rows) {
            this.fromRowId = fromRowId;
            this.toRowId = toRowId;
            this.rows = rows;
        }

        long fromRowId() {
            return fromRowId;
        }

        long toRowId() {
            return toRowId;
        }

        /**
         * @return how many rows were copied in this range
         */
        long rows() {
            return rows;
        }

        @Override
        public String toString() {
            return "row IDs " + fromRowId + " to " + toRowId + " (" + rows + " rows)";
        }
    }

    private final long[] starts;
    private final long[] ends;
    private final List<Range> ranges = new ArrayList<>();
    private int next;
    private long position;
    private boolean open;
    private long openFromRowId;
    private long openFromPosition;
    private long lastRowId;

    private SamplePlan(long[] starts, long[] ends) {
        this.starts = starts;
        this.ends = ends;
    }

    /**
     * Plan the ranges for a table.
     *
     * @param rowCount how many rows the table has
     */
    static SamplePlan forRows(long rowCount, Random random) {
        List<long[]> planned = new ArrayList<>();
        for (long windowStart = 0; windowStart < rowCount; windowStart += WINDOW_ROWS) {
            long windowRows = Math.min(WINDOW_ROWS, rowCount - windowStart);
            long sampleRows = Math.max(1, (long) Math.ceil(windowRows * FRACTION));
            long rangeCount = Math.max(1, Math.round(sampleRows / (double) RANGE_ROWS));
            long rangeRows = Math.max(1, (long) Math.ceil(sampleRows / (double) rangeCount));
            long slotRows = windowRows / rangeCount;
            for (long slot = 0; slot < rangeCount; slot++) {
                long slotStart = windowStart + slot * slotRows;
                long slotLength = slot == rangeCount - 1 ? windowStart + windowRows - slotStart : slotRows;
                long length = Math.min(rangeRows, slotLength);
                long offset = (long) (random.nextDouble() * (slotLength - length + 1));
                planned.add(new long[]{slotStart + offset, slotStart + offset + length - 1});
            }
        }
        long[] starts = new long[planned.size()];
        long[] ends = new long[planned.size()];
        for (int i = 0; i < planned.size(); i++) {
            starts[i] = planned.get(i)[0];
            ends[i] = planned.get(i)[1];
        }
        return new SamplePlan(starts, ends);
    }

    /**
     * @return how many rows the planned ranges cover
     */
    long plannedRows() {
        long rows = 0;
        for (int i = 0; i < starts.length; i++) {
            rows += ends[i] - starts[i] + 1;
        }
        return rows;
    }

    /**
     * Note the row IDs of a batch of copied rows, in the order they were copied.
     */
    void observe(List<Row> rows) {
        for (Row row : rows) {
            long rowId = row.rowId();
            if (!open && next < starts.length && position == starts[next]) {
                open = true;
                openFromRowId = rowId;
                openFromPosition = position;
            }
            if (open && position == ends[next]) {
                ranges.add(new Range(openFromRowId, rowId, position - openFromPosition + 1));
                open = false;
                next++;
            }
            lastRowId = rowId;
            position++;
        }
    }

    /**
     * @return the ranges seen so far; a range cut short because the table
     *         had fewer rows than planned ends at the last row copied
     */
    List<Range> ranges() {
        List<Range> all = new ArrayList<>(ranges);
        if (open) {
            all.add(new Range(openFromRowId, lastRowId, position - openFromPosition));
        }
        return Collections.unmodifiableList(all);
    }
}
