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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class SamplePlanTest {

    /** Row IDs with gaps that grow, so row ID space and copy order differ */
    private static long rowId(long position) {
        return 10 + position * 3 + (position / 1000) * (position / 1000);
    }

    private static List<SamplePlan.Range> observe(SamplePlan plan, long rows, int batch) {
        List<Row> pending = new ArrayList<>();
        for (long position = 0; position < rows; position++) {
            pending.add(new Row(rowId(position), new Object[0]));
            if (pending.size() == batch) {
                plan.observe(pending);
                pending.clear();
            }
        }
        plan.observe(pending);
        return plan.ranges();
    }

    private static long position(long rowId, long rows) {
        for (long position = 0; position < rows; position++) {
            if (rowId(position) == rowId) {
                return position;
            }
        }
        throw new AssertionError("no row ID " + rowId);
    }

    @ParameterizedTest
    @ValueSource(longs = {100_001, 1_000_000, 2_500_000})
    @DisplayName("should select about 1% of the rows, in ranges spread over every million rows copied")
    void coversOnePercentOfEachMillion(long rows) {
        SamplePlan plan = SamplePlan.forRows(rows, new Random(3));

        List<SamplePlan.Range> ranges = observe(plan, rows, 4_321);

        long covered = ranges.stream().mapToLong(SamplePlan.Range::rows).sum();
        assertEquals(plan.plannedRows(), covered);
        assertTrue(covered >= rows / 100 && covered <= rows / 100 + 1_000, "covered " + covered);
        for (long window = 0; window * SamplePlan.WINDOW_ROWS < rows; window++) {
            long start = window * SamplePlan.WINDOW_ROWS;
            long end = Math.min(rows, start + SamplePlan.WINDOW_ROWS);
            long inWindow = ranges.stream()
                .filter(range -> position(range.fromRowId(), rows) >= start && position(range.toRowId(), rows) < end)
                .mapToLong(SamplePlan.Range::rows).sum();
            assertTrue(inWindow >= (end - start) / 100, "window " + window + " has " + inWindow + " sampled rows");
        }
    }

    @Test
    @DisplayName("should note the row IDs of the rows copied at the chosen positions, across batches")
    void rangesMatchCopiedRows() {
        long rows = 300_000;
        SamplePlan plan = SamplePlan.forRows(rows, new Random(11));

        List<SamplePlan.Range> ranges = observe(plan, rows, 777);

        long previousEnd = Long.MIN_VALUE;
        for (SamplePlan.Range range : ranges) {
            long from = position(range.fromRowId(), rows);
            long to = position(range.toRowId(), rows);
            assertEquals(range.rows(), to - from + 1, range.toString());
            assertTrue(range.fromRowId() > previousEnd, "ranges overlap or are out of order");
            previousEnd = range.toRowId();
        }
        assertEquals(3, ranges.size());
    }

    @Test
    @DisplayName("should choose different ranges for different random numbers")
    void random() {
        List<SamplePlan.Range> first = observe(SamplePlan.forRows(500_000, new Random(1)), 500_000, 1_000);
        List<SamplePlan.Range> second = observe(SamplePlan.forRows(500_000, new Random(2)), 500_000, 1_000);

        assertNotEquals(first.get(0).fromRowId(), second.get(0).fromRowId());
    }

    @Test
    @DisplayName("should end a range at the last row when fewer rows were copied than planned")
    void cutShort() {
        SamplePlan plan = SamplePlan.forRows(200_000, new Random(5));
        List<SamplePlan.Range> planned = observe(SamplePlan.forRows(200_000, new Random(5)), 200_000, 1_000);
        long stopAt = position(planned.get(0).fromRowId(), 200_000) + 10;

        List<SamplePlan.Range> ranges = observe(plan, stopAt, 1_000);

        assertEquals(1, ranges.size());
        assertEquals(rowId(stopAt - 1), ranges.get(0).toRowId());
        assertEquals(10, ranges.get(0).rows());
    }
}
