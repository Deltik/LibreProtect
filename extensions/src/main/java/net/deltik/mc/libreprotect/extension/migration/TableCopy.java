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

import java.util.Collections;
import java.util.List;

/**
 * One table of a migration: which columns are copied, what the source held
 * before the copy, and which rows validation compares.
 */
final class TableCopy {

    private final String table;
    private final List<String> sourceColumns;
    private final List<String> targetColumns;
    private final TableStats sourceStats;
    private final long highWater;
    private final SamplePlan sample;

    /**
     * @param sourceColumns the columns to read, in the same order as {@code targetColumns}
     * @param targetColumns the same columns as the target names them
     * @param highWater the highest row ID the source handed out, at least its largest row ID
     * @param sample the rows to compare, or {@code null} to compare them all
     */
    TableCopy(String table, List<String> sourceColumns, List<String> targetColumns, TableStats sourceStats,
              long highWater, SamplePlan sample) {
        this.table = table;
        this.sourceColumns = Collections.unmodifiableList(sourceColumns);
        this.targetColumns = Collections.unmodifiableList(targetColumns);
        this.sourceStats = sourceStats;
        this.highWater = highWater;
        this.sample = sample;
    }

    String table() {
        return table;
    }

    List<String> sourceColumns() {
        return sourceColumns;
    }

    List<String> targetColumns() {
        return targetColumns;
    }

    TableStats sourceStats() {
        return sourceStats;
    }

    long highWater() {
        return highWater;
    }

    /**
     * @return the sampled ranges to compare, or {@code null} to compare every row
     */
    SamplePlan sample() {
        return sample;
    }

    /**
     * @return how many rows validation compares
     */
    long comparedRows() {
        return sample == null ? sourceStats.count() : sample.plannedRows();
    }
}
