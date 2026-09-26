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

/**
 * What validation compares for every table: the row count and the smallest
 * and largest row IDs.
 */
public final class TableStats {

    private final long count;
    private final long minRowId;
    private final long maxRowId;

    /**
     * @param minRowId the smallest row ID, or 0 for an empty table
     * @param maxRowId the largest row ID, or 0 for an empty table
     */
    public TableStats(long count, long minRowId, long maxRowId) {
        this.count = count;
        this.minRowId = minRowId;
        this.maxRowId = maxRowId;
    }

    public long count() {
        return count;
    }

    public long minRowId() {
        return minRowId;
    }

    public long maxRowId() {
        return maxRowId;
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof TableStats)) {
            return false;
        }
        TableStats that = (TableStats) other;
        return count == that.count && minRowId == that.minRowId && maxRowId == that.maxRowId;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(count) * 31 * 31 + Long.hashCode(minRowId) * 31 + Long.hashCode(maxRowId);
    }

    @Override
    public String toString() {
        return count + " rows, row IDs " + minRowId + " to " + maxRowId;
    }
}
