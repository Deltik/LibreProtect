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

/**
 * How many rows each purge chunk handles: about 5,000 to start, halved after
 * a chunk that held its lease for more than 100 ms and grown after one that
 * held it for less than 40 ms, so that no chunk holds the database for long.
 */
final class ChunkSizer {

    static final int INITIAL_ROWS = 5_000;
    static final int MINIMUM_ROWS = 100;
    static final int MAXIMUM_ROWS = 50_000;
    static final long SLOW_NANOS = 100_000_000L;
    static final long FAST_NANOS = 40_000_000L;

    private int rows = INITIAL_ROWS;

    /**
     * @return rows the next chunk should handle
     */
    int rows() {
        return rows;
    }

    /**
     * Adjust after a chunk that held its lease for {@code elapsedNanos}.
     */
    void record(long elapsedNanos) {
        if (elapsedNanos > SLOW_NANOS) {
            rows = Math.max(MINIMUM_ROWS, rows / 2);
        } else if (elapsedNanos < FAST_NANOS) {
            rows = Math.min(MAXIMUM_ROWS, rows + rows / 2);
        }
    }

    /**
     * @param width the rowid width of the last range
     * @param count the rows the last range held
     * @return a rowid width that should hold about {@link #rows()} rows, given the last range's density
     */
    long span(long width, long count, long maximum) {
        if (count <= 0) {
            return Math.max(1, Math.min(maximum, width));
        }
        double span = (double) rows * width / count;
        return (long) Math.max(1, Math.min(maximum, span));
    }
}
