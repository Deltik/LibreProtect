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
 * Picks how many rows to copy per batch: as many as take about a second to
 * read and write, within bounds, and few enough that a batch stays small in
 * memory. Each batch is one transaction, so this also bounds how much work a
 * retry repeats.
 */
final class BatchSizer {

    static final int MINIMUM = 500;
    static final int MAXIMUM = 50_000;
    static final int INITIAL = 1_000;
    static final long TARGET_NANOS = 1_000_000_000L;
    static final long MAXIMUM_BYTES = 32L * 1024 * 1024;

    private int size = INITIAL;

    /**
     * @return the number of rows to read for the next batch
     */
    int size() {
        return size;
    }

    /**
     * Adjust to a batch that just finished. The size changes by at most a
     * factor of two per batch, so one slow or fast batch doesn't swing it.
     *
     * @param rows how many rows the batch had
     * @param bytes about how much memory the rows took
     * @param elapsedNanos how long reading and writing them took
     */
    void record(int rows, long bytes, long elapsedNanos) {
        if (rows <= 0) {
            return;
        }
        double nanosPerRow = Math.max(1L, elapsedNanos) / (double) rows;
        double next = TARGET_NANOS / nanosPerRow;
        if (bytes > 0) {
            next = Math.min(next, MAXIMUM_BYTES / (bytes / (double) rows));
        }
        next = Math.max(size / 2.0, Math.min(size * 2.0, next));
        size = (int) Math.max(MINIMUM, Math.min(MAXIMUM, next));
    }
}
