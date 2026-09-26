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

import java.util.Locale;
import java.util.function.LongSupplier;

/**
 * A progress bar for a long step of the migration, such as
 * {@code Copying [######--------------] 30% 12,345 of 41,150 rows, co_block,
 * 2,469 rows/s, about 12 s left}, shown at most every few seconds.
 */
final class Progress {

    static final long INTERVAL_NANOS = 5_000_000_000L;
    private static final int BAR_WIDTH = 20;

    /** Where progress lines go */
    @FunctionalInterface
    interface Output {
        void line(String line);
    }

    private final Output output;
    private final String verb;
    private final String unit;
    private final long total;
    private final boolean showRate;
    private final LongSupplier clock;
    private final long started;
    private long lastShown;

    /**
     * @param verb what's being done, such as "Copying"
     * @param unit what's counted, such as "rows" or "rows compared"
     * @param total how many there are in all
     * @param showRate whether to show the rate and the time left
     * @param clock the time in nanoseconds, {@code System::nanoTime} outside tests
     */
    Progress(Output output, String verb, String unit, long total, boolean showRate, LongSupplier clock) {
        this.output = output;
        this.verb = verb;
        this.unit = unit;
        this.total = total;
        this.showRate = showRate;
        this.clock = clock;
        this.started = clock.getAsLong();
        this.lastShown = started;
    }

    /**
     * Show the progress if the interval has passed since it was last shown.
     *
     * @param done how many are done
     * @param current what's being worked on, such as a table name
     */
    void update(long done, String current) {
        long now = clock.getAsLong();
        if (now - lastShown >= INTERVAL_NANOS) {
            lastShown = now;
            output.line(line(done, current, now));
        }
    }

    /**
     * @return the progress line for the given state, without throttling
     */
    String line(long done, String current, long now) {
        double fraction = total <= 0 ? 1 : Math.min(1, done / (double) total);
        int filled = (int) Math.floor(fraction * BAR_WIDTH);
        StringBuilder line = new StringBuilder(verb).append(" [");
        for (int i = 0; i < BAR_WIDTH; i++) {
            line.append(i < filled ? '#' : '-');
        }
        line.append("] ").append((int) Math.floor(fraction * 100)).append("% ")
            .append(count(done)).append(" of ").append(count(total)).append(' ').append(unit);
        if (current != null) {
            line.append(", ").append(current);
        }
        if (showRate) {
            long elapsed = now - started;
            if (elapsed > 0 && done > 0) {
                double perSecond = done / (elapsed / 1e9);
                line.append(", ").append(count(Math.round(perSecond))).append(" rows/s");
                if (done < total) {
                    line.append(", about ").append(duration(Math.round((total - done) / perSecond * 1e9))).append(" left");
                }
            }
        }
        return line.toString();
    }

    /**
     * @return the time since this progress started, e.g. {@code 4 min 2 s}
     */
    String elapsed() {
        return duration(clock.getAsLong() - started);
    }

    static String count(long value) {
        return String.format(Locale.ROOT, "%,d", value);
    }

    /**
     * @return e.g. {@code 1 row} or {@code 1,234 rows}
     */
    static String rows(long value) {
        return count(value) + (value == 1 ? " row" : " rows");
    }

    /**
     * @return a duration in the two largest units, e.g. {@code 1 h 5 min}, {@code 12 s}
     */
    static String duration(long nanos) {
        long seconds = Math.max(0, Math.round(nanos / 1e9));
        long hours = seconds / 3600;
        long minutes = seconds % 3600 / 60;
        seconds %= 60;
        if (hours > 0) {
            return hours + " h " + minutes + " min";
        }
        if (minutes > 0) {
            return minutes + " min " + seconds + " s";
        }
        return seconds + " s";
    }
}
