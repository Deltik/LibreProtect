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

/**
 * Repeats a database call that failed for a reason that may pass (see
 * {@link TransientErrors}). Waits 1, 2, 4, 8 and 16 seconds between five
 * retries, and stops waiting when the migration has to stop. A call that
 * scans a whole table, which can take long on a large one, is repeated once.
 */
final class Retry {

    static final int RETRIES = 5;
    static final int SCAN_RETRIES = 1;
    static final long FIRST_DELAY_MILLIS = 1_000;
    private static final long STOP_POLL_MILLIS = 250;

    /** A database call to repeat */
    @FunctionalInterface
    interface Call<T> {
        T call() throws SQLException;
    }

    /** Hears about each retry, to tell the person waiting */
    @FunctionalInterface
    interface Listener {
        /**
         * @param retry   which retry this is, from 1
         * @param retries how many retries the call gets at most
         */
        void retrying(String what, int retry, int retries, SQLException cause, long delayMillis);
    }

    /** Sleeps, and can be replaced in tests */
    @FunctionalInterface
    interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }

    private final StopCheck stop;
    private final Listener listener;
    private final Sleeper sleeper;

    Retry(StopCheck stop, Listener listener) {
        this(stop, listener, Thread::sleep);
    }

    Retry(StopCheck stop, Listener listener, Sleeper sleeper) {
        this.stop = stop;
        this.listener = listener;
        this.sleeper = sleeper;
    }

    /**
     * @param what what the call does, for messages, such as "writing block"
     * @return what the call returned, once it succeeds
     * @throws SQLException the call's error if it isn't transient, or the
     *                      last one once the retries are used up
     * @throws MigrationException if the migration has to stop while waiting
     */
    <T> T call(String what, Call<T> call) throws SQLException, MigrationException, InterruptedException {
        return call(what, RETRIES, call);
    }

    /**
     * Like {@link #call(String, Call)}, for a call that scans a whole table,
     * such as counting its rows: repeated only once, since each attempt may
     * take as long as the scan does.
     */
    <T> T scan(String what, Call<T> call) throws SQLException, MigrationException, InterruptedException {
        return call(what, SCAN_RETRIES, call);
    }

    private <T> T call(String what, int retries, Call<T> call)
        throws SQLException, MigrationException, InterruptedException {
        long delay = FIRST_DELAY_MILLIS;
        for (int retry = 1; ; retry++) {
            try {
                return call.call();
            } catch (SQLException e) {
                if (retry > retries || !TransientErrors.isTransient(e)) {
                    throw e;
                }
                listener.retrying(what, retry, retries, e, delay);
                pause(delay);
                delay *= 2;
            }
        }
    }

    private void pause(long millis) throws MigrationException, InterruptedException {
        long remaining = millis;
        while (remaining > 0) {
            stop.check();
            long step = Math.min(remaining, STOP_POLL_MILLIS);
            sleeper.sleep(step);
            remaining -= step;
        }
        stop.check();
    }
}
