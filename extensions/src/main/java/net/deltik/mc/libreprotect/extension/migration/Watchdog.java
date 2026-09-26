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

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

/**
 * Watches, on a thread of its own, for the migration having to stop, such
 * as the server shutting down, and then aborts the migration's database
 * work. The migration otherwise only notices a stop between database calls,
 * and one call can wait on an unresponsive server for minutes, while
 * CoreProtect's shutdown waits for the migration and holds its queue.
 */
final class Watchdog implements AutoCloseable {

    static final long POLL_MILLIS = 200;

    /** Something whose work can be aborted from another thread */
    @FunctionalInterface
    interface Abortable {
        void abort();
    }

    private final Supplier<String> stopReason;
    private final List<Abortable> watched = new CopyOnWriteArrayList<>();
    private final Thread thread;
    private volatile boolean closed;
    private volatile boolean fired;

    /**
     * @param stopReason why the migration has to stop now, or {@code null}
     */
    Watchdog(Supplier<String> stopReason) {
        this.stopReason = stopReason;
        this.thread = new Thread(this::run, "LibreProtect migration watchdog");
        thread.setDaemon(true);
    }

    Watchdog start() {
        thread.start();
        return this;
    }

    /**
     * Abort this too once the migration has to stop, or at once if it
     * already has to.
     */
    void watch(Abortable abortable) {
        watched.add(abortable);
        if (fired) {
            abortQuietly(abortable);
        }
    }

    /**
     * @return whether a stop was seen and the watched work aborted
     */
    boolean fired() {
        return fired;
    }

    private void run() {
        while (!closed) {
            String reason;
            try {
                reason = stopReason.get();
            } catch (RuntimeException e) {
                reason = null;
            }
            if (reason != null) {
                fired = true;
                for (Abortable abortable : watched) {
                    abortQuietly(abortable);
                }
                return;
            }
            try {
                Thread.sleep(POLL_MILLIS);
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    private static void abortQuietly(Abortable abortable) {
        try {
            abortable.abort();
        } catch (RuntimeException e) {
            // Aborting is best effort; the migration still stops at its next check
        }
    }

    @Override
    public void close() {
        closed = true;
        thread.interrupt();
    }
}
