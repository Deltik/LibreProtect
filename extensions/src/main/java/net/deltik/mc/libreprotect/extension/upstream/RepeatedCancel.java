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

package net.deltik.mc.libreprotect.extension.upstream;

import net.deltik.mc.libreprotect.LibreProtectLogger;

import java.util.Objects;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

/**
 * Cancels a call again and again, from when a signal goes up until the call
 * ends, for a cancel that only reaches work that has started: one made
 * once, by someone else, just before the work starts would miss it.
 *
 * <p>CoreProtect's shutdown cancels a ClickHouse purge once, and its
 * retention ignores a cancel until the purge it runs has registered itself,
 * a moment into the call. A shutdown that cancels in that moment would
 * otherwise wait for the whole purge.
 */
final class RepeatedCancel implements AutoCloseable {

    /** How often the signal is checked, and the cancel repeated once it's up */
    static final long POLL_MILLIS = 100;

    private final ScheduledThreadPoolExecutor watchdog;

    private RepeatedCancel(ScheduledThreadPoolExecutor watchdog) {
        this.watchdog = watchdog;
    }

    /**
     * Start checking {@code signal}, and cancel each time it's up, until
     * {@link #close()}. An exception from either doesn't end the checks; the
     * first is logged.
     *
     * @param name what checks, as the name of its thread, and in the log
     */
    static RepeatedCancel start(String name, BooleanSupplier signal, Runnable cancel) {
        Objects.requireNonNull(signal, "signal");
        Objects.requireNonNull(cancel, "cancel");
        ScheduledThreadPoolExecutor watchdog = new ScheduledThreadPoolExecutor(1, runnable -> {
            Thread thread = new Thread(runnable, name);
            thread.setDaemon(true);
            return thread;
        });
        AtomicBoolean warned = new AtomicBoolean();
        watchdog.scheduleWithFixedDelay(() -> {
            try {
                if (signal.getAsBoolean()) {
                    cancel.run();
                }
            } catch (RuntimeException | LinkageError e) {
                // The next check tries again
                if (warned.compareAndSet(false, true)) {
                    LibreProtectLogger.warning(name + " failed, and keeps trying: " + e);
                }
            }
        }, 0, POLL_MILLIS, TimeUnit.MILLISECONDS);
        return new RepeatedCancel(watchdog);
    }

    /**
     * Stop cancelling, and wait up to a second for a cancel under way to
     * end, so that none comes after this returns. Never throws.
     */
    @Override
    public void close() {
        watchdog.shutdownNow();
        try {
            // A cancel that hangs is left behind: the call it was for has ended
            watchdog.awaitTermination(1, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
