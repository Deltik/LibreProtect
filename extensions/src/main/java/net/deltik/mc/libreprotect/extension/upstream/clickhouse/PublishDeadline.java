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

package net.deltik.mc.libreprotect.extension.upstream.clickhouse;

import net.deltik.mc.libreprotect.extension.upstream.Flags;

import java.sql.SQLException;
import java.sql.SQLNonTransientException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

/**
 * Bounds how long CoreProtect's ClickHouse writer may keep retrying a
 * publication, and stops it when the server shuts down or the migration is
 * aborted ({@link #abort()}).
 *
 * <p>While the server runs, CoreProtect retries a publication that
 * ClickHouse refuses until it succeeds, with back-off up to 30 seconds. That
 * suits its consumer, but a migration holds persistence paused meanwhile, so
 * a refusal that never clears (a missing grant, a memory limit, a setting the
 * server doesn't know) would stall the server's logging for good, and hold
 * up its shutdown.
 *
 * <p>When the limit passes, or once the server starts shutting down, this
 * interrupts the publishing thread and reports the failure. CoreProtect's
 * writer honors the interrupt while it waits between attempts and while it
 * reconciles, but not during an insert already in flight, which ends by
 * itself within CoreProtect's 5-minute socket timeout. So the limit caps
 * retrying, not progress: a publication that keeps succeeding can run past
 * it, at worst by the insert in flight plus one insert for each partition
 * still to publish, each within that socket timeout. The interrupt never
 * outlives the publication.
 *
 * <p>The capability report's {@code relies} lines on
 * {@code ClickHouseBatchPublisher}'s {@code publish},
 * {@code shouldContinueRecovery} and {@code pauseBeforeRetry}, and on
 * {@code ClickHouseNativeClient}'s constructor, watch that behavior.
 */
final class PublishDeadline implements AutoCloseable {

    /** How often the watchdog checks the limit and whether the server is shutting down */
    static final long POLL_MILLIS = 100;

    /** One publication through CoreProtect's ClickHouse writer */
    interface Publication {
        void run() throws SQLException;
    }

    private final Duration limit;
    private final BooleanSupplier shuttingDown;
    private ScheduledExecutorService watchdog;
    /** The publication running now, if any */
    private volatile Expiry current;
    private volatile boolean aborted;

    /**
     * @param limit        how long a publication may keep retrying
     * @param shuttingDown whether the server is shutting down, which stops publications at once
     */
    PublishDeadline(Duration limit, BooleanSupplier shuttingDown) {
        if (limit.isNegative() || limit.isZero()) {
            throw new IllegalArgumentException("The publication limit must be positive");
        }
        this.limit = limit;
        this.shuttingDown = Objects.requireNonNull(shuttingDown, "shuttingDown");
    }

    /**
     * @return whether CoreProtect has started shutting down, by every signal
     *         it has: its shutdown raises the first, and only a new start of
     *         the plugin resets it
     */
    static BooleanSupplier serverShuttingDown(Flags flags) {
        return flags::shuttingDown;
    }

    Duration limit() {
        return limit;
    }

    /**
     * Run the publication in this thread, and stop it if it keeps retrying
     * past the limit or the server shuts down.
     *
     * @param what what is being published, for the error message
     * @throws ExpiredException if it was stopped
     */
    void run(String what, Publication publication) throws SQLException {
        if (aborted) {
            throw new ExpiredException("Writing " + what + " to ClickHouse didn't start because the migration is"
                + " stopping", null);
        }
        if (isShuttingDown()) {
            throw new ExpiredException("Writing " + what + " to ClickHouse didn't start because the server is"
                + " shutting down", null);
        }
        Expiry expiry = new Expiry(Thread.currentThread());
        current = expiry;
        if (aborted) {
            expiry.expire(Expiry.ABORT);
        }
        long start = System.nanoTime();
        ScheduledFuture<?> timer = watchdog().scheduleAtFixedRate(() -> {
            if (isShuttingDown()) {
                expiry.expire(Expiry.SHUTDOWN);
            } else if (System.nanoTime() - start >= limit.toNanos()) {
                expiry.expire(Expiry.LIMIT);
            }
        }, POLL_MILLIS, POLL_MILLIS, TimeUnit.MILLISECONDS);
        try {
            publication.run();
        } catch (SQLException | RuntimeException e) {
            String reason = expiry.finish();
            if (reason == Expiry.ABORT) {
                throw new ExpiredException("Writing " + what + " to ClickHouse stopped because the migration is"
                    + " stopping: " + ClickHouseRowSink.describe(e), e);
            }
            if (reason == Expiry.SHUTDOWN) {
                throw new ExpiredException("Writing " + what + " to ClickHouse stopped because the server is shutting"
                    + " down: " + ClickHouseRowSink.describe(e), e);
            }
            if (reason == Expiry.LIMIT) {
                throw new ExpiredException("Writing " + what + " to ClickHouse didn't succeed within "
                    + describe(limit) + " of retrying: " + ClickHouseRowSink.describe(e), e);
            }
            throw e;
        } finally {
            current = null;
            timer.cancel(false);
            expiry.finish();
        }
    }

    /**
     * Stop the publication running now, from any thread, and refuse every
     * publication from now on. Never throws.
     */
    void abort() {
        aborted = true;
        Expiry expiry = current;
        if (expiry != null) {
            expiry.expire(Expiry.ABORT);
        }
    }

    /**
     * An exception here would end the watchdog's checks, the limit's included
     */
    private boolean isShuttingDown() {
        try {
            return shuttingDown.getAsBoolean();
        } catch (RuntimeException | LinkageError e) {
            return false;
        }
    }

    private synchronized ScheduledExecutorService watchdog() {
        if (watchdog == null) {
            ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1, runnable -> {
                Thread thread = new Thread(runnable, "LibreProtect ClickHouse publication watchdog");
                thread.setDaemon(true);
                return thread;
            });
            executor.setRemoveOnCancelPolicy(true);
            watchdog = executor;
        }
        return watchdog;
    }

    @Override
    public synchronized void close() {
        if (watchdog != null) {
            watchdog.shutdownNow();
            watchdog = null;
        }
    }

    static String describe(Duration duration) {
        long seconds = duration.getSeconds();
        if (seconds >= 60 && seconds % 60 == 0) {
            return seconds / 60 + (seconds == 60 ? " minute" : " minutes");
        }
        if (seconds >= 1) {
            return seconds + (seconds == 1 ? " second" : " seconds");
        }
        return duration.toMillis() + " ms";
    }

    /**
     * A publication that was stopped. Not worth retrying: CoreProtect already
     * retried it all that time, or the server or the migration is stopping.
     */
    static final class ExpiredException extends SQLNonTransientException {
        private static final long serialVersionUID = 1L;

        ExpiredException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Whether and why a publication was stopped. Interrupting and finishing
     * exclude each other, so the publishing thread is never interrupted
     * after the publication ends.
     */
    private static final class Expiry {
        static final String LIMIT = "limit";
        static final String SHUTDOWN = "shutdown";
        static final String ABORT = "abort";

        private final Thread thread;
        private boolean finished;
        private String reason;

        Expiry(Thread thread) {
            this.thread = thread;
        }

        synchronized void expire(String why) {
            if (!finished && reason == null) {
                reason = why;
                thread.interrupt();
            }
        }

        /**
         * Called by the publishing thread when the publication ends. Clears
         * the interrupt that expiring set, so the caller carries on with its
         * interrupt status as it was, apart from interrupts from elsewhere.
         *
         * @return why the publication was stopped, or {@code null} if it wasn't
         */
        synchronized String finish() {
            if (!finished) {
                finished = true;
                if (reason != null) {
                    Thread.interrupted();
                }
            }
            return reason;
        }
    }
}
