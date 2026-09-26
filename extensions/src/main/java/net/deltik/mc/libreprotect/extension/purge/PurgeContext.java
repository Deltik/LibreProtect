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

import java.sql.Statement;

/**
 * The auto-purge worker thread's side of stopping: a stop flag, waits that
 * end as soon as it's set, and the statement to cancel.
 *
 * <p>Stopping interrupts the worker only while it is inside
 * {@link #interruptibly}. Elsewhere it may be inside a JDBC driver or
 * CoreProtect's connection pool, where an interrupt is reported as a failed
 * connection instead of a stop; those get their statement canceled instead.
 */
public final class PurgeContext {

    /** Work for {@link #interruptibly}, such as taking a lock */
    @FunctionalInterface
    public interface Interruptible<T> {
        T call() throws InterruptedException;
    }

    private final Object monitor = new Object();
    private volatile boolean stopRequested;
    private volatile Statement activeStatement;
    private Thread worker;
    private boolean interruptible;
    private long wakeups;

    /**
     * @return whether the purge must stop
     */
    public boolean stopRequested() {
        return stopRequested;
    }

    /**
     * Wait, returning early once a stop is requested.
     */
    public void pause(long millis) throws InterruptedException {
        long deadline = System.nanoTime() + millis * 1_000_000L;
        synchronized (monitor) {
            long remaining;
            while (!stopRequested && (remaining = (deadline - System.nanoTime()) / 1_000_000L) > 0) {
                monitor.wait(remaining);
            }
        }
    }

    /**
     * Run a blocking call that a stop may interrupt, such as taking a lock.
     * An interrupt never outlives the call.
     *
     * @throws InterruptedException if the call was interrupted, or a stop was requested before it started
     */
    public <T> T interruptibly(Interruptible<T> action) throws InterruptedException {
        synchronized (monitor) {
            if (stopRequested) {
                throw new InterruptedException("Auto-purge is stopping");
            }
            interruptible = true;
        }
        try {
            return action.call();
        } finally {
            synchronized (monitor) {
                interruptible = false;
                // A stop's interrupt is delivered under the monitor, so this clears any that arrived
                Thread.interrupted();
            }
        }
    }

    /**
     * @return a count of {@link #wake} calls, for {@link #idle}
     */
    long wakeups() {
        synchronized (monitor) {
            return wakeups;
        }
    }

    /**
     * Wait until the time passes, a stop is requested or {@link #wake} is
     * called. A wake since {@code seen} was read counts, so one that arrives
     * while the caller is busy between reading it and waiting isn't lost.
     *
     * @param seen what {@link #wakeups} returned before the caller last looked for work
     */
    void idle(long millis, long seen) throws InterruptedException {
        long deadline = System.nanoTime() + millis * 1_000_000L;
        synchronized (monitor) {
            long remaining;
            while (!stopRequested && wakeups == seen && (remaining = (deadline - System.nanoTime()) / 1_000_000L) > 0) {
                monitor.wait(remaining);
            }
        }
    }

    /**
     * End an {@link #idle} wait early.
     */
    void wake() {
        synchronized (monitor) {
            wakeups++;
            monitor.notifyAll();
        }
    }

    /**
     * Name the thread that {@link #requestStop} interrupts.
     */
    void bind(Thread worker) {
        synchronized (monitor) {
            this.worker = worker;
        }
    }

    /**
     * Ask the worker to stop: set the flag, end its waits, and cancel its
     * statement. Returns at once.
     */
    void requestStop() {
        synchronized (monitor) {
            stopRequested = true;
            monitor.notifyAll();
            if (interruptible && worker != null) {
                worker.interrupt();
            }
        }
        Statement statement = activeStatement;
        if (statement != null) {
            cancel(statement);
        }
    }

    /**
     * Note the statement that is running, so a stop can cancel it.
     */
    void track(Statement statement) {
        activeStatement = statement;
        if (statement != null && stopRequested) {
            cancel(statement);
        }
    }

    void untrack() {
        activeStatement = null;
    }

    /**
     * Cancel off the calling thread: MySQL's driver opens a connection to
     * cancel, and the server thread must not wait for that.
     */
    private static void cancel(Statement statement) {
        Thread canceler = new Thread(() -> {
            try {
                statement.cancel();
            } catch (Throwable e) {
                // The statement finished or its connection closed: nothing left to cancel
            }
        }, "LibreProtect auto-purge cancel");
        canceler.setDaemon(true);
        canceler.start();
    }
}
