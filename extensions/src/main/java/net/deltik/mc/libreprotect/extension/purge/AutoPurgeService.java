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

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.extension.upstream.CoreProtectPurge;

import java.time.Clock;
import java.time.ZoneId;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Automatic purging: deletes CoreProtect data older than {@code auto-purge}
 * once a day at {@code auto-purge-time}, in small chunks, while the server
 * keeps running.
 *
 * <p>A purge stops safely when the server shuts down, a manual purge starts,
 * a database migration or conversion starts, or the consumer is paused, and
 * continues at the next scheduled run. See {@link ChunkedPurge} for how rows
 * are removed and {@link AutoPurgeScheduler} for when.
 */
public final class AutoPurgeService {

    /** How long {@link #runNow} waits for its purge */
    private static final long RUN_NOW_TIMEOUT_MILLIS = TimeUnit.MINUTES.toMillis(5);
    /** The name of the thread that probes CoreProtect, then starts the schedule */
    static final String STARTER_NAME = "LibreProtect auto-purge start";

    private static final Object LOCK = new Object();
    private static AutoPurgeScheduler scheduler;
    /** The thread that starts the schedule last, or {@code null} */
    private static Thread starting;
    /** How often it was stopped, so that a start that probes meanwhile doesn't start the schedule after a stop */
    private static long stops;

    private AutoPurgeService() {
    }

    /**
     * Start the schedule, on a thread of its own that probes CoreProtect
     * first, off the server's thread. Does nothing if it is running already.
     * Never throws.
     */
    public static void start() {
        try {
            start(CoreProtectPurge::create, PurgeLog.CONSOLE, Clock.systemUTC(), AutoPurgeScheduler.POLL_MILLIS);
        } catch (Throwable e) {
            LibreProtectLogger.warning("Auto-purge couldn't start: " + e);
        }
    }

    /**
     * Get the bridge on a thread of its own, then start the schedule with it,
     * unless it runs already, or a stop came meanwhile.
     *
     * @param bridges gives the bridge, such as by probing CoreProtect
     * @return the thread that starts the schedule, or {@code null} if it
     *         runs already
     */
    static Thread start(Supplier<PurgeBridge> bridges, PurgeLog log, Clock clock, long pollMillis) {
        synchronized (LOCK) {
            if (scheduler != null && !scheduler.stopRequested()) {
                return null;
            }
            long generation = stops;
            Thread starter = new Thread(() -> {
                try {
                    PurgeBridge bridge = bridges.get();
                    synchronized (LOCK) {
                        if (stops == generation) {
                            start(bridge, log, clock, pollMillis);
                        }
                    }
                } catch (Throwable e) {
                    LibreProtectLogger.warning("Auto-purge couldn't start: " + e);
                }
            }, STARTER_NAME);
            starter.setDaemon(true);
            starting = starter;
            starter.start();
            return starter;
        }
    }

    /**
     * Start the schedule with this bridge now, unless it runs already.
     */
    static void start(PurgeBridge bridge, PurgeLog log, Clock clock, long pollMillis) {
        synchronized (LOCK) {
            if (scheduler != null && !scheduler.stopRequested()) {
                return;
            }
            AutoPurgeScheduler started = new AutoPurgeScheduler(bridge, log, clock, ZoneId::systemDefault, pollMillis);
            started.start();
            scheduler = started;
        }
    }

    /**
     * Stop the schedule and any purge in progress, and keep a start that is
     * still probing CoreProtect from starting it. Never throws, and is safe
     * to call without {@link #start()} or more than once.
     *
     * <p>On CoreProtect 24, nothing else waits for a purge before the
     * database closes, so this waits up to 10 seconds for it to end. On
     * CoreProtect 25, shutdown waits for the purge's claim itself, so this
     * returns at once.
     */
    public static void stop() {
        try {
            AutoPurgeScheduler stopping;
            synchronized (LOCK) {
                stops++;
                stopping = scheduler;
            }
            if (stopping != null) {
                stopping.stop();
            }
        } catch (Throwable e) {
            LibreProtectLogger.warning("Auto-purge couldn't stop cleanly: " + e);
        }
    }

    /**
     * Purge rows older than {@code cutoffEpochSeconds} now, on the auto-purge
     * thread, and wait for it, once the schedule has started. Every stop rule
     * applies, but the 30-day minimum doesn't. For LibreProtect's integration
     * test, which reaches this by reflection; never call it on the server
     * thread.
     *
     * <p>Package-private keeps it out of any API, but reflection reaches it
     * from any plugin. That gives a plugin nothing new: it can purge any
     * amount of data by dispatching {@code /co purge} as the console, or
     * through {@code CoreProtectAPI.performPurge}.
     *
     * @return rows removed
     * @throws IllegalStateException if auto-purge isn't running or the purge stopped early
     */
    static long runNow(long cutoffEpochSeconds) throws Exception {
        Thread pending;
        synchronized (LOCK) {
            pending = starting;
        }
        if (pending != null) {
            pending.join(RUN_NOW_TIMEOUT_MILLIS);
        }
        AutoPurgeScheduler current;
        synchronized (LOCK) {
            current = scheduler;
        }
        if (current == null) {
            throw new IllegalStateException("Auto-purge isn't running");
        }
        return current.runNow(cutoffEpochSeconds, RUN_NOW_TIMEOUT_MILLIS);
    }
}
