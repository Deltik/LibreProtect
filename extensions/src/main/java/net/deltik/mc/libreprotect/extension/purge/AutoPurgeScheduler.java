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

import net.deltik.mc.libreprotect.extension.common.Engine;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

/**
 * The auto-purge thread: waits for the daily run time, purges, and repeats.
 *
 * <p>It rereads the settings at least once a minute, because
 * {@code /co reload} changes them without restarting background services.
 * It uses a plain daemon thread rather than the server's scheduler, which
 * Folia doesn't have, and never waits for the server thread.
 */
final class AutoPurgeScheduler implements Runnable {

    static final String THREAD_NAME = "LibreProtect auto-purge";
    /** How often the settings are reread while waiting */
    static final long POLL_MILLIS = 60_000;

    private final PurgeBridge bridge;
    private final PurgeLog log;
    private final Clock clock;
    private final Supplier<ZoneId> zones;
    private final long pollMillis;
    private final PurgeContext context = new PurgeContext();
    private final Thread thread;
    private final Object requests = new Object();
    private Request request;
    private boolean finished;

    // Used by the thread that calls start(), then by the auto-purge thread
    private AutoPurgeSettings settings;
    private ZoneId zone;
    private ZonedDateTime nextRun;
    private boolean orphansPending;
    private String warnedRetention;
    private String warnedTime;
    private boolean warnedDatabaseLock;
    private String warnedUnavailable;
    private String warnedUnreadable;

    /**
     * @param zones the server's time zone, read again at every poll
     * @param pollMillis how often to reread the settings while waiting
     */
    AutoPurgeScheduler(PurgeBridge bridge, PurgeLog log, Clock clock, Supplier<ZoneId> zones, long pollMillis) {
        this.bridge = Objects.requireNonNull(bridge, "bridge");
        this.log = Objects.requireNonNull(log, "log");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.zones = Objects.requireNonNull(zones, "zones");
        this.pollMillis = pollMillis;
        this.thread = new Thread(this, THREAD_NAME);
        thread.setDaemon(true);
        context.bind(thread);
    }

    /**
     * Read the settings, log the schedule, and start the thread.
     */
    void start() {
        settings = readSettings();
        zone = zones.get();
        nextRun = scheduleFrom(clock.instant());
        announce(false);
        thread.start();
    }

    /**
     * Stop the thread and any purge in progress. Waits for them only as long
     * as the bridge says; CoreProtect 25 itself waits for its claims.
     */
    void stop() {
        context.requestStop();
        long timeout = bridge.stopTimeoutMillis();
        if (timeout <= 0 || !thread.isAlive() || Thread.currentThread() == thread) {
            return;
        }
        try {
            thread.join(timeout);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (thread.isAlive()) {
            long seconds = (timeout + 999) / 1000;
            log.warning("Auto-purge didn't stop within " + seconds + (seconds == 1 ? " second" : " seconds")
                + ". Shutdown goes on without it.");
            bridge.abandon();
        }
    }

    /**
     * @return whether a stop was requested
     */
    boolean stopRequested() {
        return context.stopRequested();
    }

    /**
     * @return whether the thread is still running
     */
    boolean isAlive() {
        return thread.isAlive();
    }

    /**
     * Have the auto-purge thread purge now, with the given cutoff and no
     * minimum retention, and wait until it's done. Every stop rule applies.
     * Must not be called on the server thread.
     *
     * @return rows removed
     * @throws IllegalStateException if the purge stopped early or auto-purge isn't running
     * @throws TimeoutException if the purge didn't finish in time
     */
    long runNow(long cutoff, long timeoutMillis) throws InterruptedException, TimeoutException {
        Request pending = new Request(cutoff);
        synchronized (requests) {
            if (finished || context.stopRequested()) {
                throw new IllegalStateException("Auto-purge isn't running");
            }
            if (request != null) {
                throw new IllegalStateException("Another purge was requested already");
            }
            request = pending;
        }
        context.wake();
        PurgeResult result = pending.await(timeoutMillis);
        if (!result.completed()) {
            throw new IllegalStateException("Auto-purge stopped because " + because(result) + " after removing "
                + rows(result.removed()));
        }
        return result.removed();
    }

    @Override
    public void run() {
        try {
            while (!context.stopRequested()) {
                // Read before looking for a request, so that a request's wake-up can't slip in unseen
                long wakeups = context.wakeups();
                Request requested = takeRequest();
                if (requested != null) {
                    refresh();
                    PurgeResult result = purge(requested.cutoff, clock.instant().getEpochSecond());
                    report(result);
                    requested.complete(result);
                    continue;
                }
                refresh();
                Instant now = clock.instant();
                if (nextRun != null && !now.isBefore(nextRun.toInstant())) {
                    long seconds = now.getEpochSecond();
                    PurgeResult result = purge(seconds - settings.retentionSeconds(), seconds);
                    nextRun = scheduleFrom(clock.instant());
                    report(result);
                    continue;
                }
                long wait = pollMillis;
                if (nextRun != null) {
                    wait = Math.max(1, Math.min(wait, nextRun.toInstant().toEpochMilli() - now.toEpochMilli()));
                }
                context.idle(wait, wakeups);
            }
        } catch (InterruptedException e) {
            // Only a stop interrupts this thread
        } catch (RuntimeException | LinkageError e) {
            log.warning("Auto-purge stopped working until the next restart: " + e);
        } finally {
            Request abandoned;
            synchronized (requests) {
                finished = true;
                abandoned = request;
                request = null;
            }
            if (abandoned != null) {
                abandoned.complete(new PurgeResult(0, StopReason.SHUTDOWN, null, 0, false));
            }
        }
    }

    /**
     * Purge rows older than {@code cutoff}. Stops early if {@code auto-purge}
     * changes, since the cutoff came from it.
     *
     * @param now the server's time as the run starts, in Unix seconds
     */
    private PurgeResult purge(long cutoff, long now) {
        long retention = settings.retentionSeconds();
        // The cutoff comes from the server's clock; showing it makes a wrong clock visible
        log.info("Auto-purge is removing data from before "
            + Schedule.describe(Instant.ofEpochSecond(cutoff).atZone(zone)) + ".");
        PurgeResult result;
        try {
            ChunkedPurge purge = new ChunkedPurge(bridge, context, log, () -> {
                AutoPurgeSettings latest = readSettingsQuietly();
                return latest != null && latest.retentionSeconds() != retention ? StopReason.SETTINGS_CHANGED : null;
            }, cutoff, now);
            result = purge.run(orphansPending);
        } catch (RuntimeException e) {
            result = new PurgeResult(0, StopReason.ERROR, e.toString(), 0, false);
        }
        // Unless there are known to be none, as on CoreProtect 24
        orphansPending = !result.orphansCleaned() && (orphansPending || result.removed() > 0)
            && !Boolean.FALSE.equals(bridge.entitySpawnTracking());
        return result;
    }

    private void report(PurgeResult result) {
        String next = nextRun == null ? null : Schedule.describe(nextRun);
        if (result.completed()) {
            log.info("Auto-purge removed " + rows(result.removed()) + " in " + describeDuration(result.elapsedMillis())
                + "." + (next == null ? "" : " Next run: " + next + "."));
            return;
        }
        StringBuilder message = new StringBuilder("Auto-purge stopped because ").append(because(result));
        if (result.removed() > 0) {
            message.append(", after removing ").append(rows(result.removed()));
        }
        message.append(". It continues at the next ").append(next == null || result.stopReason() == StopReason.SHUTDOWN
            ? "scheduled run." : "run: " + next + ".");
        StopReason reason = result.stopReason();
        if (reason == StopReason.ERROR || reason == StopReason.DATABASE_BUSY
            || reason == StopReason.DATABASE_LOCK_DISABLED || reason == StopReason.DATABASE_RECOVERY
            || reason == StopReason.UNSUPPORTED_DATABASE) {
            log.warning(message.toString());
        } else {
            log.info(message.toString());
        }
    }

    /**
     * Reread the settings and time zone, and reschedule and log if they changed.
     */
    private void refresh() {
        AutoPurgeSettings latest = readSettingsQuietly();
        ZoneId currentZone = zones.get();
        if (latest == null || (latest.sameValues(settings) && currentZone.equals(zone))) {
            return;
        }
        boolean wasEnabled = settings.enabled();
        settings = latest;
        zone = currentZone;
        nextRun = scheduleFrom(clock.instant());
        announce(wasEnabled);
    }

    /**
     * Log the schedule and any problems with the settings. Each problem is
     * logged once, until the setting changes.
     */
    private void announce(boolean wasEnabled) {
        // Whether auto-purge is on can't be told then, so this is said either way
        String unreadable = reason(bridge::settingsUnavailableReason);
        if (unreadable != null && !unreadable.equals(warnedUnreadable)) {
            log.warning("Auto-purge can't read its settings with this CoreProtect build: " + unreadable + ".");
        }
        warnedUnreadable = unreadable;

        String retentionProblem = settings.retentionProblem();
        if (retentionProblem == null) {
            warnedRetention = null;
        } else if (!Objects.equals(settings.retentionValue(), warnedRetention)) {
            warnedRetention = settings.retentionValue();
            log.warning(retentionProblem);
        }
        if (!settings.enabled()) {
            if (wasEnabled && retentionProblem == null) {
                log.info("Auto-purge is off.");
            }
            return;
        }

        String timeProblem = settings.timeProblem();
        if (timeProblem == null) {
            warnedTime = null;
        } else if (!Objects.equals(settings.timeValue(), warnedTime)) {
            warnedTime = settings.timeValue();
            log.warning(timeProblem);
        }

        // A run that can't happen isn't announced
        String unavailable = reason(bridge::unavailableReason);
        if (unavailable != null) {
            if (!unavailable.equals(warnedUnavailable)) {
                log.warning("Auto-purge won't work with this CoreProtect build: " + unavailable + ".");
            }
            warnedUnavailable = unavailable;
            return;
        }
        warnedUnavailable = null;
        log.info("Auto-purge keeps " + AutoPurgeSettings.describeRetention(settings.retentionSeconds())
            + " of data. Next run: " + Schedule.describe(nextRun) + ".");

        boolean databaseLockMissing = false;
        try {
            databaseLockMissing = bridge.activeEngine() == Engine.CLICKHOUSE && !bridge.databaseLock();
        } catch (RuntimeException e) {
            // Checked again when the purge runs
        }
        if (databaseLockMissing && !warnedDatabaseLock) {
            log.warning("Auto-purge can't run on ClickHouse while database-lock is disabled in CoreProtect's "
                + "config.yml. Set database-lock: true there, then restart the server or use /co reload.");
        }
        warnedDatabaseLock = databaseLockMissing;
    }

    /**
     * @return a reason from the bridge, or {@code null} if it has none or
     *         can't tell now; each run says why it stops
     */
    private static String reason(Supplier<String> reason) {
        try {
            return reason.get();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private ZonedDateTime scheduleFrom(Instant after) {
        return settings.enabled() ? Schedule.nextRun(after, settings.time(), zone) : null;
    }

    private AutoPurgeSettings readSettings() {
        return AutoPurgeSettings.of(bridge.retentionSetting(), bridge.timeSetting());
    }

    /**
     * @return the settings, or {@code null} if CoreProtect's config can't be read right now
     */
    private AutoPurgeSettings readSettingsQuietly() {
        try {
            return readSettings();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private Request takeRequest() {
        synchronized (requests) {
            Request taken = request;
            request = null;
            return taken;
        }
    }

    private static String because(PurgeResult result) {
        return result.stopReason().because() + (result.detail() == null ? "" : " (" + result.detail() + ")");
    }

    static String rows(long rows) {
        return String.format(Locale.ROOT, "%,d %s", rows, rows == 1 ? "row" : "rows");
    }

    /**
     * @return a duration for messages, such as "42 s" or "3 min 5 s"
     */
    static String describeDuration(long millis) {
        long seconds = millis / 1000;
        if (seconds == 0) {
            return "less than a second";
        }
        if (seconds < 60) {
            return seconds + " s";
        }
        if (seconds < 3600) {
            return seconds / 60 + " min " + seconds % 60 + " s";
        }
        return seconds / 3600 + " h " + seconds % 3600 / 60 + " min";
    }

    /** A purge requested through {@link #runNow} */
    private static final class Request {
        final long cutoff;
        private PurgeResult result;

        Request(long cutoff) {
            this.cutoff = cutoff;
        }

        synchronized void complete(PurgeResult result) {
            this.result = result;
            notifyAll();
        }

        synchronized PurgeResult await(long timeoutMillis) throws InterruptedException, TimeoutException {
            long deadline = System.nanoTime() + timeoutMillis * 1_000_000L;
            long remaining;
            while (result == null) {
                remaining = (deadline - System.nanoTime()) / 1_000_000L;
                if (remaining <= 0) {
                    throw new TimeoutException("The purge didn't finish within " + timeoutMillis + " ms");
                }
                wait(remaining);
            }
            return result;
        }
    }
}
