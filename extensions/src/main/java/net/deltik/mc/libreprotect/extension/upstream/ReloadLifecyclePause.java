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

import net.deltik.mc.libreprotect.extension.common.PurgeChunkLock;
import net.deltik.mc.libreprotect.extension.migration.MigrationException;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;

import java.util.concurrent.Future;
import java.util.function.Supplier;

/**
 * The pause of CoreProtect with a database reload lifecycle, such as
 * CoreProtect 25, as its docs describe for {@code /co migrate-db}: begin a
 * reload, which pauses persistence, once auto-purge lets go of the database;
 * take the reload's lock; and wait for open connections to close. The lock
 * belongs to the thread that took it, which is the only one that can
 * release it, so the hold ends the reload on that same thread. Until the
 * pause, CoreProtect keeps working, while the migration checks its target.
 *
 * <p>CoreProtect's shutdown blocks new reloads first and then waits for a
 * running one, so the migration watches for that and stops within seconds.
 */
final class ReloadLifecyclePause implements Pause {

    private static final long AUTO_PURGE_TIMEOUT_MILLIS = 10_000;
    private static final long RETRY_MILLIS = 100;
    private static final long PAUSE_TIMEOUT_MILLIS = 120_000;
    private static final long POLL_MILLIS = 250;

    private final StaticMethod<?, RuntimeException> begin;
    private final StaticMethod<Boolean, InterruptedException> lock;
    private final StaticMethod<Void, RuntimeException> end;
    private final StaticMethod<Void, RuntimeException> halt;
    private final StaticMethod<Boolean, RuntimeException> reloadRunning;
    private final StaticMethod<Boolean, RuntimeException> reloadPaused;
    private final StaticMethod<?, RuntimeException> shutdownSignal;
    private final StaticMethod<Boolean, InterruptedException> awaitDrain;
    private final Flags flags;
    private final Hooks.PurgeWorker purgeWorker;
    /** CoreProtect's recovery of DuckDB, or {@code null}; only a migration from DuckDB needs it (see {@link EngineSide}) */
    private final Hooks.DuckDBRecovery recovery;

    private ReloadLifecyclePause(Upstream upstream) throws Missing {
        UpstreamClass consumer = upstream.type(Names.CONSUMER);
        begin = consumer.staticMethod("beginDatabaseReload", Object.class);
        lock = consumer.staticMethod("lockDatabaseReload", boolean.class, long.class)
            .throwing(InterruptedException.class);
        end = consumer.staticMethod("endDatabaseReload", void.class, boolean.class);
        halt = consumer.staticMethod("haltPersistence", void.class);
        reloadRunning = consumer.staticMethod("isDatabaseReloadRunning", boolean.class);
        reloadPaused = consumer.staticMethod("isDatabaseReloadPaused", boolean.class);
        shutdownSignal = consumer.staticMethod("databaseReloadShutdownSignal", Future.class);
        awaitDrain = upstream.type(Names.DATABASE).staticMethod("awaitConnectionDrain", boolean.class, long.class)
            .throwing(InterruptedException.class);
        MigrationProtocol.need(upstream, StartResult.CAPABILITY);
        flags = MigrationProtocol.need(upstream, Flags.CAPABILITY);
        purgeWorker = MigrationProtocol.need(upstream, Hooks.PURGE_WORKER);
        recovery = MigrationProtocol.orNull(upstream, Hooks.DUCKDB_RECOVERY);

        upstream.relyOn("starts a reload that pauses persistence, unless shutdown, halted persistence, a reload, a"
            + " purge or a rollback is in the way", begin);
        upstream.relyOn("takes the database lifecycle's write lock for the calling thread, which keeps the"
            + " consumer's batches and other threads' connections out", lock);
        upstream.relyOn("releases the write lock only on the thread that holds it, and resumes persistence if asked",
            end);
        upstream.relyOn("stops saving events until CoreProtect restarts", halt);
        upstream.relyOn("gives a copy of the signal that completes once shutdown blocks reloads", shutdownSignal);
        upstream.relyOn("waits until every connection it handed out is closed", awaitDrain);
        upstream.relyOn("hands connections to the thread that holds the reload's write lock while persistence is"
            + " paused, and to no other", Names.DATABASE, "getConnection(ZZZI)Ljava/sql/Connection;");
        upstream.relyOn("tells every thread but the one that holds the reload's write lock that the database is"
            + " blocked while persistence is paused", Names.CONSUMER, "isDatabaseReloadBlocked()Z");
        upstream.relyOn("blocks new reloads first, waits for a running one, and then while migrationRunning is set",
            Names.SHUTDOWN_SERVICE, "safeShutdown(Lorg/bukkit/plugin/Plugin;)V");
        upstream.relyOn("waits while a database reload runs", Names.SHUTDOWN_SERVICE, "waitForMaintenanceCompletion(J)V");
    }

    static ReloadLifecyclePause probe(Upstream upstream) throws Missing {
        return new ReloadLifecyclePause(upstream);
    }

    /**
     * A purge that someone started refuses the migration: it sets
     * {@code purgeRunning} and runs a worker of its own. Auto-purge only
     * claims the database for a moment per chunk, which the pause waits for.
     */
    @Override
    public String refusal() {
        if (manualPurgeRunning()) {
            return StartResult.of(StartResult.Kind.PURGE_RUNNING.name()).refusal();
        }
        if (reloadRunning.call() || reloadPaused.call() || (recovery != null && recovery.pending())) {
            return "CoreProtect is reloading or recovering its database. Wait for it to finish.";
        }
        return null;
    }

    @Override
    public Future<?> shutdownSignal() {
        return (Future<?>) shutdownSignal.call();
    }

    @Override
    public Hold hold(Supplier<String> stopReason) {
        return new ReloadHold(stopReason);
    }

    @Override
    public boolean haltPersistence() {
        halt.call();
        return true;
    }

    /**
     * @return whether a purge that someone started is running, as opposed to
     *         a chunk of auto-purge
     */
    private boolean manualPurgeRunning() {
        return flags.purgeRunning() || purgeWorker.running();
    }

    private final class ReloadHold extends Hold {
        private final Supplier<String> stopReason;
        private boolean reloading;
        private boolean released;

        ReloadHold(Supplier<String> stopReason) {
            this.stopReason = stopReason;
        }

        /**
         * Begin the reload, retrying for a few seconds while auto-purge holds
         * the database for a chunk; it stops once it sees
         * {@code migrationRunning}, and the pause waits for its chunk lock too.
         */
        @Override
        void doAcquire() throws MigrationException, InterruptedException {
            long autoPurgeDeadline = System.nanoTime() + AUTO_PURGE_TIMEOUT_MILLIS * 1_000_000L;
            while (!reloading) {
                StartResult result = StartResult.of(begin.call());
                if (result.started()) {
                    reloading = true;
                } else if (result.kind() != StartResult.Kind.PURGE_RUNNING || manualPurgeRunning()) {
                    throw new MigrationException(result.refusal());
                } else {
                    waitFor(autoPurgeDeadline, "Auto-purge didn't pause for the migration");
                    Thread.sleep(RETRY_MILLIS);
                }
            }
            long deadline = System.nanoTime() + PAUSE_TIMEOUT_MILLIS * 1_000_000L;
            // Auto-purge's claim already keeps its chunks out of the reload; this makes sure, as without the lifecycle
            while (!PurgeChunkLock.awaitNoChunk(POLL_MILLIS)) {
                waitFor(deadline, "Auto-purge didn't finish its current step");
            }
            while (!lock.call(POLL_MILLIS)) {
                waitFor(deadline, "CoreProtect's database work didn't finish");
            }
            while (!awaitDrain.call(POLL_MILLIS)) {
                waitFor(deadline, "CoreProtect's database connections didn't close");
            }
        }

        /**
         * End the reload that this hold began; one that it didn't begin is
         * someone else's to end.
         */
        @Override
        void doRelease(boolean resume) {
            if (reloading && !released) {
                released = true;
                end.call(resume);
            }
        }

        private void waitFor(long deadline, String timeout) throws MigrationException {
            String stop = stopReason.get();
            if (stop != null) {
                throw new MigrationException("The migration stopped because " + stop + ".");
            }
            if (System.nanoTime() > deadline) {
                throw new MigrationException(timeout + " in time. Try again in a moment.");
            }
        }
    }
}
