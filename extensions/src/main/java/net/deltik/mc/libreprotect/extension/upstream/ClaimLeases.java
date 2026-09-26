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
import net.deltik.mc.libreprotect.extension.purge.CooperativeGate;
import net.deltik.mc.libreprotect.extension.purge.Lease;
import net.deltik.mc.libreprotect.extension.purge.PurgeContext;
import net.deltik.mc.libreprotect.extension.purge.StopReason;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;

import java.sql.Connection;

/**
 * CoreProtect 25's background purge claims: each unit of work claims a
 * background purge, which makes manual purges, rollbacks and reloads wait,
 * and releases it on the same thread right after. CoreProtect's shutdown
 * waits for a claim to be released, so stopping doesn't wait. A claim
 * refused because a manual purge is running is the only sign of one, and
 * stops the purge; one refused for a rollback or reload waits and retries.
 * An exclusive claim also takes CoreProtect's database write lock, which
 * the consumer and every new connection wait for, and waits for open
 * connections to close.
 *
 * <p>On SQLite, each unit of work also holds the consumer's pause gate,
 * taken only while the claim is held, so that shutdown, which waits for the
 * claim, never finds the gate held.
 */
final class ClaimLeases extends Leases {

    /** How long a unit of work waits, before claiming, for the consumer or a lookup to let go of the gate */
    private static final long GATE_WAIT_MILLIS = 10_000;
    /** How long a unit of work holding a claim waits for the gate */
    private static final long CLAIMED_GATE_WAIT_MILLIS = 250;
    /** How long an exclusive claim waits for other connections to close; everything else waits meanwhile */
    private static final long DRAIN_WAIT_MILLIS = 250;

    private final StaticMethod<?, RuntimeException> claim;
    private final StaticMethod<Void, RuntimeException> release;
    private final StaticMethod<Boolean, InterruptedException> awaitDrain;
    private final StaticMethod<Connection, RuntimeException> connection;
    private final CooperativeGate gate;

    ClaimLeases(Upstream upstream) throws Missing {
        UpstreamClass consumer = upstream.type(Names.CONSUMER);
        claim = consumer.staticMethod("claimBackgroundPurge", Object.class, boolean.class);
        upstream.type(claim.returnType()).asEnum().require(StartResult.Kind.STARTED.name());
        release = consumer.staticMethod("releaseBackgroundPurge", void.class);
        StaticField isPaused = consumer.writableStaticField("isPaused", boolean.class);
        StaticMethod<Boolean, RuntimeException> halted = consumer.staticMethod("isPersistenceHalted", boolean.class);
        UpstreamClass database = upstream.type(Names.DATABASE);
        awaitDrain = database.staticMethod("awaitConnectionDrain", boolean.class, long.class)
            .throwing(InterruptedException.class);
        connection = database.staticMethod("getConnection", Connection.class, boolean.class, int.class);
        // As CoreProtect's lookups do: a halt keeps the consumer paused
        gate = gate(isPaused, halted::call);

        upstream.relyOn("refuses while a manual purge, a rollback, a database reload or a persistence halt is on,"
            + " and otherwise marks a background purge running, which those refuse to start alongside; with true, it"
            + " also takes the database write lock on the calling thread, which connections and the consumer's"
            + " batches wait for", claim);
        upstream.relyOn("clears the background purge mark, and unlocks an exclusive claim's write lock, which only"
            + " the thread that took it can", release);
        upstream.relyOn("refuses a rollback while a manual purge or a background purge claim is held",
            Names.CONSUMER, "claimRollback(Ljava/lang/String;Z)" + Names.descriptor(Names.OPERATION_START_RESULT));
        upstream.relyOn("refuses a database reload while a manual purge or a background purge claim is held",
            Names.CONSUMER, "beginDatabaseReload()" + Names.descriptor(Names.OPERATION_START_RESULT));
        upstream.relyOn("refuses a database recovery while a manual purge or a background purge claim is held",
            Names.CONSUMER, "beginDatabaseRecovery()" + Names.descriptor(Names.OPERATION_START_RESULT));
        upstream.relyOn("refuses a manual purge while a background purge claim is held", Names.CONSUMER,
            "claimPurge()" + Names.descriptor(Names.OPERATION_START_RESULT));
        upstream.relyOn("returns once every connection it handed out is closed, or false after the timeout",
            awaitDrain);
        upstream.relyOn("passes the request on to getConnection(boolean, boolean, boolean, int)", connection);
        upstream.relyOn("takes the database read lock through Consumer.lockDatabaseAccess, tracks the connection it"
            + " gives until it's closed, and with force doesn't wait for the consumer's pause gate on SQLite",
            Names.DATABASE, "getConnection(ZZZI)Ljava/sql/Connection;");
        upstream.relyOn("takes the database read lock, which an exclusive claim's write lock holds off",
            Names.CONSUMER, "lockDatabaseAccess()V");
        upstream.relyOn("gives the database read lock back", Names.CONSUMER, "unlockDatabaseAccess()V");
        upstream.relyOn("waits between batches while isPaused is set", Names.CONSUMER, "pauseConsumer(I)V");
        upstream.relyOn("writes each batch under the database read lock, which an exclusive claim's write lock"
            + " holds off, and none while isPaused is set", Names.CONSUMER, "processConsumerBatch(IZ)V");
        upstream.relyOn("claims its purge through Consumer.claimPurge, which refuses while a background purge claim"
            + " is held, before it changes the database, and keeps its worker running until it's done",
            Names.PURGE_COMMAND + "$1BasicThread", "run()V");
        upstream.relyOn("stops background services, then waits for maintenance to complete before it closes the"
            + " database", Names.SHUTDOWN_SERVICE, "safeShutdown(Lorg/bukkit/plugin/Plugin;)V");
        upstream.relyOn("waits, for up to 15 minutes, while a background purge claim or purgeRunning is held",
            Names.SHUTDOWN_SERVICE, "waitForMaintenanceCompletion(J)V");
    }

    /**
     * Wait for the gate before claiming, so the claim isn't held while
     * waiting; claim; check again what the claim doesn't; then, for an
     * exclusive claim, wait for other connections to close, and on SQLite
     * take the gate.
     */
    @Override
    public Lease lease(PurgeContext context, boolean gated, boolean exclusive, Stops stops)
        throws InterruptedException {
        StopReason reason = stops.check(false);
        if (reason != null) {
            return Lease.stop(reason);
        }
        if (gated && !exclusive && !gate.awaitFree(context, GATE_WAIT_MILLIS)) {
            return Lease.busy(GATE_BUSY);
        }
        StartResult claimed = StartResult.of(exclusive
            ? context.interruptibly(() -> claim.call(true))
            : claim.call(false));
        if (!claimed.started()) {
            return refused(claimed, context);
        }
        boolean holdsGate = false;
        boolean granted = false;
        try {
            // The claim doesn't check these
            reason = stops.check(false);
            if (reason != null) {
                return Lease.stop(reason);
            }
            if (exclusive && !context.interruptibly(() -> awaitDrain.call(DRAIN_WAIT_MILLIS))) {
                return Lease.busy("other database connections are open");
            }
            if (gated) {
                holdsGate = gate.acquire(context, CLAIMED_GATE_WAIT_MILLIS);
                if (!holdsGate) {
                    return Lease.busy(GATE_BUSY);
                }
            }
            // With the gate, forced past CoreProtect's own wait for it
            Connection opened = connection.call(gated, CONNECTION_WAIT_MILLIS);
            if (opened == null) {
                return Lease.busy(NO_CONNECTION);
            }
            boolean releaseGate = holdsGate;
            Lease lease = Lease.granted(opened, () -> release(opened, releaseGate));
            granted = true;
            return lease;
        } finally {
            if (!granted) {
                try {
                    if (holdsGate) {
                        gate.release();
                    }
                } finally {
                    releaseClaim();
                }
            }
        }
    }

    /**
     * @return what a refused claim means for the purge; for one of
     *         CoreProtect's claims, background or not
     */
    static Lease refused(StartResult result, PurgeContext context) {
        switch (result.kind()) {
            case PURGE_RUNNING:
                return Lease.stop(StopReason.MANUAL_PURGE);
            case PERSISTENCE_HALTED:
                return Lease.stop(StopReason.PERSISTENCE_HALTED);
            case ROLLBACK_RUNNING:
                return Lease.busy("a rollback is running");
            case RELOAD_RUNNING:
                return Lease.busy("CoreProtect is reloading the database");
            case INTERRUPTED:
                // Only a stop interrupts the purge while it waits for the lock
                return context.stopRequested() ? Lease.stop(StopReason.SHUTDOWN) : Lease.busy("interrupted");
            default:
                // An answer of a newer CoreProtect's, whose meaning isn't known, unless the purge is stopping anyway
                return context.stopRequested() ? Lease.stop(StopReason.SHUTDOWN)
                    : Lease.stop(StopReason.DATABASE_BUSY, "CoreProtect refused a purge claim with " + result.name());
        }
    }

    private void release(Connection opened, boolean holdsGate) {
        try {
            close(opened);
        } finally {
            try {
                if (holdsGate) {
                    gate.release();
                }
            } finally {
                releaseClaim();
            }
        }
    }

    /**
     * Give back the claim. Only ever on the thread that took it: an
     * exclusive claim holds a lock that only that thread can unlock, and a
     * failed release would leave every purge, rollback and reload refused,
     * and shutdown waiting for 15 minutes.
     */
    private void releaseClaim() {
        try {
            release.call();
        } catch (RuntimeException e) {
            LibreProtectLogger.severe("Auto-purge couldn't release its database claim: " + e);
        }
    }

    @Override
    public boolean exclusive() {
        return true;
    }

    /**
     * CoreProtect's shutdown waits for a claim to be released itself.
     */
    @Override
    public long stopTimeoutMillis() {
        return 0;
    }

    @Override
    public void abandon() {
        gate.release();
    }
}
