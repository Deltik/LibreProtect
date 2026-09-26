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
import java.util.Map;

/**
 * CoreProtect 24, which has no claims for background work: a purge watches
 * its lifecycle flags, which say that a manual purge, migration or
 * conversion started, the consumer was paused or the server is stopping,
 * and never sets them. Setting {@code purgeRunning} would make its shutdown
 * skip draining the consumer's queue. Its shutdown doesn't wait for the
 * purge either, so stopping does, for a while.
 *
 * <p>A manual purge that starts during a unit of work overlaps it: it sets
 * {@code purgeRunning} and takes the gate without waiting for it. On SQLite
 * it then copies the rows to keep into a new file and swaps that in. The
 * work's deletes, all older than the cutoff, either reach the copy or are
 * lost with the old file, and the next unit sees {@code purgeRunning} and
 * stops. At worst, rows the work removed come back with the copy and wait
 * for the next run.
 *
 * <p>No lease is exclusive: CoreProtect 24 has no entity tracking to clean
 * up after, nor DuckDB to checkpoint.
 */
final class CooperativeLeases extends Leases {

    /** How long a unit of work waits for the consumer or a lookup to let go of the gate */
    private static final long GATE_WAIT_MILLIS = 10_000;
    /** Shutdown closes the database right after stopping the purge, so it waits this long for the purge */
    private static final long STOP_TIMEOUT_MILLIS = 10_000;

    private final StaticField activeRollbacks;
    private final StaticMethod<Connection, RuntimeException> connection;
    private final CooperativeGate gate;

    CooperativeLeases(Upstream upstream) throws Missing {
        // The flags it takes turns by, which the purge's stops read
        Flags.CAPABILITY.probe(upstream).require();
        activeRollbacks = upstream.type(Names.CONFIG_HANDLER).staticField("activeRollbacks", Map.class);
        UpstreamClass consumer = upstream.type(Names.CONSUMER);
        gate = gate(consumer.writableStaticField("isPaused", boolean.class), null);
        connection = upstream.type(Names.DATABASE).staticMethod("getConnection", Connection.class, boolean.class,
            int.class);

        upstream.relyOn("waits before each batch while isPaused, pauseConsumer or purgeRunning is set",
            Names.CONSUMER, "pauseConsumer(I)V");
        upstream.relyOn("passes the request on to getConnection(boolean, boolean, boolean, int)", connection);
        upstream.relyOn("with force, doesn't wait for the consumer's pause gate on SQLite", Names.DATABASE,
            "getConnection(ZZZI)Ljava/sql/Connection;");
        upstream.relyOn("sets purgeRunning before it changes the database, and on SQLite moves a rebuilt file over"
            + " the database before it clears purgeRunning", Names.PURGE_COMMAND + "$1BasicThread", "run()V");
        upstream.relyOn("marks the rollback in activeRollbacks before its thread starts", Names.ROLLBACK_RESTORE_COMMAND,
            "runCommand(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Z[Ljava/lang/String;"
                + "Lorg/bukkit/Location;JJ)V");
        upstream.relyOn("removes the rollback from activeRollbacks once it's done",
            Names.ROLLBACK_RESTORE_COMMAND + "$1BasicThread2", "run()V");
        upstream.relyOn("stops background services first, then closes the database once its consumer is done,"
            + " waiting for nothing they run", Names.SHUTDOWN_SERVICE, "safeShutdown(Lorg/bukkit/plugin/Plugin;)V");
    }

    /**
     * Wait for rollbacks, hold the gate on SQLite, then open a connection.
     */
    @Override
    public Lease lease(PurgeContext context, boolean gated, boolean exclusive, Stops stops)
        throws InterruptedException {
        StopReason reason = stops.check(false);
        if (reason != null) {
            return Lease.stop(reason);
        }
        if (exclusive) {
            return Lease.stop(StopReason.UNSUPPORTED_DATABASE, "CoreProtect has no claims that keep every other"
                + " database user waiting");
        }
        // A rollback marks the rows it undid; let it finish first, as CoreProtect 25's claims do
        Object rollbacks = activeRollbacks.get();
        if (rollbacks instanceof Map && !((Map<?, ?>) rollbacks).isEmpty()) {
            return Lease.busy("a rollback is running");
        }
        boolean holdsGate = false;
        boolean granted = false;
        try {
            if (gated) {
                holdsGate = gate.acquire(context, GATE_WAIT_MILLIS);
                if (!holdsGate) {
                    return Lease.busy(GATE_BUSY);
                }
                // Checked again: a manual purge takes the database without waiting for the gate
                reason = stops.check(false);
                if (reason != null) {
                    return Lease.stop(reason);
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
            if (!granted && holdsGate) {
                gate.release();
            }
        }
    }

    private void release(Connection opened, boolean holdsGate) {
        try {
            close(opened);
        } finally {
            if (holdsGate) {
                gate.release();
            }
        }
    }

    @Override
    public boolean exclusive() {
        return false;
    }

    @Override
    public long stopTimeoutMillis() {
        return STOP_TIMEOUT_MILLIS;
    }

    /**
     * The purge is stuck in a statement past the stop timeout. If it holds
     * the gate, CoreProtect's consumer would skip its last write of the
     * queue at shutdown, so give the gate back.
     */
    @Override
    public void abandon() {
        gate.release();
    }
}
