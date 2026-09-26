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
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticField;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.function.BooleanSupplier;

/**
 * How automatic purging takes turns with CoreProtect's own database work:
 * each unit of work runs under a {@link Lease}, which holds what this
 * CoreProtect needs held and gives a connection. CoreProtect 25 has
 * background purge claims for this, which its maintenance and its shutdown
 * wait for. CoreProtect 24 has only its lifecycle flags, which a purge
 * watches and never sets, and its consumer's cooperative pause gate; its
 * shutdown waits for nothing.
 *
 * <p>On SQLite, each unit of work also holds the consumer's pause gate
 * ({@code Consumer.isPaused}), like CoreProtect's lookups do, so that it
 * doesn't write while the consumer does, which would wait on SQLite's lock.
 */
public abstract class Leases {

    public static final Capability<Leases> CAPABILITY = Capability.of("auto-purge.coordination",
        Choice.way("background-claims", "CoreProtect's background purge claims, which its maintenance and shutdown"
            + " wait for", Designs.MULTI_ENGINE, ClaimLeases::new),
        Choice.way("cooperative-flags", "CoreProtect's lifecycle flags, and its consumer's pause gate on SQLite",
            CooperativeLeases::new));

    /** Why purging must stop, for a lease to check again once it holds what it took */
    @FunctionalInterface
    public interface Stops {
        /**
         * @param holdingPurgeClaim whether the lease holds CoreProtect's
         *                          purge claim, whose {@code purgeRunning}
         *                          otherwise shows a manual purge
         * @return why purging must stop now, or {@code null}
         */
        StopReason check(boolean holdingPurgeClaim);
    }

    /** How long to wait for a MySQL connection from CoreProtect's pool */
    static final int CONNECTION_WAIT_MILLIS = 1000;
    static final String GATE_BUSY = "the consumer or a lookup is using the database";
    static final String NO_CONNECTION = "no database connection is available";

    Leases() {
    }

    /**
     * Take what this CoreProtect needs held for one unit of purge work and
     * open a connection for it. Returns a lease that says why not instead,
     * if purging must stop or wait.
     *
     * @param gated whether to hold the consumer's pause gate too, as on SQLite
     * @param exclusive whether the work needs every other database user to
     *                  wait, with every other connection closed
     */
    public abstract Lease lease(PurgeContext context, boolean gated, boolean exclusive, Stops stops)
        throws InterruptedException;

    /**
     * @return whether leases can be exclusive, which orphan cleanup and a
     *         DuckDB checkpoint need
     */
    public abstract boolean exclusive();

    /**
     * @return how long stopping may wait for the purge to end, in
     *         milliseconds; 0 if CoreProtect's shutdown waits for it
     */
    public abstract long stopTimeoutMillis();

    /**
     * Give back the pause gate, if a unit of work that is stuck holds it.
     * Safe from any thread.
     */
    public abstract void abandon();

    /**
     * @param halted whether the consumer must stay paused when the gate is
     *               given back, as CoreProtect's lookups leave it after a
     *               persistence halt; or {@code null} if it never must
     * @return the consumer's pause gate
     */
    static CooperativeGate gate(StaticField isPaused, BooleanSupplier halted) {
        return new CooperativeGate(isPaused::getBoolean, () -> isPaused.setBoolean(true), () -> {
            if (halted == null || !halted.getAsBoolean()) {
                isPaused.setBoolean(false);
            }
        });
    }

    static void close(Connection connection) {
        try {
            connection.close();
        } catch (SQLException | RuntimeException e) {
            // Closed already, or its database is being closed
        }
    }
}
