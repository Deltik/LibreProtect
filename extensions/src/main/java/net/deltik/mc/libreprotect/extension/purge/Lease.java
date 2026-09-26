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

import java.sql.Connection;
import java.util.Objects;

/**
 * Permission from CoreProtect for one unit of purge work, with a connection
 * to do it on, or why there is none.
 *
 * <p>A granted lease holds whatever this CoreProtect needs, such as
 * CoreProtect 25's background purge claim or the cooperative
 * {@code Consumer.isPaused} gate. Closing it gives all of that back. It must
 * be closed on the thread that took it: CoreProtect 25 releases its claim's
 * lock on that thread.
 */
public final class Lease implements AutoCloseable {

    private final Connection connection;
    private final Runnable release;
    private final StopReason stopReason;
    private final String stopDetail;
    private final String busyReason;
    private final Thread owner;
    private boolean closed;

    private Lease(Connection connection, Runnable release, StopReason stopReason, String stopDetail,
                  String busyReason) {
        this.connection = connection;
        this.release = release;
        this.stopReason = stopReason;
        this.stopDetail = stopDetail;
        this.busyReason = busyReason;
        this.owner = Thread.currentThread();
    }

    /**
     * @param connection the connection for the work, or {@code null} if the
     *                   work opens its own (ClickHouse)
     * @param release gives back what the lease holds, including closing the
     *                connection; runs once, when the lease is closed
     */
    public static Lease granted(Connection connection, Runnable release) {
        return new Lease(connection, Objects.requireNonNull(release, "release"), null, null, null);
    }

    /**
     * The purge must stop.
     */
    public static Lease stop(StopReason reason) {
        return stop(reason, null);
    }

    /**
     * The purge must stop.
     *
     * @param detail more about why, for messages, or {@code null}
     */
    public static Lease stop(StopReason reason, String detail) {
        return new Lease(null, null, Objects.requireNonNull(reason, "reason"), detail, null);
    }

    /**
     * Other work has the database for now; try again later.
     *
     * @param reason what the purge is waiting for, for messages
     */
    public static Lease busy(String reason) {
        return new Lease(null, null, null, null, Objects.requireNonNull(reason, "reason"));
    }

    /**
     * @return whether the work may run
     */
    public boolean isGranted() {
        return release != null;
    }

    /**
     * @return why the purge must stop, or {@code null}
     */
    public StopReason stopReason() {
        return stopReason;
    }

    /**
     * @return more about why the purge must stop, or {@code null}
     */
    public String stopDetail() {
        return stopDetail;
    }

    /**
     * @return what the purge is waiting for, or {@code null}
     */
    public String busyReason() {
        return busyReason;
    }

    /**
     * @return the connection of a granted lease
     */
    public Connection connection() {
        if (!isGranted()) {
            throw new IllegalStateException("Lease not granted");
        }
        return connection;
    }

    /**
     * Give back what the lease holds. Does nothing for a lease that wasn't
     * granted or is already closed.
     *
     * @throws IllegalStateException on a thread other than the one that took the lease
     */
    @Override
    public void close() {
        if (!isGranted() || closed) {
            return;
        }
        if (Thread.currentThread() != owner) {
            throw new IllegalStateException("A lease must be closed on the thread that took it (" + owner.getName() + ")");
        }
        closed = true;
        release.run();
    }
}
