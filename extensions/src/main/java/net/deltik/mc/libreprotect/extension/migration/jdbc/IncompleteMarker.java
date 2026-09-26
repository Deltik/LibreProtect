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

package net.deltik.mc.libreprotect.extension.migration.jdbc;

/**
 * How a target's {@code database_lock} row says that it holds an unfinished
 * migration, so that CoreProtect refuses to use it.
 */
public final class IncompleteMarker {

    private final int status;
    private final boolean timeInFarFuture;

    private IncompleteMarker(int status, boolean timeInFarFuture) {
        this.status = status;
        this.timeInFarFuture = timeInFarFuture;
    }

    /**
     * A status that CoreProtect never activates, such as CoreProtect 25's
     * {@code DATABASE_LOCK_MIGRATION_INCOMPLETE}, with the current time.
     */
    public static IncompleteMarker status(int status) {
        return new IncompleteMarker(status, false);
    }

    /**
     * The "in use by another server" status with a time that never passes,
     * for versions without a dedicated status: CoreProtect 24 waits for such
     * a lock at startup, gives up and disables itself.
     */
    public static IncompleteMarker lockedForever(int activeStatus) {
        return new IncompleteMarker(activeStatus, true);
    }

    int status() {
        return status;
    }

    /**
     * @return the lock time to write, in seconds since the epoch
     */
    int time() {
        return timeInFarFuture ? Integer.MAX_VALUE : (int) (System.currentTimeMillis() / 1000L);
    }
}
