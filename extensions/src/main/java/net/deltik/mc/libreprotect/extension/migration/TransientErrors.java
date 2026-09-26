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

package net.deltik.mc.libreprotect.extension.migration;

import java.net.SocketTimeoutException;
import java.sql.SQLException;
import java.sql.SQLNonTransientException;
import java.sql.SQLRecoverableException;
import java.sql.SQLTransientException;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.Set;

/**
 * Tells database errors that may go away when the call is repeated from
 * those that won't.
 */
public final class TransientErrors {

    private TransientErrors() {
    }

    /**
     * @return whether an error, or any error it wraps, may go away when the
     *         call is repeated: a busy SQLite file, a MySQL deadlock or lock
     *         wait timeout, a lost connection, or anything the driver calls
     *         transient or recoverable. What the driver calls non-transient,
     *         such as bad data, a constraint violation or a connection that
     *         can't be made, never is; nor is a server that didn't answer
     *         within the migration's own network timeouts, which a repeated
     *         call would wait for as long again.
     */
    public static boolean isTransient(Throwable error) {
        if (error instanceof SQLNonTransientException || timedOut(error)) {
            return false;
        }
        Deque<Throwable> pending = new ArrayDeque<>();
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        pending.add(error);
        while (!pending.isEmpty()) {
            Throwable current = pending.poll();
            if (!seen.add(current)) {
                continue;
            }
            if (current instanceof SQLTransientException || current instanceof SQLRecoverableException) {
                return true;
            }
            if (current instanceof SQLException && !(current instanceof SQLNonTransientException)) {
                SQLException sql = (SQLException) current;
                if (isTransientState(sql.getSQLState()) || isTransientMySQLError(sql.getErrorCode())
                    || isBusySQLite(sql.getMessage())) {
                    return true;
                }
                if (sql.getNextException() != null) {
                    pending.add(sql.getNextException());
                }
            }
            if (current.getCause() != null) {
                pending.add(current.getCause());
            }
        }
        return false;
    }

    /**
     * @return whether a network timeout of the connection caused the error:
     *         the driver's socket gave up waiting, as MySQL's does after
     *         {@code Connection.setNetworkTimeout} or its connect timeout
     */
    private static boolean timedOut(Throwable error) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable current = error; current != null && seen.add(current); current = current.getCause()) {
            if (current instanceof SocketTimeoutException) {
                return true;
            }
        }
        return false;
    }

    /** Connection exceptions (08) and transaction rollbacks such as deadlocks (40) */
    private static boolean isTransientState(String state) {
        return state != null && (state.startsWith("08") || state.startsWith("40"));
    }

    /** Lock wait timeout, deadlock, server gone away, lost connection */
    private static boolean isTransientMySQLError(int code) {
        return code == 1205 || code == 1213 || code == 2006 || code == 2013;
    }

    /** sqlite-jdbc starts its messages with the result code, such as [SQLITE_BUSY_SNAPSHOT] */
    private static boolean isBusySQLite(String message) {
        return message != null && (message.startsWith("[SQLITE_BUSY") || message.startsWith("[SQLITE_LOCKED"));
    }
}
