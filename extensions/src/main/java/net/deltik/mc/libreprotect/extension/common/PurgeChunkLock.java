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

package net.deltik.mc.libreprotect.extension.common;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Held by auto-purge for each chunk of work on the database, so that
 * {@code /co migrate-db} can wait for a chunk that is still running before
 * it reads the source.
 *
 * <p>Auto-purge checks, while it holds this, that no migration is running,
 * and a migration sets {@code migrationRunning} before it waits for this. So
 * once the wait ends, a chunk that was running has ended, and no other will
 * start. On CoreProtect 24 with MySQL, nothing else stands between the two:
 * a chunk holds only a pooled connection there.
 */
public final class PurgeChunkLock {

    private static final ReentrantLock LOCK = new ReentrantLock();

    private PurgeChunkLock() {
    }

    /**
     * For auto-purge: hold the lock for a chunk. Release it with
     * {@link #release()} on the same thread.
     *
     * @return whether it is held; {@code false} if a migration held it for
     *         longer than the timeout
     */
    public static boolean tryHold(long timeoutMillis) throws InterruptedException {
        return LOCK.tryLock(timeoutMillis, TimeUnit.MILLISECONDS);
    }

    /**
     * For auto-purge: release the lock that {@link #tryHold} took.
     */
    public static void release() {
        LOCK.unlock();
    }

    /**
     * @return whether the calling thread holds the lock
     */
    public static boolean isHeldByCurrentThread() {
        return LOCK.isHeldByCurrentThread();
    }

    /**
     * For a migration that has already made auto-purge stop before its next
     * chunk: wait until a chunk that is running, if any, has ended.
     *
     * @return whether no chunk is running now; {@code false} after the timeout
     */
    public static boolean awaitNoChunk(long timeoutMillis) throws InterruptedException {
        if (!LOCK.tryLock(timeoutMillis, TimeUnit.MILLISECONDS)) {
            return false;
        }
        LOCK.unlock();
        return true;
    }
}
