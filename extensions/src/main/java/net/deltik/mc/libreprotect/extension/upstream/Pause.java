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

import net.deltik.mc.libreprotect.extension.migration.MigrationException;

import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.function.Supplier;

/**
 * How a migration holds CoreProtect's database work while it copies and
 * switches databases, and lets go of it: one half of a
 * {@link MigrationProtocol}. What holds CoreProtect, and how its shutdown
 * treats a migration, differ between CoreProtect's designs, so each has a
 * pause of its own, and they're never mixed.
 */
interface Pause {

    /**
     * @return why a migration can't be claimed now, from what only this way
     *         of pausing knows, such as a purge or a reload that is running;
     *         {@code null} if nothing is in its way
     */
    String refusal();

    /**
     * @return a signal of CoreProtect's shutdown as it is now, which
     *         completes once the shutdown begins, or {@code null} if this way
     *         of pausing has none
     */
    Future<?> shutdownSignal();

    /**
     * @param stopReason why the migration has to stop now, or {@code null}
     *                   to carry on, as {@code MigrationSession.stopReason}
     * @return a hold on CoreProtect that the calling thread owns, which it
     *         must acquire and release itself
     */
    Hold hold(Supplier<String> stopReason);

    /**
     * Make CoreProtect stop saving events for good, until it restarts, when
     * it has no database left to save them to.
     *
     * @return whether it did; {@code false} where CoreProtect can't
     */
    default boolean haltPersistence() {
        return false;
    }

    /**
     * For tests without a server: the same way of pausing, with the tasks
     * it runs on the server's thread run by {@code executor} instead.
     */
    default Pause onServerThread(Executor executor) {
        return this;
    }

    /**
     * What a migration holds of CoreProtect. Some of CoreProtect's locks
     * belong to the thread that took them, so a hold belongs to the thread
     * that created it: only that thread may acquire and release it, and a
     * release from any other is refused rather than half done.
     */
    abstract class Hold {

        private final Thread owner = Thread.currentThread();

        /**
         * Wait until CoreProtect has finished the database work in progress,
         * then hold it. What was held when this fails stays held until
         * {@link #release}.
         *
         * @throws MigrationException if CoreProtect didn't settle in time, or
         *                            the migration has to stop
         * @throws IllegalStateException if the calling thread doesn't own the hold
         */
        final void acquire() throws MigrationException, InterruptedException {
            checkOwner("pause CoreProtect");
            doAcquire();
        }

        /**
         * Let go of whatever the hold took, in reverse. Does nothing when
         * called again.
         *
         * @param resume whether CoreProtect may resume saving events; not
         *               after a failed switch left it without a database
         * @throws IllegalStateException if the calling thread doesn't own the
         *                               hold; nothing is released then
         */
        final void release(boolean resume) {
            checkOwner("release CoreProtect");
            doRelease(resume);
        }

        /**
         * @return whether the calling thread owns the hold
         */
        final boolean ownedByCurrentThread() {
            return Thread.currentThread() == owner;
        }

        abstract void doAcquire() throws MigrationException, InterruptedException;

        abstract void doRelease(boolean resume);

        private void checkOwner(String action) {
            if (!ownedByCurrentThread()) {
                throw new IllegalStateException("Only the thread " + owner.getName() + " may " + action + ", not "
                    + Thread.currentThread().getName());
            }
        }
    }
}
