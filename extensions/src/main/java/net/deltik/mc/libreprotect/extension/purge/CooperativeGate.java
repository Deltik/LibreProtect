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

import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

/**
 * CoreProtect's cooperative {@code Consumer.isPaused} gate, used the way its
 * lookups use it: wait until nobody holds it, hold it for one short piece of
 * work, then give it back. On SQLite this keeps a purge chunk from writing at
 * the same time as the consumer, which would otherwise wait on SQLite's lock.
 */
public final class CooperativeGate {

    private static final long POLL_MILLIS = 5;

    private final BooleanSupplier held;
    private final BooleanSupplier take;
    private final Runnable giveBack;
    private final AtomicBoolean ours = new AtomicBoolean();

    /**
     * @param held whether anyone holds the gate ({@code Consumer.isPaused})
     * @param take takes the gate if nobody holds it, and says whether it did
     * @param giveBack gives back the gate that {@code take} took
     */
    public CooperativeGate(BooleanSupplier held, BooleanSupplier take, Runnable giveBack) {
        this.held = Objects.requireNonNull(held, "held");
        this.take = Objects.requireNonNull(take, "take");
        this.giveBack = Objects.requireNonNull(giveBack, "giveBack");
    }

    /**
     * Wait until nobody holds the gate, without taking it.
     *
     * @return whether it became free before the timeout and before a stop was requested
     */
    public boolean awaitFree(PurgeContext context, long timeoutMillis) throws InterruptedException {
        return awaitFreeUntil(context, deadline(timeoutMillis));
    }

    /**
     * Wait until nobody holds the gate, then take it, waiting on if someone
     * else took it first.
     *
     * @return whether the gate is now held; {@code false} after the timeout or a stop request
     */
    public boolean acquire(PurgeContext context, long timeoutMillis) throws InterruptedException {
        long deadline = deadline(timeoutMillis);
        while (awaitFreeUntil(context, deadline)) {
            if (take.getAsBoolean()) {
                ours.set(true);
                return true;
            }
            // Taken first, or refused, as CoreProtect refuses it while it saves no events
            if (System.nanoTime() - deadline >= 0) {
                return false;
            }
            context.pause(POLL_MILLIS);
        }
        return false;
    }

    private boolean awaitFreeUntil(PurgeContext context, long deadline) throws InterruptedException {
        while (held.getAsBoolean()) {
            if (context.stopRequested() || System.nanoTime() - deadline >= 0) {
                return false;
            }
            context.pause(POLL_MILLIS);
        }
        return !context.stopRequested();
    }

    private static long deadline(long timeoutMillis) {
        return System.nanoTime() + timeoutMillis * 1_000_000L;
    }

    /**
     * Give back the gate if this holds it. Safe to call more than once, and
     * from another thread when the holder is stuck.
     */
    public void release() {
        if (ours.compareAndSet(true, false)) {
            giveBack.run();
        }
    }

    /**
     * @return whether this holds the gate
     */
    public boolean isHeld() {
        return ours.get();
    }
}
