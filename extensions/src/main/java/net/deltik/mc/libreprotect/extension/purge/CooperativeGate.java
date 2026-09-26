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
 * CoreProtect's cooperative {@code Consumer.isPaused} flag, used the way its
 * lookups use it: wait until nobody holds it, hold it for one short piece of
 * work, then clear it. On SQLite this keeps a purge chunk from writing at the
 * same time as the consumer, which would otherwise wait on SQLite's lock.
 */
public final class CooperativeGate {

    private static final long POLL_MILLIS = 5;

    private final BooleanSupplier held;
    private final Runnable hold;
    private final Runnable clear;
    private final AtomicBoolean ours = new AtomicBoolean();

    /**
     * @param held whether anyone holds the gate ({@code Consumer.isPaused})
     * @param hold sets the flag
     * @param clear clears the flag
     */
    public CooperativeGate(BooleanSupplier held, Runnable hold, Runnable clear) {
        this.held = Objects.requireNonNull(held, "held");
        this.hold = Objects.requireNonNull(hold, "hold");
        this.clear = Objects.requireNonNull(clear, "clear");
    }

    /**
     * Wait until nobody holds the gate, without taking it.
     *
     * @return whether it became free before the timeout and before a stop was requested
     */
    public boolean awaitFree(PurgeContext context, long timeoutMillis) throws InterruptedException {
        long deadline = System.nanoTime() + timeoutMillis * 1_000_000L;
        while (held.getAsBoolean()) {
            if (context.stopRequested() || System.nanoTime() - deadline >= 0) {
                return false;
            }
            context.pause(POLL_MILLIS);
        }
        return !context.stopRequested();
    }

    /**
     * Wait until nobody holds the gate, then hold it.
     *
     * @return whether the gate is now held; {@code false} after the timeout or a stop request
     */
    public boolean acquire(PurgeContext context, long timeoutMillis) throws InterruptedException {
        if (!awaitFree(context, timeoutMillis)) {
            return false;
        }
        hold.run();
        ours.set(true);
        return true;
    }

    /**
     * Clear the gate if this holds it. Safe to call more than once, and from
     * another thread when the holder is stuck.
     */
    public void release() {
        if (ours.compareAndSet(true, false)) {
            clear.run();
        }
    }

    /**
     * @return whether this holds the gate
     */
    public boolean isHeld() {
        return ours.get();
    }
}
