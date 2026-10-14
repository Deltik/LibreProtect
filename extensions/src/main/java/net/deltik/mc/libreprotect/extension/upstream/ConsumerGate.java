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

import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;

/**
 * CoreProtect's consumer, the thread that writes queued events: its
 * cooperative {@code isPaused} gate, which lookups hold while they read, and
 * the handshake that shows it waiting in its pause loop, where it writes
 * nothing and holds no connection.
 *
 * <p>With pause claims, the gate is claimed and given back through
 * CoreProtect's own methods, as its lookups do. Before them, it's set and
 * cleared directly, as its lookups did then.
 */
public final class ConsumerGate {

    public static final Capability<ConsumerGate> CAPABILITY = Capability.of("consumer.gate",
        Choice.way("pause-claims", "CoreProtect's consumer pause gate, claimed as its lookups claim it",
            Designs.PAUSE_CLAIMS, upstream -> new ConsumerGate(upstream, true)),
        Choice.way("pause-flags", "CoreProtect's consumer pause gate",
            upstream -> new ConsumerGate(upstream, false)));

    private final StaticField isPaused;
    private final StaticField pausedSuccess;
    private final StaticMethod<Boolean, RuntimeException> isRunning;
    private final StaticMethod<Boolean, RuntimeException> isPersistenceHalted;
    /** How to claim the gate, or {@code null} before pause claims */
    private final StaticMethod<Boolean, RuntimeException> claim;
    /** How to give a claim back, or {@code null} before pause claims */
    private final StaticMethod<Void, RuntimeException> releaseClaim;

    private ConsumerGate(Upstream upstream, boolean claims) throws Missing {
        UpstreamClass consumer = upstream.type(Names.CONSUMER);
        if (claims) {
            isPaused = consumer.staticField("isPaused", boolean.class);
            claim = consumer.staticMethod("tryClaimConsumerPause", boolean.class);
            releaseClaim = consumer.staticMethod("releaseOperationPause", void.class);
            upstream.relyOn("claims the gate under its pause monitor, unless someone holds it or persistence is"
                + " halted", claim);
            upstream.relyOn("gives a claim back, leaving the gate held only while maintenance pauses the consumer",
                releaseClaim);
            // Outside Consumer, which its methods' fingerprints don't cover
            upstream.relyOn("claims the gate before it writes a batch, writes none if it can't, and gives back only"
                + " the claim it took", Names.PROCESS, "processConsumer(IZ)V");
        } else {
            // Held like CoreProtect's lookups hold it, by migrations and, on SQLite, by purges
            isPaused = consumer.writableStaticField("isPaused", boolean.class);
            claim = null;
            releaseClaim = null;
        }
        // Protected: CoreProtect's purge command reaches it by extending Consumer
        pausedSuccess = consumer.staticField("pausedSuccess", boolean.class);
        isRunning = consumer.staticMethod("isRunning", boolean.class);
        isPersistenceHalted = consumer.staticMethodSince(Designs.MULTI_ENGINE, "isPersistenceHalted",
            boolean.class);
        upstream.relyOn("waits while isPaused, pauseConsumer or purgeRunning is set, with pausedSuccess set, and"
            + " clears pausedSuccess before it writes again", Names.CONSUMER, pauseLoop(upstream));
        // CoreProtect 25 checks the gate again under its database lock, before each batch
        upstream.relyOnSince(Designs.MULTI_ENGINE, "writes no batch while isPaused is set", Names.CONSUMER,
            "processConsumerBatch(IZ)V");
    }

    /**
     * @return the consumer's pause loop by name and descriptor, for ways that
     *         rely on it: with pause claims, it returns whether to write
     */
    static String pauseLoop(Upstream upstream) {
        return "pauseConsumer(I)" + (Designs.PAUSE_CLAIMS.isIn(upstream) ? "Z" : "V");
    }

    /**
     * @return whether someone holds the gate: a lookup, a reload, a purge,
     *         or the consumer itself
     */
    public boolean isPaused() {
        return isPaused.getBoolean();
    }

    /**
     * Take the gate if nobody holds it, as CoreProtect's lookups take it.
     * Give it back with {@link #release()}.
     *
     * @return whether this took it
     */
    public boolean tryHold() {
        if (claim != null) {
            return claim.call();
        }
        if (isPaused.getBoolean()) {
            return false;
        }
        isPaused.setBoolean(true);
        return true;
    }

    /**
     * Give back the gate that {@link #tryHold()} took.
     */
    public void release() {
        if (releaseClaim != null) {
            releaseClaim.call();
        } else if (!persistenceHalted()) {
            // As CoreProtect's lookups left it before pause claims: a halt keeps the consumer paused
            isPaused.setBoolean(false);
        }
    }

    /**
     * @return whether the consumer is waiting in its pause loop, so it's not
     *         writing to the database
     */
    public boolean parked() {
        return pausedSuccess.getBoolean();
    }

    /**
     * @return whether the consumer thread is alive
     */
    public boolean running() {
        return isRunning.call();
    }

    /**
     * @return whether CoreProtect 25 stopped saving events after a database
     *         failure; always false on CoreProtect 24, which can't stop
     */
    public boolean persistenceHalted() {
        return isPersistenceHalted.call();
    }
}
