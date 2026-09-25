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
 */
public final class ConsumerGate {

    public static final Capability<ConsumerGate> CAPABILITY = Capability.of("consumer.gate",
        Choice.way("pause-flags", "CoreProtect's consumer pause gate", ConsumerGate::new));

    private final StaticField isPaused;
    private final StaticField pausedSuccess;
    private final StaticMethod<Boolean, RuntimeException> isRunning;
    private final StaticMethod<Boolean, RuntimeException> isPersistenceHalted;

    private ConsumerGate(Upstream upstream) throws Missing {
        UpstreamClass consumer = upstream.type(Names.CONSUMER);
        // Held like CoreProtect's lookups hold it, by migrations and, on SQLite, by purges
        isPaused = consumer.writableStaticField("isPaused", boolean.class);
        // Protected: CoreProtect's purge command reaches it by extending Consumer
        pausedSuccess = consumer.staticField("pausedSuccess", boolean.class);
        isRunning = consumer.staticMethod("isRunning", boolean.class);
        isPersistenceHalted = consumer.staticMethodSince(Designs.MULTI_ENGINE, "isPersistenceHalted",
            boolean.class);
        upstream.relyOn("waits while isPaused, pauseConsumer or purgeRunning is set, with pausedSuccess set, and"
            + " clears pausedSuccess before it writes again", Names.CONSUMER, "pauseConsumer(I)V");
        // CoreProtect 25 checks the gate again under its database lock, before each batch
        upstream.relyOnSince(Designs.MULTI_ENGINE, "writes no batch while isPaused is set", Names.CONSUMER,
            "processConsumerBatch(IZ)V");
    }

    /**
     * @return whether someone holds the gate: a lookup, a reload, or a purge
     */
    public boolean isPaused() {
        return isPaused.getBoolean();
    }

    public void setPaused(boolean paused) {
        isPaused.setBoolean(paused);
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
