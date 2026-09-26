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

import net.deltik.mc.libreprotect.extension.common.PurgeChunkLock;
import net.deltik.mc.libreprotect.extension.migration.MigrationException;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

/**
 * The pause of CoreProtect without a lifecycle for switching databases,
 * such as CoreProtect 24. A migration holds what CoreProtect's purge command
 * holds, and more:
 * <ul>
 *   <li>{@code migrationRunning}, from the claim on: purges refuse to start,
 *       and CoreProtect's shutdown clears {@code purgeRunning} once it sees
 *       it, then waits for the consumer.</li>
 *   <li>{@code purgeRunning}, set on the server's thread: lookups,
 *       rollbacks, reloads and other direct writers refuse to start.</li>
 *   <li>{@code pauseConsumer}, which the consumer's pause loop honors while
 *       {@code migrationRunning} is set, even once shutdown has cleared
 *       {@code purgeRunning}: the consumer writes its queue only once the
 *       migration releases it, to whichever database is active then.</li>
 *   <li>{@code Consumer.isPaused}, the gate that lookups and CoreProtect's
 *       reload hold while they work, taken only once they let go of it, and
 *       once rollbacks, whose lookups take it too, have ended.</li>
 * </ul>
 * The hold releases them in reverse, and the migration's watchdog makes it
 * stop within seconds once the server does.
 *
 * <p>CoreProtect 25 still has these flags, with other meanings, so this is
 * never used on a CoreProtect that has any part of the reload lifecycle
 * (see {@link MigrationProtocol}).
 */
final class FlagProtocolPause implements Pause {

    /** The refusal while a purge runs */
    static final String PURGE_RUNNING = "A purge is running. Try again once it has finished.";

    private static final long PAUSE_TIMEOUT_MILLIS = 120_000;
    private static final long POLL_MILLIS = 150;
    private static final long GATE_POLL_MILLIS = 20;

    private final Flags flags;
    private final ConsumerGate gate;
    private final Executor serverThread;

    private FlagProtocolPause(Flags flags, ConsumerGate gate, Executor serverThread) {
        this.flags = flags;
        this.gate = gate;
        this.serverThread = serverThread;
    }

    static FlagProtocolPause probe(Upstream upstream) throws Missing {
        Flags flags = MigrationProtocol.flags(upstream);
        ConsumerGate gate = MigrationProtocol.need(upstream, ConsumerGate.CAPABILITY);
        ServerThread serverThread = MigrationProtocol.need(upstream, ServerThread.CAPABILITY);
        upstream.relyOn("clears purgeRunning once it sees migrationRunning, then waits for the consumer only while"
            + " purgeRunning is clear", Names.SHUTDOWN_SERVICE, "safeShutdown(Lorg/bukkit/plugin/Plugin;)V");
        upstream.relyOn("keeps the consumer waiting while pauseConsumer or purgeRunning is set, for as long as"
            + " migrationRunning is, even once serverRunning clears", Names.CONSUMER, "pauseConsumer(I)V");
        upstream.relyOn("refuses to start a reload while purgeRunning is set", Names.RELOAD_COMMAND,
            "runCommand(Lorg/bukkit/command/CommandSender;Z[Ljava/lang/String;)V");
        upstream.relyOn("refuses to start a purge while migrationRunning is set", Names.PURGE_COMMAND,
            "runCommand(Lorg/bukkit/command/CommandSender;Z[Ljava/lang/String;)V");
        upstream.relyOn("refuses to start a lookup while purgeRunning is set", Names.LOOKUP_COMMAND,
            "runCommand(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Z[Ljava/lang/String;)V");
        upstream.relyOn("refuses to start a rollback or restore while purgeRunning is set",
            Names.ROLLBACK_RESTORE_COMMAND, "runCommand(Lorg/bukkit/command/CommandSender;Lorg/bukkit/command/Command;Z"
                + "[Ljava/lang/String;Lorg/bukkit/Location;JJ)V");
        upstream.relyOn("hands out only forced connections while purgeRunning is set", Names.DATABASE,
            "getConnection(ZZZI)Ljava/sql/Connection;");
        return new FlagProtocolPause(flags, gate, serverThread.executor());
    }

    @Override
    public String refusal() {
        return flags.purgeRunning() ? PURGE_RUNNING : null;
    }

    @Override
    public Future<?> shutdownSignal() {
        return null;
    }

    @Override
    public Hold hold(Supplier<String> stopReason) {
        return new FlagHold(stopReason);
    }

    @Override
    public Pause onServerThread(Executor executor) {
        return new FlagProtocolPause(flags, gate, executor);
    }

    private final class FlagHold extends Hold {
        private final Supplier<String> stopReason;
        private final Object holdLock = new Object();
        /** Guarded by {@link #holdLock} */
        private boolean released;
        /** Guarded by {@link #holdLock} */
        private boolean heldPurge;
        private boolean heldConsumer;
        private boolean savedPauseConsumer;
        private boolean heldGate;

        FlagHold(Supplier<String> stopReason) {
            this.stopReason = stopReason;
        }

        /**
         * Hold purges, which refuses new rollbacks, lookups and reloads; wait
         * until a running chunk of auto-purge ends, since on MySQL it holds
         * nothing else the migration waits for; wait until rollbacks end,
         * since their lookups take the gate; wait until the consumer is in
         * its pause loop, where it holds no connection, on two looks in a
         * row; and take the gate once lookups and reloads let go of it.
         */
        @Override
        void doAcquire() throws MigrationException, InterruptedException {
            long deadline = System.nanoTime() + PAUSE_TIMEOUT_MILLIS * 1_000_000L;
            holdPurges(deadline);
            // migrationRunning keeps auto-purge from starting a chunk; one that started before may still be deleting
            while (!PurgeChunkLock.awaitNoChunk(POLL_MILLIS)) {
                checkRunning();
                waitUntil(deadline, "Auto-purge didn't finish its current step");
            }
            while (flags.rollbacksRunning()) {
                checkRunning();
                waitUntil(deadline, "A rollback or restore didn't finish");
                Thread.sleep(POLL_MILLIS);
            }
            savedPauseConsumer = flags.pauseConsumer();
            flags.setPauseConsumer(true);
            heldConsumer = true;
            int confirmations = 0;
            while (confirmations < 2) {
                checkRunning();
                if (!gate.running() || gate.parked()) {
                    confirmations++;
                } else {
                    confirmations = 0;
                }
                waitUntil(deadline, "CoreProtect's consumer didn't finish its work");
                Thread.sleep(POLL_MILLIS);
            }
            // Take the gate once a lookup or reload that holds it lets go, the way they take it
            while (gate.isPaused()) {
                checkRunning();
                waitUntil(deadline, "A lookup or reload didn't finish");
                Thread.sleep(GATE_POLL_MILLIS);
            }
            gate.setPaused(true);
            heldGate = true;
        }

        /**
         * Set {@code purgeRunning} on the server's thread, where CoreProtect's
         * shutdown runs as well: set there, it's either set before the
         * shutdown begins, which then clears it, or never. Set from any other
         * thread, a shutdown that already cleared it would stop waiting for
         * the consumer.
         */
        private void holdPurges(long deadline) throws MigrationException, InterruptedException {
            CompletableFuture<Boolean> held = new CompletableFuture<>();
            try {
                serverThread.execute(() -> {
                    try {
                        synchronized (holdLock) {
                            if (!released && flags.serverRunning() && !flags.purgeRunning()) {
                                flags.setPurgeRunning(true);
                                heldPurge = true;
                            }
                            held.complete(heldPurge);
                        }
                    } catch (RuntimeException | LinkageError e) {
                        held.completeExceptionally(e);
                    }
                });
            } catch (RuntimeException e) {
                throw new MigrationException("The migration couldn't pause CoreProtect: " + e, e);
            }
            while (true) {
                checkRunning();
                waitUntil(deadline, "The server's main thread didn't respond");
                try {
                    if (held.get(POLL_MILLIS, TimeUnit.MILLISECONDS)) {
                        return;
                    }
                    throw new MigrationException(PURGE_RUNNING);
                } catch (TimeoutException e) {
                    // Keep waiting
                } catch (ExecutionException e) {
                    throw new MigrationException("The migration couldn't pause CoreProtect: " + e.getCause(), e);
                }
            }
        }

        @Override
        void doRelease(boolean resume) {
            if (heldGate) {
                heldGate = false;
                gate.setPaused(false);
            }
            if (heldConsumer) {
                heldConsumer = false;
                flags.setPauseConsumer(savedPauseConsumer);
            }
            synchronized (holdLock) {
                released = true;
                if (heldPurge) {
                    // Shutdown may already have cleared it; a purge can't have set it again while migrationRunning is set
                    heldPurge = false;
                    flags.setPurgeRunning(false);
                }
            }
        }

        private void checkRunning() throws MigrationException {
            String stop = stopReason.get();
            if (stop != null) {
                throw new MigrationException("The migration stopped because " + stop + ".");
            }
        }
    }

    private static void waitUntil(long deadline, String timeout) throws MigrationException {
        if (System.nanoTime() > deadline) {
            throw new MigrationException(timeout + " within " + PAUSE_TIMEOUT_MILLIS / 1000 + " seconds.");
        }
    }
}
