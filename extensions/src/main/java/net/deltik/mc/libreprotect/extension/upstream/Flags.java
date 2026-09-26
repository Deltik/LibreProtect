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

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

/**
 * CoreProtect's lifecycle flags in {@code ConfigHandler}, which its own
 * commands and threads check before they touch the database. The names are
 * the same in CoreProtect 24 and 25, but what sets them and what honors
 * them differ; the capabilities that use them say how.
 *
 * <p>On CoreProtect 25, a purge is claimed through
 * {@code Consumer.claimPurge}, which sets {@code purgeRunning} under the
 * consumer's lock after checking reloads and rollbacks, and its consumer is
 * paused through database reloads. So there, {@link #setPurgeRunning} and
 * {@link #setPauseConsumer}, CoreProtect 24's protocol, refuse.
 * {@code migrationRunning} has no such claim on either: a migration sets it
 * itself, and CoreProtect's shutdown waits while it's set.
 *
 * <p>The capability only reads the flags, which auto-purge needs too. Only
 * the flags that {@link #forMigrations} gives a migration protocol can be
 * set, so a flag that CoreProtect made final turns off migrations alone.
 */
public final class Flags {

    public static final Capability<Flags> CAPABILITY = Capability.of("lifecycle.flags",
        Choice.way("static-flags", "CoreProtect's running, migration, conversion, purge and pause flags",
            Flags::new));

    private final StaticField serverRunning;
    private final StaticField migrationRunning;
    private final StaticField converterRunning;
    private final StaticField purgeRunning;
    private final StaticField pauseConsumer;
    private final StaticField activeRollbacks;
    private final StaticField shutdownDrainRunning;
    private final StaticMethod<?, RuntimeException> shutdownSignal;
    /** How CoreProtect shows that it has its newer design, which rules out writing the flags; or {@code null} */
    private final String newerDesign;

    private Flags(Upstream upstream) throws Missing {
        newerDesign = Designs.MULTI_ENGINE.evidenceIn(upstream).orElse(null);
        UpstreamClass handler = upstream.type(Names.CONFIG_HANDLER);
        serverRunning = handler.staticField("serverRunning", boolean.class);
        migrationRunning = handler.staticField("migrationRunning", boolean.class);
        converterRunning = handler.staticField("converterRunning", boolean.class);
        purgeRunning = handler.staticField("purgeRunning", boolean.class);
        pauseConsumer = handler.staticField("pauseConsumer", boolean.class);
        activeRollbacks = handler.staticField("activeRollbacks", Map.class);
        // CoreProtect 25's shutdown signals, which come before serverRunning clears
        shutdownDrainRunning = handler.staticFieldSince(Designs.MULTI_ENGINE, "shutdownDrainRunning",
            boolean.class);
        // A copy of the signal each time, which completes with it
        shutdownSignal = upstream.type(Names.CONSUMER).staticMethodSince(Designs.MULTI_ENGINE,
            "databaseReloadShutdownSignal", CompletableFuture.class);
    }

    private Flags(Flags flags, StaticField migrationRunning, StaticField purgeRunning, StaticField pauseConsumer) {
        newerDesign = flags.newerDesign;
        serverRunning = flags.serverRunning;
        this.migrationRunning = migrationRunning;
        converterRunning = flags.converterRunning;
        this.purgeRunning = purgeRunning;
        this.pauseConsumer = pauseConsumer;
        activeRollbacks = flags.activeRollbacks;
        shutdownDrainRunning = flags.shutdownDrainRunning;
        shutdownSignal = flags.shutdownSignal;
    }

    /**
     * For the probe of a migration protocol: these flags, able to set those
     * that a migration sets, which only migrations need writable. That's
     * {@code migrationRunning} on every CoreProtect, and {@code purgeRunning}
     * and {@code pauseConsumer} with CoreProtect 24's protocol.
     *
     * @throws Missing if CoreProtect made one of them final
     */
    Flags forMigrations(Upstream upstream) throws Missing {
        UpstreamClass handler = upstream.type(Names.CONFIG_HANDLER);
        StaticField migration = handler.writableStaticField("migrationRunning", boolean.class);
        if (newerDesign != null) {
            return new Flags(this, migration, purgeRunning, pauseConsumer);
        }
        return new Flags(this, migration, handler.writableStaticField("purgeRunning", boolean.class),
            handler.writableStaticField("pauseConsumer", boolean.class));
    }

    public boolean serverRunning() {
        return serverRunning.getBoolean();
    }

    public boolean migrationRunning() {
        return migrationRunning.getBoolean();
    }

    /**
     * @throws IllegalStateException unless these flags are {@link #forMigrations}'
     */
    public void setMigrationRunning(boolean running) {
        migrationRunning.setBoolean(running);
    }

    public boolean converterRunning() {
        return converterRunning.getBoolean();
    }

    public boolean purgeRunning() {
        return purgeRunning.getBoolean();
    }

    /**
     * For CoreProtect 24's protocol, where a purge sets it itself.
     *
     * @throws IllegalStateException on CoreProtect 25, whose purges are
     *                               claimed through {@code Consumer.claimPurge}
     */
    public void setPurgeRunning(boolean running) {
        refuseOnNewerDesign("purgeRunning", "claims purges through Consumer.claimPurge, under its lock");
        purgeRunning.setBoolean(running);
    }

    public boolean pauseConsumer() {
        return pauseConsumer.getBoolean();
    }

    /**
     * For CoreProtect 24's protocol, where a migration pauses the consumer
     * with it.
     *
     * @throws IllegalStateException on CoreProtect 25, whose consumer is
     *                               paused through database reloads
     */
    public void setPauseConsumer(boolean pause) {
        refuseOnNewerDesign("pauseConsumer", "pauses its consumer through database reloads");
        pauseConsumer.setBoolean(pause);
    }

    private void refuseOnNewerDesign(String flag, String instead) {
        if (newerDesign != null) {
            throw new IllegalStateException("Setting " + flag + " is CoreProtect 24's protocol, but " + newerDesign
                + ", which " + instead);
        }
    }

    /**
     * @return whether a rollback or restore is running
     */
    public boolean rollbacksRunning() {
        Object rollbacks = activeRollbacks.get();
        return rollbacks instanceof Map && !((Map<?, ?>) rollbacks).isEmpty();
    }

    /**
     * @return whether CoreProtect is stopping, or not running, by every
     *         signal it has: {@code serverRunning} cleared, and on
     *         CoreProtect 25, its shutdown drain or the shutdown signal of
     *         database reloads, which come first
     */
    public boolean shuttingDown() {
        if (!serverRunning() || shutdownDrainRunning.getBoolean()) {
            return true;
        }
        Object signal = shutdownSignal.call();
        return signal instanceof Future && ((Future<?>) signal).isDone();
    }
}
