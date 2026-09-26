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

import java.util.concurrent.atomic.AtomicLong;

/**
 * Small steps around database maintenance, each a capability of its own,
 * so that one upstream reshaped leaves the others working.
 *
 * <p>The counter of purged rows is in every CoreProtect that LibreProtect
 * knows, so one that lacks it renamed it, and it's unavailable, never
 * absent; its step is harmless to skip. The others belong to CoreProtect
 * 25's multi-engine layer, which needs them: absent before it, and
 * unavailable if it lacks them.
 */
public final class Hooks {

    public static final Capability<AutoPurgeCounter> AUTO_PURGE_COUNTER = Capability.of("hook.auto-purge-counter",
        Choice.way("rows-purged", "CoreProtect's count of rows that automatic purges removed",
            AutoPurgeCounter::new));

    public static final Capability<EntitySpawnVerification> ENTITY_SPAWN_VERIFICATION = Capability.of(
        "hook.entity-spawn-verification",
        Choice.way("invalidate", "CoreProtect's check of tracked entities against the database",
            EntitySpawnVerification::new));

    public static final Capability<PurgeWorker> PURGE_WORKER = Capability.of("hook.purge-worker",
        Choice.way("worker-running", "CoreProtect's sign of a manual purge still at work", PurgeWorker::new));

    private Hooks() {
    }

    /**
     * {@code ConfigHandler.autoPurgeRowsPurged}, which CoreProtect's status shows.
     */
    public static final class AutoPurgeCounter {
        private final StaticField counter;

        private AutoPurgeCounter(Upstream upstream) throws Missing {
            counter = upstream.type(Names.CONFIG_HANDLER).staticField("autoPurgeRowsPurged", AtomicLong.class);
        }

        /**
         * Count rows that an automatic purge removed.
         */
        public void add(long rows) {
            Object value = counter.get();
            if (value instanceof AtomicLong) {
                ((AtomicLong) value).addAndGet(rows);
            }
        }
    }

    /**
     * {@code EntitySpawnTracking.invalidateDatabaseVerification()}.
     */
    public static final class EntitySpawnVerification {
        private final StaticMethod<Void, RuntimeException> invalidate;

        private EntitySpawnVerification(Upstream upstream) throws Missing {
            Designs.MULTI_ENGINE.requireIn(upstream);
            invalidate = upstream.type(Names.ENTITY_SPAWN_TRACKING).staticMethod("invalidateDatabaseVerification",
                void.class);
        }

        /**
         * Make CoreProtect check again which tracked entities still have a
         * row, after rows were removed or the database changed.
         */
        public void invalidate() {
            invalidate.call();
        }
    }

    /**
     * {@code PurgeCommand.isPurgeWorkerRunning()}: a manual purge keeps its
     * worker running after {@code purgeRunning} clears.
     */
    public static final class PurgeWorker {
        private final StaticMethod<Boolean, RuntimeException> running;

        private PurgeWorker(Upstream upstream) throws Missing {
            Designs.MULTI_ENGINE.requireIn(upstream);
            running = upstream.type(Names.PURGE_COMMAND).staticMethod("isPurgeWorkerRunning", boolean.class);
        }

        public boolean running() {
            return running.call();
        }
    }
}
