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

import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;

/**
 * CoreProtect's database reload lifecycle, as CoreProtect 25 has it, for
 * tests, which may name only what every CoreProtect has. Each member is
 * found when it's first called.
 */
final class Lifecycle {

    private Lifecycle() {
    }

    /**
     * @return the name of CoreProtect's answer, such as {@code STARTED}
     */
    static String beginDatabaseReload() {
        return name(consumer("beginDatabaseReload", Object.class).call());
    }

    static boolean lockDatabaseReload(long timeoutMillis) throws InterruptedException {
        return consumer("lockDatabaseReload", boolean.class, long.class).throwing(InterruptedException.class)
            .call(timeoutMillis);
    }

    static void endDatabaseReload(boolean resumePersistence) {
        consumer("endDatabaseReload", void.class, boolean.class).call(resumePersistence);
    }

    static boolean isDatabaseReloadRunning() {
        return consumer("isDatabaseReloadRunning", boolean.class).call();
    }

    static boolean isDatabaseReloadPaused() {
        return consumer("isDatabaseReloadPaused", boolean.class).call();
    }

    static boolean isPersistenceHalted() {
        return consumer("isPersistenceHalted", boolean.class).call();
    }

    static void blockDatabaseReloadForShutdown() {
        consumer("blockDatabaseReloadForShutdown", void.class).call();
    }

    static String claimBackgroundPurge(boolean pausePersistence) {
        return name(consumer("claimBackgroundPurge", Object.class, boolean.class).call(pausePersistence));
    }

    static void releaseBackgroundPurge() {
        consumer("releaseBackgroundPurge", void.class).call();
    }

    static String claimPurge() {
        return name(consumer("claimPurge", Object.class).call());
    }

    static void releasePurge() {
        consumer("releasePurge", void.class).call();
    }

    /**
     * Hold the lifecycle's read lock, as a batch of the consumer does.
     */
    static void lockDatabaseAccess() {
        consumer("lockDatabaseAccess", void.class).call();
    }

    static void unlockDatabaseAccess() {
        consumer("unlockDatabaseAccess", void.class).call();
    }

    /**
     * @return the status of a database lock row that marks an unfinished migration
     */
    static int incompleteStatus() {
        try {
            return Upstream.coreProtect().type(Names.DATABASE).intConstant("DATABASE_LOCK_MIGRATION_INCOMPLETE")
                .getAsInt();
        } catch (Missing e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    private static <R> StaticMethod<R, RuntimeException> consumer(String name, Class<R> returns,
                                                                  Class<?>... parameters) {
        try {
            return Upstream.coreProtect().type(Names.CONSUMER).staticMethod(name, returns, parameters);
        } catch (Missing e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    private static String name(Object result) {
        return ((Enum<?>) result).name();
    }
}
