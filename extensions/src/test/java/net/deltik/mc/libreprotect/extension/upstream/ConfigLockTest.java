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

import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.testutil.AssumeCapability;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link ConfigLock} is the very lock that CoreProtect's
 * {@code static synchronized} ConfigHandler methods hold.
 */
class ConfigLockTest {

    @Test
    @DisplayName("should keep CoreProtect's static synchronized ConfigHandler methods waiting while held")
    void blocksUpstream() throws Exception {
        AssumeCapability.strategy("config.lock", "class-monitor");
        ConfigLock lock = Capabilities.current().require(ConfigLock.CAPABILITY);
        Method method = staticSynchronized(Upstream.coreProtect().type(Names.CONFIG_HANDLER).type());
        CountDownLatch done = new CountDownLatch(1);
        Thread upstream = new Thread(() -> {
            try {
                method.invoke(null, arguments(method));
            } catch (ReflectiveOperationException | RuntimeException e) {
                // Whatever it does once it has the lock doesn't matter
            } finally {
                done.countDown();
            }
        }, "upstream ConfigHandler call");
        upstream.setDaemon(true);

        synchronized (lock.monitor()) {
            upstream.start();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (upstream.getState() != Thread.State.BLOCKED && System.nanoTime() < deadline) {
                Thread.sleep(5);
            }
            assertEquals(Thread.State.BLOCKED, upstream.getState(), method + " didn't wait for the lock");
            assertFalse(done.await(100, TimeUnit.MILLISECONDS));
        }
        assertTrue(done.await(10, TimeUnit.SECONDS), method + " didn't run once the lock was released");
    }

    @Test
    @DisplayName("should run an action while holding the lock")
    void run() throws Exception {
        AssumeCapability.strategy("config.lock", "class-monitor");
        ConfigLock lock = Capabilities.current().require(ConfigLock.CAPABILITY);
        boolean[] held = new boolean[1];

        lock.run(() -> held[0] = Thread.holdsLock(lock.monitor()));

        assertTrue(held[0]);
        assertSame(Upstream.coreProtect().type(Names.CONFIG_HANDLER).type(), lock.monitor());
    }

    private static Method staticSynchronized(Class<?> type) {
        for (Method method : type.getDeclaredMethods()) {
            int modifiers = method.getModifiers();
            if (Modifier.isStatic(modifiers) && Modifier.isSynchronized(modifiers)) {
                method.setAccessible(true);
                return method;
            }
        }
        throw new AssertionError(type + " has no static synchronized method");
    }

    private static Object[] arguments(Method method) {
        Class<?>[] types = method.getParameterTypes();
        Object[] arguments = new Object[types.length];
        for (int i = 0; i < types.length; i++) {
            if (types[i] == boolean.class) {
                arguments[i] = false;
            } else if (types[i] == int.class) {
                arguments[i] = 0;
            } else if (types[i] == long.class) {
                arguments[i] = 0L;
            }
        }
        return arguments;
    }
}
