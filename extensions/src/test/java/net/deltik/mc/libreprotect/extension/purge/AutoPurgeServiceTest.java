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

import net.deltik.mc.libreprotect.extension.common.Engine;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Clock;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class AutoPurgeServiceTest {

    @TempDir
    Path directory;

    private TestDatabase database;

    @AfterEach
    void tearDown() throws Exception {
        AutoPurgeService.stop();
        awaitThreads(0);
        if (database != null) {
            database.close();
        }
    }

    private static long threads() {
        return Thread.getAllStackTraces().keySet().stream()
            .filter(thread -> thread.getName().equals(AutoPurgeScheduler.THREAD_NAME) && thread.isAlive())
            .count();
    }

    private static void awaitThreads(long expected) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (threads() != expected && System.nanoTime() < deadline) {
            Thread.sleep(5);
        }
        assertEquals(expected, threads());
    }

    private FakeBridge bridge() throws SQLException {
        database = TestDatabase.create(Engine.SQLITE, directory);
        return new FakeBridge(database);
    }

    @Test
    @DisplayName("should run one auto-purge thread, however often it is started")
    void startsOnce() throws Exception {
        FakeBridge bridge = bridge();
        RecordingLog log = new RecordingLog();

        AutoPurgeService.start(bridge, log, Clock.systemUTC(), 60_000);
        AutoPurgeService.start(bridge, log, Clock.systemUTC(), 60_000);

        awaitThreads(1);
        assertEquals(1, log.containing("Auto-purge keeps 30 days of data").size(), log::toString);
        Thread thread = Thread.getAllStackTraces().keySet().stream()
            .filter(each -> each.getName().equals(AutoPurgeScheduler.THREAD_NAME)).findFirst().orElseThrow();
        assertTrue(thread.isDaemon(), "the thread must not keep the server's JVM alive");
    }

    @Test
    @DisplayName("should probe CoreProtect off the calling thread, and not start after a stop that came meanwhile")
    void startsOffTheCallingThread() throws Exception {
        FakeBridge bridge = bridge();
        CountDownLatch probing = new CountDownLatch(1);
        CountDownLatch probed = new CountDownLatch(1);
        AtomicReference<Thread> prober = new AtomicReference<>();

        Thread starter = AutoPurgeService.start(() -> {
            prober.set(Thread.currentThread());
            probing.countDown();
            try {
                probed.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return bridge;
        }, new RecordingLog(), Clock.systemUTC(), 60_000);

        assertTrue(probing.await(5, TimeUnit.SECONDS));
        assertNotSame(Thread.currentThread(), prober.get());
        assertTrue(prober.get().isDaemon(), "the probe must not keep the server's JVM alive");
        AutoPurgeService.stop();
        probed.countDown();
        starter.join(5_000);
        assertFalse(starter.isAlive());
        assertEquals(0, threads(), "the schedule started after the stop");

        // A start after the stop starts it
        AutoPurgeService.start(() -> bridge, new RecordingLog(), Clock.systemUTC(), 60_000).join(5_000);
        awaitThreads(1);
    }

    @Test
    @DisplayName("should stop safely any number of times, with or without a start")
    void stopsSafely() throws Exception {
        assertDoesNotThrow(AutoPurgeService::stop);
        AutoPurgeService.start(bridge(), new RecordingLog(), Clock.systemUTC(), 60_000);
        awaitThreads(1);

        assertDoesNotThrow(AutoPurgeService::stop);
        assertDoesNotThrow(AutoPurgeService::stop);
        awaitThreads(0);
    }

    @Test
    @DisplayName("should start again after a stop")
    void restarts() throws Exception {
        FakeBridge bridge = bridge();
        AutoPurgeService.start(bridge, new RecordingLog(), Clock.systemUTC(), 60_000);
        AutoPurgeService.stop();
        awaitThreads(0);

        AutoPurgeService.start(bridge, new RecordingLog(), Clock.systemUTC(), 60_000);

        awaitThreads(1);
    }

    @Test
    @DisplayName("runNow should purge on the auto-purge thread and return the rows removed")
    void runNow() throws Exception {
        FakeBridge bridge = bridge();
        database.insert("block", new long[]{1, 2, 3}, new long[]{100, 200, 300});
        AutoPurgeService.start(bridge, new RecordingLog(), Clock.systemUTC(), 60_000);

        assertEquals(1, AutoPurgeService.runNow(200));

        assertEquals(List.of(2L, 3L), database.rowids("block"));
    }

    @Test
    @DisplayName("runNow should refuse when auto-purge isn't running")
    void runNowStopped() throws Exception {
        AutoPurgeService.start(bridge(), new RecordingLog(), Clock.systemUTC(), 60_000);
        AutoPurgeService.stop();

        assertThrows(IllegalStateException.class, () -> AutoPurgeService.runNow(200));
    }
}
