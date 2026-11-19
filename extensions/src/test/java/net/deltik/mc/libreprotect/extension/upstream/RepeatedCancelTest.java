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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class RepeatedCancelTest {

    private final AtomicBoolean signal = new AtomicBoolean();
    private final AtomicInteger cancels = new AtomicInteger();

    @Test
    @DisplayName("should never cancel while the signal is down")
    void quiet() throws Exception {
        try (RepeatedCancel ignored = RepeatedCancel.start("test", signal::get, cancels::incrementAndGet)) {
            Thread.sleep(3 * RepeatedCancel.POLL_MILLIS);
        }

        assertEquals(0, cancels.get());
    }

    @Test
    @DisplayName("should keep cancelling once the signal is up, so work that registers late is cancelled too")
    void repeats() throws Exception {
        // Like CoreProtect's retention, which ignores cancels until its purge registers
        AtomicBoolean registered = new AtomicBoolean();
        CountDownLatch reached = new CountDownLatch(1);
        try (RepeatedCancel ignored = RepeatedCancel.start("test", signal::get, () -> {
            cancels.incrementAndGet();
            if (registered.get()) {
                reached.countDown();
            }
        })) {
            signal.set(true);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (cancels.get() == 0) {
                assertTrue(System.nanoTime() < deadline, "never cancelled");
                Thread.sleep(5);
            }
            // The first cancel came too early, as CoreProtect's own would
            registered.set(true);

            assertTrue(reached.await(5, TimeUnit.SECONDS), "the cancel wasn't repeated");
        }
        assertTrue(cancels.get() >= 2, () -> cancels.get() + " cancels");
    }

    @Test
    @DisplayName("should keep checking when the signal or the cancel throws")
    void survivesExceptions() throws Exception {
        AtomicInteger checks = new AtomicInteger();
        CountDownLatch thirdCancel = new CountDownLatch(3);
        try (RepeatedCancel ignored = RepeatedCancel.start("test", () -> {
            if (checks.incrementAndGet() == 1) {
                throw new IllegalStateException("CoreProtect isn't loaded");
            }
            return true;
        }, () -> {
            thirdCancel.countDown();
            throw new IllegalStateException("No ClickHouse database is active");
        })) {
            assertTrue(thirdCancel.await(5, TimeUnit.SECONDS), "the checks stopped");
        }
    }

    @Test
    @DisplayName("should not cancel after it's closed, and close at once")
    void closes() throws Exception {
        signal.set(true);
        RepeatedCancel repeating = RepeatedCancel.start("test", signal::get, cancels::incrementAndGet);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (cancels.get() == 0) {
            assertTrue(System.nanoTime() < deadline, "never cancelled");
            Thread.sleep(5);
        }

        long closing = System.nanoTime();
        repeating.close();
        long closedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - closing);
        int afterClose = cancels.get();
        Thread.sleep(3 * RepeatedCancel.POLL_MILLIS);

        assertEquals(afterClose, cancels.get(), "cancelled after it was closed");
        assertTrue(closedMillis < 500, "closed in " + closedMillis + " ms");
        assertDoesNotThrow(repeating::close);
    }
}
