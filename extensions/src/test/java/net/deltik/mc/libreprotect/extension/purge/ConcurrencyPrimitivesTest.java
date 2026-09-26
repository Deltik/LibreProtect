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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link PurgeContext}, {@link CooperativeGate}, {@link Lease} and {@link ChunkSizer}.
 */
class ConcurrencyPrimitivesTest {

    private static Thread worker(PurgeContext context, Runnable body) {
        Thread thread = new Thread(body, "test worker");
        context.bind(thread);
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    @Nested
    @DisplayName("PurgeContext")
    class Context {

        @Test
        @DisplayName("pause should end as soon as a stop is requested")
        void pauseEndsOnStop() throws Exception {
            PurgeContext context = new PurgeContext();
            CountDownLatch done = new CountDownLatch(1);
            worker(context, () -> {
                try {
                    context.pause(60_000);
                } catch (InterruptedException e) {
                    throw new AssertionError(e);
                }
                done.countDown();
            });
            Thread.sleep(50);
            long started = System.nanoTime();
            context.requestStop();
            assertTrue(done.await(2, TimeUnit.SECONDS));
            assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(1));
            assertTrue(context.stopRequested());
        }

        @Test
        @DisplayName("idle should end on wake without stopping")
        void idleEndsOnWake() throws Exception {
            PurgeContext context = new PurgeContext();
            CountDownLatch done = new CountDownLatch(1);
            worker(context, () -> {
                try {
                    context.idle(60_000, context.wakeups());
                } catch (InterruptedException e) {
                    throw new AssertionError(e);
                }
                done.countDown();
            });
            Thread.sleep(50);
            context.wake();
            assertTrue(done.await(2, TimeUnit.SECONDS));
            assertFalse(context.stopRequested());
        }

        @Test
        @DisplayName("idle should return at once after a wake since the count it was given")
        void idleCountsEarlierWake() throws Exception {
            PurgeContext context = new PurgeContext();
            long seen = context.wakeups();
            // As if a request arrived while the thread was busy between looking for work and waiting
            context.wake();

            long started = System.nanoTime();
            context.idle(60_000, seen);

            assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(1));
        }

        @Test
        @DisplayName("a stop should interrupt a blocking call inside interruptibly")
        void interruptsInsideSection() throws Exception {
            PurgeContext context = new PurgeContext();
            AtomicReference<Throwable> thrown = new AtomicReference<>();
            AtomicBoolean interruptedAfter = new AtomicBoolean(true);
            CountDownLatch entered = new CountDownLatch(1);
            Thread thread = worker(context, () -> {
                try {
                    context.interruptibly(() -> {
                        entered.countDown();
                        Thread.sleep(60_000);
                        return null;
                    });
                } catch (InterruptedException e) {
                    thrown.set(e);
                }
                interruptedAfter.set(Thread.currentThread().isInterrupted());
            });
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            context.requestStop();
            thread.join(2000);
            assertFalse(thread.isAlive());
            assertInstanceOf(InterruptedException.class, thrown.get());
            assertFalse(interruptedAfter.get(), "the interrupt must not outlive the call");
        }

        @Test
        @DisplayName("a stop should never interrupt the worker outside interruptibly")
        void noInterruptOutsideSection() throws Exception {
            PurgeContext context = new PurgeContext();
            CountDownLatch stopped = new CountDownLatch(1);
            AtomicBoolean interrupted = new AtomicBoolean();
            Thread thread = worker(context, () -> {
                try {
                    stopped.await();
                } catch (InterruptedException e) {
                    interrupted.set(true);
                }
                interrupted.set(interrupted.get() || Thread.currentThread().isInterrupted());
            });
            context.requestStop();
            stopped.countDown();
            thread.join(2000);
            assertFalse(interrupted.get());
        }

        @Test
        @DisplayName("interruptibly should refuse to start once a stop is requested")
        void refusesAfterStop() {
            PurgeContext context = new PurgeContext();
            context.requestStop();
            AtomicBoolean ran = new AtomicBoolean();
            assertThrows(InterruptedException.class, () -> context.interruptibly(() -> ran.getAndSet(true)));
            assertFalse(ran.get());
        }
    }

    @Nested
    @DisplayName("CooperativeGate")
    class Gate {

        private final AtomicBoolean flag = new AtomicBoolean();
        private final CooperativeGate gate = new CooperativeGate(flag::get, () -> flag.set(true), () -> flag.set(false));

        @Test
        @DisplayName("should hold the flag and clear it once on release")
        void holdsAndReleases() throws Exception {
            assertTrue(gate.acquire(new PurgeContext(), 100));
            assertTrue(flag.get());
            assertTrue(gate.isHeld());
            gate.release();
            assertFalse(flag.get());
            flag.set(true);
            gate.release();
            assertTrue(flag.get(), "a second release must not clear someone else's hold");
        }

        @Test
        @DisplayName("should wait for another holder to let go")
        void waitsForHolder() throws Exception {
            flag.set(true);
            Thread releaser = new Thread(() -> {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ignored) {
                }
                flag.set(false);
            });
            releaser.start();
            long started = System.nanoTime();
            assertTrue(gate.acquire(new PurgeContext(), 5_000));
            assertTrue(System.nanoTime() - started >= TimeUnit.MILLISECONDS.toNanos(90));
            gate.release();
        }

        @Test
        @DisplayName("should give up after the timeout without taking the flag")
        void timesOut() throws Exception {
            flag.set(true);
            assertFalse(gate.acquire(new PurgeContext(), 50));
            assertFalse(gate.isHeld());
            gate.release();
            assertTrue(flag.get());
        }

        @Test
        @DisplayName("should give up once a stop is requested")
        void stops() throws Exception {
            flag.set(true);
            PurgeContext context = new PurgeContext();
            context.requestStop();
            assertFalse(gate.awaitFree(context, 5_000));
            flag.set(false);
            assertFalse(gate.acquire(context, 5_000));
            assertFalse(flag.get());
        }
    }

    @Nested
    @DisplayName("Lease")
    class Leases {

        @Test
        @DisplayName("should release once, on the thread that took it")
        void releasesOnce() {
            AtomicInteger releases = new AtomicInteger();
            Lease lease = Lease.granted(null, releases::incrementAndGet);
            lease.close();
            lease.close();
            assertEquals(1, releases.get());
        }

        @Test
        @DisplayName("should refuse to release on another thread")
        void refusesOtherThread() throws Exception {
            AtomicInteger releases = new AtomicInteger();
            Lease lease = Lease.granted((Connection) null, releases::incrementAndGet);
            AtomicReference<Throwable> thrown = new AtomicReference<>();
            Thread other = new Thread(() -> {
                try {
                    lease.close();
                } catch (Throwable e) {
                    thrown.set(e);
                }
            });
            other.start();
            other.join();
            assertInstanceOf(IllegalStateException.class, thrown.get());
            assertEquals(0, releases.get());
            lease.close();
            assertEquals(1, releases.get());
        }

        @Test
        @DisplayName("refusals should carry their reason and hold nothing")
        void refusals() {
            Lease stop = Lease.stop(StopReason.MANUAL_PURGE);
            assertFalse(stop.isGranted());
            assertEquals(StopReason.MANUAL_PURGE, stop.stopReason());
            assertThrows(IllegalStateException.class, stop::connection);
            Lease busy = Lease.busy("a rollback is running");
            assertFalse(busy.isGranted());
            assertEquals("a rollback is running", busy.busyReason());
            assertDoesNotThrow(busy::close);
        }
    }

    @Nested
    @DisplayName("ChunkSizer")
    class Sizer {

        @Test
        @DisplayName("should start at 5,000 rows, halve above 100 ms and grow below 40 ms, within bounds")
        void adapts() {
            ChunkSizer sizer = new ChunkSizer();
            assertEquals(5_000, sizer.rows());
            sizer.record(TimeUnit.MILLISECONDS.toNanos(150));
            assertEquals(2_500, sizer.rows());
            sizer.record(TimeUnit.MILLISECONDS.toNanos(70));
            assertEquals(2_500, sizer.rows());
            sizer.record(TimeUnit.MILLISECONDS.toNanos(20));
            assertEquals(3_750, sizer.rows());
            for (int i = 0; i < 50; i++) {
                sizer.record(TimeUnit.SECONDS.toNanos(5));
            }
            assertEquals(ChunkSizer.MINIMUM_ROWS, sizer.rows());
            for (int i = 0; i < 50; i++) {
                sizer.record(0);
            }
            assertEquals(ChunkSizer.MAXIMUM_ROWS, sizer.rows());
        }

        @Test
        @DisplayName("should widen a rowid span over sparse ranges and narrow it over dense ones")
        void span() {
            ChunkSizer sizer = new ChunkSizer();
            assertEquals(50_000, sizer.span(10_000, 1_000, Long.MAX_VALUE));
            assertEquals(500, sizer.span(10_000, 100_000, Long.MAX_VALUE));
            assertEquals(1, sizer.span(1, 1_000_000, Long.MAX_VALUE));
            assertEquals(1_000, sizer.span(10_000, 1, 1_000));
            assertEquals(10_000, sizer.span(10_000, 0, Long.MAX_VALUE));
        }
    }
}
