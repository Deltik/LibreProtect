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

package net.deltik.mc.libreprotect.extension.upstream.clickhouse;

import net.deltik.mc.libreprotect.extension.upstream.Names;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.testutil.CoreProtectFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

class PublishDeadlineTest {

    @RegisterExtension
    final CoreProtectFixture coreProtect = new CoreProtectFixture();

    private final AtomicBoolean shuttingDown = new AtomicBoolean();
    private final PublishDeadline deadline = new PublishDeadline(Duration.ofMillis(300), shuttingDown::get);

    @AfterEach
    void tearDown() {
        deadline.close();
        coreProtect.reset();
        // Never leave an interrupt behind for the next test
        Thread.interrupted();
    }

    @Test
    @DisplayName("should stop a publication at once when the server starts shutting down")
    void shutdown() throws Exception {
        PublishDeadline fiveMinutes = new PublishDeadline(Duration.ofMinutes(5), shuttingDown::get);
        Thread shutdown = new Thread(() -> {
            try {
                Thread.sleep(300);
            } catch (InterruptedException e) {
                return;
            }
            shuttingDown.set(true);
        });
        try {
            long start = System.nanoTime();
            shutdown.start();

            PublishDeadline.ExpiredException e = assertThrows(PublishDeadline.ExpiredException.class,
                () -> fiveMinutes.run("the 5 chat rows", PublishDeadlineTest::retryLikeCoreProtect));

            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1_500);
            assertEquals("Writing the 5 chat rows to ClickHouse stopped because the server is shutting down:"
                + " Interrupted while republishing a ClickHouse batch partition: sleep interrupted", e.getMessage());
            assertFalse(Thread.currentThread().isInterrupted(), "the interrupt outlived the publication");
        } finally {
            shutdown.join();
            fiveMinutes.close();
        }
    }

    @Test
    @DisplayName("should stop a publication at once when aborted from another thread, and refuse the next")
    void abort() throws Exception {
        PublishDeadline fiveMinutes = new PublishDeadline(Duration.ofMinutes(5), () -> false);
        Thread aborter = new Thread(() -> {
            try {
                Thread.sleep(300);
            } catch (InterruptedException e) {
                return;
            }
            fiveMinutes.abort();
        });
        try {
            long start = System.nanoTime();
            aborter.start();

            PublishDeadline.ExpiredException e = assertThrows(PublishDeadline.ExpiredException.class,
                () -> fiveMinutes.run("the 5 chat rows", PublishDeadlineTest::retryLikeCoreProtect));

            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1_500);
            assertEquals("Writing the 5 chat rows to ClickHouse stopped because the migration is stopping:"
                + " Interrupted while republishing a ClickHouse batch partition: sleep interrupted", e.getMessage());
            assertFalse(Thread.currentThread().isInterrupted(), "the interrupt outlived the publication");
            int[] runs = {0};
            assertEquals("Writing the rows to ClickHouse didn't start because the migration is stopping",
                assertThrows(PublishDeadline.ExpiredException.class,
                    () -> fiveMinutes.run("the rows", () -> runs[0]++)).getMessage());
            assertEquals(0, runs[0]);
        } finally {
            aborter.join();
            fiveMinutes.close();
        }
    }

    @Test
    @DisplayName("should abort without a publication running, without throwing")
    void abortIdle() {
        assertDoesNotThrow(deadline::abort);
        assertDoesNotThrow(deadline::abort);
        assertThrows(PublishDeadline.ExpiredException.class, () -> deadline.run("the rows", () -> {
        }));
    }

    @Test
    @DisplayName("should not start a publication once the server is shutting down")
    void noStartDuringShutdown() {
        shuttingDown.set(true);
        int[] runs = {0};

        PublishDeadline.ExpiredException e = assertThrows(PublishDeadline.ExpiredException.class,
            () -> deadline.run("the cleared incomplete-migration mark", () -> runs[0]++));

        assertEquals("Writing the cleared incomplete-migration mark to ClickHouse didn't start because the server is"
            + " shutting down", e.getMessage());
        assertEquals(0, runs[0]);
    }

    @Test
    @DisplayName("should keep enforcing the limit when the shutdown check fails")
    void brokenShutdownCheck() {
        PublishDeadline broken = new PublishDeadline(Duration.ofMillis(300), () -> {
            throw new IllegalStateException("CoreProtect isn't loaded");
        });
        try {
            PublishDeadline.ExpiredException e = assertThrows(PublishDeadline.ExpiredException.class,
                () -> broken.run("the rows", PublishDeadlineTest::retryLikeCoreProtect));
            assertTrue(e.getMessage().startsWith("Writing the rows to ClickHouse didn't succeed within 300 ms"),
                e.getMessage());
        } finally {
            broken.close();
        }
    }

    @Test
    @DisplayName("should let a publication that finishes in time succeed")
    void inTime() throws SQLException {
        int[] runs = {0};

        deadline.run("the rows", () -> runs[0]++);

        assertEquals(1, runs[0]);
        assertFalse(Thread.currentThread().isInterrupted());
    }

    @Test
    @DisplayName("should pass a failure within the limit through as it is")
    void failureInTime() {
        SQLException failure = new SQLException("Code: 241. MEMORY_LIMIT_EXCEEDED");

        assertSame(failure, assertThrows(SQLException.class, () -> deadline.run("the rows", () -> {
            throw failure;
        })));
    }

    @Test
    @DisplayName("should stop a publication that keeps retrying, and clear the interrupt it caused")
    void retryingForever() {
        long start = System.nanoTime();

        PublishDeadline.ExpiredException e = assertThrows(PublishDeadline.ExpiredException.class,
            () -> deadline.run("the 5 chat rows", PublishDeadlineTest::retryLikeCoreProtect));

        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 5_000);
        assertEquals("Writing the 5 chat rows to ClickHouse didn't succeed within 300 ms of retrying:"
            + " Interrupted while republishing a ClickHouse batch partition: sleep interrupted", e.getMessage());
        assertFalse(Thread.currentThread().isInterrupted(), "the interrupt outlived the publication");
    }

    @Test
    @DisplayName("should let a publication that ends well after the limit succeed, without a stray interrupt")
    void finishesLate() throws Exception {
        // Like a request in flight, which the interrupt doesn't stop
        deadline.run("the rows", () -> {
            long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(600);
            while (System.nanoTime() < end) {
                Thread.onSpinWait();
            }
        });

        assertFalse(Thread.currentThread().isInterrupted());
        Thread.sleep(50);
    }

    @Test
    @DisplayName("should keep an interrupt from elsewhere")
    void otherInterrupt() {
        SQLException failure = new SQLException("Interrupted while publishing a ClickHouse batch");

        assertSame(failure, assertThrows(SQLException.class, () -> deadline.run("the rows", () -> {
            Thread.currentThread().interrupt();
            throw failure;
        })));
        assertTrue(Thread.interrupted());
    }

    @Test
    @DisplayName("should never interrupt the thread after the publication ends")
    void noLateInterrupt() throws Exception {
        PublishDeadline tight = new PublishDeadline(Duration.ofMillis(1), () -> false);
        try {
            for (int attempt = 0; attempt < 40; attempt++) {
                // Around the watchdog's first check, which expires the publication, so it
                // fires just before, during and after publications end
                long spin = TimeUnit.MILLISECONDS.toNanos(PublishDeadline.POLL_MILLIS - 10)
                    + TimeUnit.MICROSECONDS.toNanos(attempt * 500L);
                try {
                    tight.run("the rows", () -> {
                        long end = System.nanoTime() + spin;
                        while (System.nanoTime() < end) {
                            Thread.onSpinWait();
                        }
                    });
                } catch (PublishDeadline.ExpiredException e) {
                    fail("a publication that returned normally failed: " + e);
                }
                assertFalse(Thread.currentThread().isInterrupted(), "attempt " + attempt);
            }
            Thread.sleep(20);
        } finally {
            tight.close();
        }
    }

    @Test
    @DisplayName("should describe limits in words")
    void describe() {
        assertEquals("5 minutes", PublishDeadline.describe(Duration.ofMinutes(5)));
        assertEquals("1 minute", PublishDeadline.describe(Duration.ofMinutes(1)));
        assertEquals("90 seconds", PublishDeadline.describe(Duration.ofSeconds(90)));
        assertEquals("1 second", PublishDeadline.describe(Duration.ofSeconds(1)));
        assertEquals("300 ms", PublishDeadline.describe(Duration.ofMillis(300)));
        assertThrows(IllegalArgumentException.class, () -> new PublishDeadline(Duration.ZERO, () -> false));
    }

    @Nested
    @DisplayName("With CoreProtect's own publisher")
    class CoreProtectPublisher {

        @TempDir
        Path controlDirectory;

        private final ExecutorService executor = Executors.newSingleThreadExecutor();
        private ClickHouseApi api;

        @BeforeEach
        void setUp() {
            api = ClickHouseTestServer.writes();
        }

        @AfterEach
        void tearDown() {
            executor.shutdownNow();
        }

        @Test
        @DisplayName("CoreProtect's writer gives up on a refused publication by itself")
        void givesUp() throws Exception {
            coreProtect.set("ConfigHandler.serverRunning", true);
            try (UnreachablePublication publication = new UnreachablePublication(api, controlDirectory)) {
                Future<SQLException> publishing = executor.submit(
                    () -> assertThrows(SQLException.class, publication::publish));

                // If it retries for as long as the server runs again, only the deadline's limit ends a publication
                // that ClickHouse keeps refusing, and PublishDeadline's Javadoc should say so
                SQLException e = assertDoesNotThrow(() -> publishing.get(30, TimeUnit.SECONDS),
                    "CoreProtect's writer no longer gives up by itself");
                assertFalse(interrupted(e), e::toString);
            }
        }

        @Test
        @DisplayName("CoreProtect's writer stops as soon as it's interrupted while it waits, which is how the"
            + " deadline stops it")
        void stopsWhenInterrupted() throws Exception {
            coreProtect.set("ConfigHandler.serverRunning", true);
            try (UnreachablePublication publication = new UnreachablePublication(api, controlDirectory)) {
                AtomicReference<Thread> worker = new AtomicReference<>();
                CountDownLatch started = new CountDownLatch(1);
                Future<SQLException> publishing = executor.submit(() -> {
                    worker.set(Thread.currentThread());
                    started.countDown();
                    try {
                        return assertThrows(SQLException.class, () -> publishUntilInterrupted(publication));
                    } finally {
                        Thread.interrupted();
                    }
                });
                assertTrue(started.await(5, TimeUnit.SECONDS));
                awaitWaiting(worker.get(), publishing);

                long interrupted = System.nanoTime();
                worker.get().interrupt();

                SQLException e = publishing.get(5, TimeUnit.SECONDS);
                long stoppedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - interrupted);
                assertTrue(interrupted(e), () -> "not stopped by the interrupt: " + e);
                assertTrue(stoppedMillis < 1_000, "stopped " + stoppedMillis + " ms after the interrupt");
            }
        }

        @Test
        @DisplayName("should stop CoreProtect's writer as soon as CoreProtect starts shutting down")
        void stopsOnShutdown() throws Exception {
            coreProtect.set("ConfigHandler.serverRunning", true);
            BooleanSupplier signal = PublishDeadline.serverShuttingDown(api.flags());
            PublishDeadline fiveMinutes = new PublishDeadline(Duration.ofMinutes(5), signal);
            try (UnreachablePublication publication = new UnreachablePublication(api, controlDirectory)) {
                assertFalse(signal.getAsBoolean());
                AtomicReference<Thread> worker = new AtomicReference<>();
                CountDownLatch started = new CountDownLatch(1);
                Future<Boolean> publishing = executor.submit(() -> {
                    worker.set(Thread.currentThread());
                    started.countDown();
                    PublishDeadline.ExpiredException e = assertThrows(PublishDeadline.ExpiredException.class,
                        () -> fiveMinutes.run("the incomplete-migration mark",
                            () -> publishUntilInterrupted(publication)));
                    assertTrue(e.getMessage().startsWith("Writing the incomplete-migration mark to ClickHouse stopped"
                        + " because the server is shutting down: "), e.getMessage());
                    return Thread.currentThread().isInterrupted();
                });
                assertTrue(started.await(5, TimeUnit.SECONDS));
                awaitWaiting(worker.get(), publishing);

                // What CoreProtect's shutdown does first
                long raised = System.nanoTime();
                consumer("blockDatabaseReloadForShutdown");

                assertFalse(publishing.get(5, TimeUnit.SECONDS), "the interrupt outlived the publication");
                long stoppedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - raised);
                assertTrue(stoppedMillis < 1_500, "stopped " + stoppedMillis + " ms after the shutdown signal");
                assertTrue(signal.getAsBoolean());
                int[] runs = {0};
                assertEquals("Writing the rows to ClickHouse didn't start because the server is shutting down",
                    assertThrows(PublishDeadline.ExpiredException.class,
                        () -> fiveMinutes.run("the rows", () -> runs[0]++)).getMessage());
                assertEquals(0, runs[0]);
            } finally {
                fiveMinutes.close();
                // What CoreProtect does when it starts again, resetting the signal
                consumer("initialize");
            }
        }
    }

    /**
     * Publish through CoreProtect's writer again each time it gives up by
     * itself, until an interrupt stops it, so that a stop never comes too late
     * to find it retrying, however slow the machine.
     */
    private static void publishUntilInterrupted(UnreachablePublication publication) throws SQLException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        while (true) {
            try {
                publication.publish();
                return;
            } catch (SQLException e) {
                // Also an interrupt that CoreProtect reported otherwise, for the caller to find; never forever
                if (interrupted(e) || Thread.currentThread().isInterrupted() || System.nanoTime() - deadline > 0) {
                    throw e;
                }
            }
        }
    }

    /**
     * Wait until a thread publishing through CoreProtect's writer waits, as
     * it does for an insert's answer, for a connection, and between attempts.
     */
    private static void awaitWaiting(Thread thread, Future<?> publishing) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (thread.getState() != Thread.State.WAITING && thread.getState() != Thread.State.TIMED_WAITING) {
            assertFalse(publishing.isDone(), "CoreProtect's writer ended without waiting");
            assertTrue(System.nanoTime() < deadline, "CoreProtect's writer never waited");
            Thread.sleep(1);
        }
    }

    /**
     * @return whether an interrupt ended the failed publication, by
     *         CoreProtect's way of reporting one: an
     *         {@link InterruptedException} among its causes
     */
    private static boolean interrupted(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof InterruptedException) {
                return true;
            }
        }
        return false;
    }

    /**
     * Call one of CoreProtect's {@code Consumer} methods without parameters.
     */
    private static void consumer(String method) throws Exception {
        Upstream.coreProtect().type(Names.CONSUMER).staticMethod(method, void.class).call();
    }

    /**
     * Retry the way some of CoreProtect's development builds' publisher did
     * while the server ran: forever, sleeping between attempts, until
     * interrupted.
     */
    private static void retryLikeCoreProtect() throws SQLException {
        while (true) {
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new SQLException("Interrupted while republishing a ClickHouse batch partition", e);
            }
        }
    }
}
