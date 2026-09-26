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

package net.deltik.mc.libreprotect.extension.migration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.sql.BatchUpdateException;
import java.sql.SQLDataException;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.sql.SQLNonTransientConnectionException;
import java.sql.SQLRecoverableException;
import java.sql.SQLTransientConnectionException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class BatchingTest {

    @Nested
    @DisplayName("BatchSizer")
    class Sizing {

        @Test
        @DisplayName("should grow fast batches toward a second each, doubling at most")
        void grows() {
            BatchSizer sizer = new BatchSizer();

            sizer.record(1_000, 100_000, 10_000_000L);
            assertEquals(2_000, sizer.size());
            for (int i = 0; i < 20; i++) {
                sizer.record(sizer.size(), sizer.size() * 100L, sizer.size() * 10_000L);
            }
            assertEquals(BatchSizer.MAXIMUM, sizer.size());
        }

        @Test
        @DisplayName("should shrink slow batches, halving at most, but not below the minimum")
        void shrinks() {
            BatchSizer sizer = new BatchSizer();

            sizer.record(1_000, 100_000, 10_000_000_000L);
            assertEquals(BatchSizer.MINIMUM, sizer.size());
            sizer.record(500, 50_000, 10_000_000_000L);
            assertEquals(BatchSizer.MINIMUM, sizer.size());
        }

        @Test
        @DisplayName("should settle where a batch takes about a second")
        void settles() {
            BatchSizer sizer = new BatchSizer();
            for (int i = 0; i < 20; i++) {
                sizer.record(sizer.size(), sizer.size() * 50L, sizer.size() * 200_000L);
            }
            assertEquals(5_000, sizer.size());
        }

        @Test
        @DisplayName("should keep batches of large rows small in memory")
        void boundsMemory() {
            BatchSizer sizer = new BatchSizer();
            for (int i = 0; i < 20; i++) {
                sizer.record(sizer.size(), sizer.size() * 10_000L, sizer.size() * 1_000L);
            }
            assertEquals(BatchSizer.MAXIMUM_BYTES / 10_000, sizer.size());
        }
    }

    @Nested
    @DisplayName("Retry")
    class Retrying {

        private final List<Long> sleeps = new ArrayList<>();
        private final List<String> heard = new ArrayList<>();

        private Retry retry(StopCheck stop) {
            return new Retry(stop, (what, attempt, retries, cause, delay) -> heard.add(what + " " + attempt + "/"
                + retries + " " + delay), sleeps::add);
        }

        @Test
        @DisplayName("should repeat transient failures with growing waits until the call succeeds")
        void retriesTransient() throws Exception {
            AtomicInteger calls = new AtomicInteger();

            String result = retry(StopCheck.NEVER).call("writing block", () -> {
                if (calls.incrementAndGet() < 3) {
                    throw new SQLTransientConnectionException("lost");
                }
                return "done";
            });

            assertEquals("done", result);
            assertEquals(List.of("writing block 1/5 1000", "writing block 2/5 2000"), heard);
            assertEquals(12, sleeps.size(), "waits in short steps to notice a stop");
            assertEquals(3_000, sleeps.stream().mapToLong(Long::longValue).sum());
        }

        @Test
        @DisplayName("should give up after five retries with the last error")
        void givesUp() {
            AtomicInteger calls = new AtomicInteger();

            SQLException thrown = assertThrows(SQLException.class, () -> retry(StopCheck.NEVER).call("x", () -> {
                throw new SQLRecoverableException("attempt " + calls.incrementAndGet());
            }));

            assertEquals("attempt 6", thrown.getMessage());
            assertEquals(Retry.RETRIES, heard.size());
            assertEquals(31_000, sleeps.stream().mapToLong(Long::longValue).sum());
        }

        @Test
        @DisplayName("should not repeat errors that won't pass")
        void permanent() {
            AtomicInteger calls = new AtomicInteger();

            assertThrows(SQLDataException.class, () -> retry(StopCheck.NEVER).call("x", () -> {
                calls.incrementAndGet();
                throw new SQLDataException("Data too long for column 'line_1'", "22001", 1406);
            }));

            assertEquals(1, calls.get());
        }

        @Test
        @DisplayName("should repeat a scan of a whole table only once, since each attempt may take long")
        void scansOnce() {
            AtomicInteger calls = new AtomicInteger();

            SQLException thrown = assertThrows(SQLException.class, () -> retry(StopCheck.NEVER).scan("counting block",
                () -> {
                    throw new SQLRecoverableException("attempt " + calls.incrementAndGet());
                }));

            assertEquals("attempt 2", thrown.getMessage());
            assertEquals(List.of("counting block 1/1 1000"), heard);
        }

        @Test
        @DisplayName("should not repeat a call that the connection's network timeout ended")
        void networkTimeout() {
            AtomicInteger calls = new AtomicInteger();

            assertThrows(SQLException.class, () -> retry(StopCheck.NEVER).call("reading block", () -> {
                calls.incrementAndGet();
                // What MySQL's driver throws once Connection.setNetworkTimeout passes
                throw new SQLRecoverableException("Communications link failure", "08S01",
                    new IOException("wrapped", new SocketTimeoutException("Read timed out")));
            }));

            assertEquals(1, calls.get());
            assertEquals(List.of(), heard);
        }

        @Test
        @DisplayName("should stop waiting when the migration has to stop")
        void stops() {
            MigrationException stop = new MigrationException("stopping");
            AtomicInteger checks = new AtomicInteger();

            MigrationException thrown = assertThrows(MigrationException.class, () -> retry(() -> {
                if (checks.incrementAndGet() > 2) {
                    throw stop;
                }
            }).call("x", () -> {
                throw new SQLTransientConnectionException("lost");
            }));

            assertSame(stop, thrown);
            assertEquals(2, sleeps.size());
        }
    }

    @Nested
    @DisplayName("TransientErrors")
    class Transience {

        @Test
        @DisplayName("should recognize errors that may pass")
        void transientErrors() {
            assertTrue(TransientErrors.isTransient(new SQLTransientConnectionException("x")));
            assertTrue(TransientErrors.isTransient(new SQLRecoverableException("x")));
            assertTrue(TransientErrors.isTransient(new SQLException("Communications link failure", "08S01")));
            assertTrue(TransientErrors.isTransient(new SQLException("Deadlock found", "40001", 1213)));
            assertTrue(TransientErrors.isTransient(new SQLException("Lock wait timeout exceeded", "HY000", 1205)));
            assertTrue(TransientErrors.isTransient(new SQLException("[SQLITE_BUSY] The database file is locked")));
            assertTrue(TransientErrors.isTransient(new SQLException("[SQLITE_BUSY_SNAPSHOT] snapshot")));
            assertTrue(TransientErrors.isTransient(new SQLException("wrapped", new SQLRecoverableException("x"))));
            BatchUpdateException batch = new BatchUpdateException("batch", new int[0]);
            batch.setNextException(new SQLException("Deadlock", "40001"));
            assertTrue(TransientErrors.isTransient(batch));
        }

        @Test
        @DisplayName("should recognize errors that won't pass")
        void permanentErrors() {
            assertFalse(TransientErrors.isTransient(new SQLIntegrityConstraintViolationException("dup", "23000", 1062)));
            assertFalse(TransientErrors.isTransient(new SQLDataException("too long", "22001", 1406)));
            assertFalse(TransientErrors.isTransient(new SQLException("[SQLITE_CONSTRAINT_PRIMARYKEY] UNIQUE")));
            assertFalse(TransientErrors.isTransient(new SQLException("no such table")));
            assertFalse(TransientErrors.isTransient(new SQLNonTransientConnectionException("Access denied", "08004")));
            assertFalse(TransientErrors.isTransient(new SQLDataException("bad", "08S01")));
            assertFalse(TransientErrors.isTransient(new SQLException("wrapped",
                new SQLNonTransientConnectionException("Unknown host", "08001"))));
            assertFalse(TransientErrors.isTransient(new SQLException("Communications link failure", "08S01",
                new SocketTimeoutException("Read timed out"))));
            assertFalse(TransientErrors.isTransient(new SQLException("Communications link failure", "08S01",
                new SocketTimeoutException("connect timed out"))));
        }
    }

    @Nested
    @DisplayName("Progress")
    class Progressing {

        @Test
        @DisplayName("should show a bar, the counts, the table, the rate and the time left")
        void line() {
            long[] now = {0};
            Progress progress = new Progress(line -> { }, "Copying", "rows", 41_150, true, () -> now[0]);

            assertEquals("Copying [######--------------] 30% 12,500 of 41,150 rows, block, 2,500 rows/s, about 11 s left",
                progress.line(12_500, "block", 5_000_000_000L));
            assertEquals("Copying [####################] 100% 41,150 of 41,150 rows, sign, 41,150 rows/s",
                progress.line(41_150, "sign", 1_000_000_000L));
        }

        @Test
        @DisplayName("should show validation progress without a rate")
        void withoutRate() {
            Progress progress = new Progress(line -> { }, "Validating", "rows compared", 3_000, false, () -> 0L);

            assertEquals("Validating [#####---------------] 25% 750 of 3,000 rows compared, user",
                progress.line(750, "user", 1_000_000_000L));
        }

        @Test
        @DisplayName("should show a line at most every five seconds")
        void throttles() {
            long[] now = {0};
            List<String> lines = new ArrayList<>();
            Progress progress = new Progress(lines::add, "Copying", "rows", 100, true, () -> now[0]);

            progress.update(10, "block");
            now[0] = 4_000_000_000L;
            progress.update(20, "block");
            now[0] = 5_000_000_000L;
            progress.update(30, "block");
            now[0] = 6_000_000_000L;
            progress.update(40, "block");

            assertEquals(1, lines.size());
            assertTrue(lines.get(0).startsWith("Copying [######--------------] 30% 30 of 100 rows"), lines.get(0));
        }

        @Test
        @DisplayName("should write durations in their two largest units")
        void durations() {
            assertEquals("0 s", Progress.duration(0));
            assertEquals("59 s", Progress.duration(59_000_000_000L));
            assertEquals("1 min 0 s", Progress.duration(60_000_000_000L));
            assertEquals("2 h 5 min", Progress.duration((2 * 3600 + 5 * 60 + 30) * 1_000_000_000L));
        }
    }
}
