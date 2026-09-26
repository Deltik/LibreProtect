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
import net.deltik.mc.libreprotect.extension.common.PurgeChunkLock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.LongStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * What the tests of {@link ChunkedPurge} share: a database of the engine a
 * test chooses, a fake bridge to CoreProtect, and a purge with a 30-day
 * retention. The tests are split by concern into classes of their own, which
 * run in separate JVMs at the same time.
 */
abstract class ChunkedPurgeFixture {

    static final long CUTOFF = 1_700_000_000L;
    static final long DAY = 86400;

    @TempDir
    Path directory;

    TestDatabase database;
    FakeBridge bridge;
    final PurgeContext context = new PurgeContext();
    final RecordingLog log = new RecordingLog();
    Supplier<StopReason> runChecks = () -> null;

    @AfterEach
    void tearDown() throws SQLException {
        if (bridge != null) {
            assertEquals(List.of(), bridge.problems(), "lease problems");
            assertEquals(0, bridge.openLeases.get(), "leases left open");
        }
        assertFalse(PurgeChunkLock.isHeldByCurrentThread(), "the chunk lock is left held");
        if (database != null) {
            database.close();
        }
    }

    void setUp(Engine engine) throws SQLException {
        database = TestDatabase.create(engine, directory);
        bridge = new FakeBridge(database);
        context.bind(Thread.currentThread());
    }

    PurgeResult purge(long cutoff) {
        return purge(cutoff, false);
    }

    PurgeResult purge(long cutoff, boolean orphansPending) {
        return purger(cutoff).timing(0, 1, 60_000).run(orphansPending);
    }

    /**
     * A purge with a 30-day retention: it runs 30 days after the cutoff
     */
    ChunkedPurge purger(long cutoff) {
        return new ChunkedPurge(bridge, context, log, () -> runChecks.get(), cutoff, cutoff + 30 * DAY);
    }

    long count(String sql) throws SQLException {
        return database.count(sql);
    }

    static long[] range(long from, long to) {
        return LongStream.rangeClosed(from, to).toArray();
    }

    static long[] repeat(long value, int times) {
        long[] values = new long[times];
        Arrays.fill(values, value);
        return values;
    }

    void insert(String table, long[] rowids, long[] times) throws SQLException {
        database.insert(table, rowids, times);
    }
}
