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
import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ChunkedPurge: ClickHouse")
class ChunkedPurgeClickHouseTest extends ChunkedPurgeFixture {

    @Test
    @DisplayName("should purge through CoreProtect's retention under one exclusive lease")
    void purges() {
        bridge = new FakeBridge(null);
        bridge.entitySpawns = true;
        bridge.clickHouseRows = 42;

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals(List.of(CUTOFF), bridge.clickHouseCutoffs);
        assertEquals(42, result.removed());
        assertEquals(42, bridge.rowsPurged.get());
        assertEquals(1, bridge.exclusiveLeases.get());
        // Once, before the lease lets the consumer go on, as after a manual purge
        assertEquals(1, bridge.purgedCallsUnderLease.get());
        assertEquals(1, bridge.purgedCalls.get());
    }

    @Test
    @DisplayName("should not have CoreProtect recheck anything when nothing was removed")
    void nothingRemoved() {
        bridge = new FakeBridge(null);

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals(0, bridge.purgedCalls.get());
    }

    @Test
    @DisplayName("should not repeat a purge that failed, since its mutation may still be running")
    void noRetry() {
        bridge = new FakeBridge(null);
        bridge.clickHouseFailure = new SQLException("Read timed out");

        PurgeResult result = purge(CUTOFF);

        assertEquals(StopReason.ERROR, result.stopReason());
        assertEquals("Read timed out", result.detail());
        assertEquals(List.of(CUTOFF), bridge.clickHouseCutoffs);
        assertEquals(0, bridge.rowsPurged.get());
    }

    @Test
    @DisplayName("should wait and try again while it can't take its claim")
    void retriesClaim() {
        bridge = new FakeBridge(null);
        bridge.clickHouseRows = 3;
        bridge.leasePolicy = number -> number <= 2 ? Lease.busy("a rollback is running") : null;

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals(List.of(CUTOFF), bridge.clickHouseCutoffs);
        assertEquals(3, result.removed());
    }

    @Test
    @DisplayName("should refuse while database-lock is disabled")
    void databaseLock() {
        bridge = new FakeBridge(null);
        bridge.databaseLock = false;

        PurgeResult result = purge(CUTOFF);

        assertEquals(StopReason.DATABASE_LOCK_DISABLED, result.stopReason());
        assertEquals("ClickHouse purges need database-lock: true in CoreProtect's config.yml",
            result.stopReason().because());
        assertEquals(List.of(), bridge.clickHouseCutoffs);
        assertEquals(0, bridge.leases.get());
    }
}
