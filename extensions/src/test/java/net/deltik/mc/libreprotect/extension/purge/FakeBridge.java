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

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.IntFunction;
import java.util.function.UnaryOperator;

/**
 * A {@link PurgeBridge} over a {@link TestDatabase}, which records what the
 * purge does with it and can be told to refuse or stop.
 */
final class FakeBridge implements PurgeBridge {

    final TestDatabase database;
    volatile Engine engine;
    volatile String prefix = "co_";
    volatile List<String> tables = List.of("block", "chat");
    volatile boolean entitySpawns;
    volatile String retention = "30d";
    volatile String time = "";
    volatile boolean databaseLock = true;
    volatile Object identity = "database";
    volatile StopReason stopReason;
    volatile String unavailable;
    volatile String settingsUnavailable;
    /** Whether the bridge can't tell whether the schema tracks entity spawns, as while CoreProtect refills its tables */
    volatile boolean entitySpawnsUnknown;
    /** Consulted for every lease, by its number from 1; returns a lease to hand out instead, or null */
    volatile IntFunction<Lease> leasePolicy = number -> null;
    /** Wraps each connection, to break or slow statements */
    volatile UnaryOperator<Connection> connections = UnaryOperator.identity();
    volatile boolean recoverFailures;
    volatile long stopTimeoutMillis;
    volatile long clickHouseRows;
    /** Thrown by every ClickHouse purge, if set */
    volatile SQLException clickHouseFailure;

    final AtomicInteger leases = new AtomicInteger();
    final AtomicInteger exclusiveLeases = new AtomicInteger();
    final AtomicInteger openLeases = new AtomicInteger();
    final AtomicLong rowsPurged = new AtomicLong();
    final AtomicInteger purgedCalls = new AtomicInteger();
    final AtomicInteger purgedCallsUnderLease = new AtomicInteger();
    final AtomicInteger abandoned = new AtomicInteger();
    final List<String> problems = new CopyOnWriteArrayList<>();
    final List<Long> clickHouseCutoffs = new CopyOnWriteArrayList<>();
    final List<SQLException> recoveryRequests = new CopyOnWriteArrayList<>();

    FakeBridge(TestDatabase database) {
        this.database = database;
        this.engine = database == null ? Engine.CLICKHOUSE : database.engine();
    }

    @Override
    public Engine activeEngine() {
        return engine;
    }

    @Override
    public String retentionSetting() {
        return retention;
    }

    @Override
    public String timeSetting() {
        return time;
    }

    @Override
    public boolean databaseLock() {
        return databaseLock;
    }

    @Override
    public String tablePrefix() {
        return prefix;
    }

    @Override
    public List<String> purgeableTables() {
        return new ArrayList<>(tables);
    }

    @Override
    public boolean tracksEntitySpawns() {
        return entitySpawns;
    }

    @Override
    public Object databaseIdentity() {
        return identity;
    }

    @Override
    public StopReason stopReason() {
        return stopReason;
    }

    @Override
    public String unavailableReason() {
        return unavailable;
    }

    @Override
    public String settingsUnavailableReason() {
        return settingsUnavailable;
    }

    @Override
    public Boolean entitySpawnTracking() {
        return entitySpawnsUnknown ? null : entitySpawns;
    }

    @Override
    public Lease lease(PurgeContext context, boolean exclusive) throws InterruptedException {
        int number = leases.incrementAndGet();
        Lease instead = leasePolicy.apply(number);
        if (instead != null) {
            return instead;
        }
        StopReason reason = stopReason;
        if (reason != null) {
            return Lease.stop(reason);
        }
        if (exclusive) {
            exclusiveLeases.incrementAndGet();
        }
        Connection connection = null;
        if (database != null) {
            try {
                connection = connections.apply(database.open());
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }
        Thread owner = Thread.currentThread();
        if (openLeases.incrementAndGet() != 1) {
            problems.add("more than one lease open at a time");
        }
        Connection opened = connection;
        return Lease.granted(connection, () -> {
            if (Thread.currentThread() != owner) {
                problems.add("lease released on " + Thread.currentThread().getName());
            }
            try {
                if (opened != null) {
                    opened.close();
                }
            } catch (SQLException e) {
                problems.add("close failed: " + e);
            }
            openLeases.decrementAndGet();
        });
    }

    @Override
    public long purgeClickHouse(long cutoff) throws SQLException {
        if (openLeases.get() != 1 || exclusiveLeases.get() == 0) {
            problems.add("ClickHouse purge without an exclusive lease");
        }
        clickHouseCutoffs.add(cutoff);
        if (clickHouseFailure != null) {
            throw clickHouseFailure;
        }
        return clickHouseRows;
    }

    @Override
    public boolean requestRecovery(SQLException failure) {
        recoveryRequests.add(failure);
        return recoverFailures;
    }

    @Override
    public void rowsPurged(long rows) {
        rowsPurged.addAndGet(rows);
    }

    @Override
    public void purged() {
        purgedCalls.incrementAndGet();
        if (openLeases.get() > 0) {
            purgedCallsUnderLease.incrementAndGet();
        }
    }

    @Override
    public long stopTimeoutMillis() {
        return stopTimeoutMillis;
    }

    @Override
    public void abandon() {
        abandoned.incrementAndGet();
    }

    List<String> problems() {
        return Collections.unmodifiableList(problems);
    }
}
