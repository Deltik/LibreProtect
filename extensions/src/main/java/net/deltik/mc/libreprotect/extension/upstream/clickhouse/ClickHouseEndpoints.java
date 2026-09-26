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

import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.RowSink;
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import net.deltik.mc.libreprotect.extension.upstream.Capabilities;
import net.deltik.mc.libreprotect.extension.upstream.Capability;
import net.deltik.mc.libreprotect.extension.upstream.CoreProtectMigration;
import net.deltik.mc.libreprotect.extension.upstream.EngineEndpoints;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Config;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Target;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;

import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.SQLNonTransientConnectionException;

/**
 * Reading and writing CoreProtect 25's ClickHouse storage for
 * {@code /co migrate-db}, through upstream's own ClickHouse classes.
 *
 * <p>ClickHouse allows one CoreProtect writer per data folder. A source only
 * reads, over its own connections, so the active ClickHouse database can be
 * read while CoreProtect keeps it open. A sink becomes the writer when it's
 * prepared, and CoreProtect takes it over at activation.
 *
 * <p>Sources need {@link ClickHouseApi#READS}, sinks
 * {@link ClickHouseApi#WRITES}; a CoreProtect whose writer changed can still
 * be migrated away from. {@link #WAYS} registers them for migrations.
 */
public final class ClickHouseEndpoints implements EngineEndpoints {

    /**
     * How migrations read and write ClickHouse, for the ways of
     * {@code migrate-db.source.clickhouse} and
     * {@code migrate-db.target.clickhouse}
     */
    public static final CoreProtectMigration.EndpointWays WAYS = CoreProtectMigration.EndpointWays.of(Engine.CLICKHOUSE)
        .source("migration-reads", "CoreProtect's ClickHouse views, read over LibreProtect's own connections",
            upstream -> new ClickHouseEndpoints(need(upstream, ClickHouseApi.READS), null))
        .target("compatibility-rows", "CoreProtect's ClickHouse writer, whose prepared database CoreProtect takes over"
            + " as it is", upstream -> new ClickHouseEndpoints(null, need(upstream, ClickHouseApi.WRITES)));

    /** How to read ClickHouse, or {@code null} for endpoints that only write */
    private final Choice<ClickHouseApi> reads;
    /** How to write ClickHouse, or {@code null} for endpoints that only read */
    private final Choice<ClickHouseApi> writes;

    /**
     * For tests: endpoints that both read and write, with these
     * capabilities, such as those of an upstream that a test hid parts of.
     * Migrations get theirs through {@link #WAYS}.
     */
    ClickHouseEndpoints(Capabilities capabilities) {
        this(capabilities.get(ClickHouseApi.READS), capabilities.get(ClickHouseApi.WRITES));
    }

    private ClickHouseEndpoints(Choice<ClickHouseApi> reads, Choice<ClickHouseApi> writes) {
        this.reads = reads;
        this.writes = writes;
    }

    /**
     * @return how this upstream supports what a way of the endpoints needs,
     *         which it can't do without
     * @throws Missing why it's unavailable, never as an absent feature: the
     *                 way needs it, so the way isn't possible
     */
    private static Choice<ClickHouseApi> need(Upstream upstream, Capability<ClickHouseApi> capability)
        throws Missing {
        Choice<ClickHouseApi> choice = capability.probe(upstream);
        if (!choice.isAvailable()) {
            throw new Missing(choice.reason());
        }
        return choice;
    }

    @Override
    public Engine engine() {
        return Engine.CLICKHOUSE;
    }

    /**
     * @return a reader of an existing ClickHouse database, which may be the
     *         active one, over its own connections
     * @throws SQLFeatureNotSupportedException if LibreProtect can't read this
     *                                         CoreProtect's ClickHouse storage
     * @throws IllegalStateException for endpoints that only write
     */
    @Override
    public RowSource openSource(DatabaseSettings settings) throws SQLException {
        if (reads == null) {
            throw new IllegalStateException("These ClickHouse endpoints only write");
        }
        ClickHouseApi api = require(reads, "read");
        return new ClickHouseRowSource(api, config(api, settings), settings.prefix());
    }

    /**
     * @return a writer of a new, empty ClickHouse database, which registers as
     *         this installation's ClickHouse writer when prepared
     * @throws SQLFeatureNotSupportedException if LibreProtect can't write this
     *                                         CoreProtect's ClickHouse storage
     * @throws IllegalStateException for endpoints that only read
     */
    @Override
    public RowSink openSink(DatabaseSettings settings) throws SQLException {
        if (writes == null) {
            throw new IllegalStateException("These ClickHouse endpoints only read");
        }
        ClickHouseApi api = require(writes, "write");
        return new ClickHouseRowSink(api, config(api, settings), settings.prefix(), api.controlDirectory(),
            api.coreVersion(), IdentifierAssignments.coreProtect(api),
            new PublishDeadline(ClickHouseRowSink.PUBLISH_LIMIT, PublishDeadline.serverShuttingDown(api.flags())));
    }

    /**
     * Hand the prepared database behind a sink from {@link #openSink} over to
     * CoreProtect, whose {@code loadMigrationDatabase} activates it as it is,
     * without checking its unfinished-migration mark. So the sink keeps the
     * mark until CoreProtect uses the database: the caller clears it through
     * the sink after the activation, and marks the database unfinished again
     * through the sink if the activation fails.
     *
     * <p>From then on, closing the sink leaves the database open: once
     * activated, it's CoreProtect's. If activation fails, close it yourself to
     * release the ClickHouse writer registration; closing it again after
     * CoreProtect closed it is harmless.
     *
     * @return CoreProtect's {@code ClickHouseDatabase}
     * @throws IllegalArgumentException if the sink isn't from {@link #openSink}
     * @throws IllegalStateException    if the sink isn't prepared or is closed
     */
    @Override
    public Object handOver(RowSink sink) {
        return preparedDatabase(sink).upstream();
    }

    /**
     * As {@link #handOver}, with the database in its wrapper.
     */
    public static Target preparedDatabase(RowSink sink) {
        if (!(sink instanceof ClickHouseRowSink)) {
            throw new IllegalArgumentException("Not a ClickHouse sink: " + sink);
        }
        return ((ClickHouseRowSink) sink).handOver();
    }

    static Config config(ClickHouseApi api, DatabaseSettings settings) throws SQLException {
        if (settings.engine() != Engine.CLICKHOUSE) {
            throw new IllegalArgumentException("Not ClickHouse settings: " + settings);
        }
        try {
            return api.config(settings.host(), settings.port(), settings.database(), settings.username(),
                settings.password(), settings.tls());
        } catch (IllegalArgumentException e) {
            throw new SQLNonTransientConnectionException("Invalid ClickHouse settings: " + e.getMessage(), e);
        }
    }

    /**
     * @param action what the capability is for, as in "can't read"
     */
    private static ClickHouseApi require(Choice<ClickHouseApi> capability, String action)
        throws SQLFeatureNotSupportedException {
        if (!capability.isAvailable()) {
            throw new SQLFeatureNotSupportedException("LibreProtect can't " + action + " this CoreProtect's"
                + " ClickHouse storage: " + capability.reason());
        }
        return capability.orElse(null);
    }
}
