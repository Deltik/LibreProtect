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

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.purge.DatabaseIdentity;
import net.deltik.mc.libreprotect.extension.purge.Lease;
import net.deltik.mc.libreprotect.extension.purge.PurgeContext;
import net.deltik.mc.libreprotect.extension.purge.StopReason;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.InstanceField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;

import java.io.File;
import java.sql.SQLException;
import java.util.Collections;
import java.util.List;

/**
 * What automatic purging needs of CoreProtect for one database engine, each
 * engine a capability of its own, which requires what purging needs for
 * every engine too, so that it's unavailable whenever purging the engine
 * can't work. SQLite, MySQL and DuckDB are purged with deletes in small rowid
 * ranges of the tables of {@link PurgeTables auto-purge.tables}, each under
 * a lease of {@link Leases auto-purge.coordination}; DuckDB also needs its
 * exclusive leases, for the orphan cleanup and the {@code CHECKPOINT} after
 * it, and CoreProtect's recovery of DuckDB. ClickHouse is purged with
 * CoreProtect's own retention, in one call, which needs
 * {@code database-lock}.
 *
 * <p>Only a CoreProtect without the multi-engine layer lacks DuckDB and
 * ClickHouse, so that alone makes their capabilities absent, however
 * CoreProtect names their classes.
 */
public abstract class PurgeEngine {

    public static final Capability<PurgeEngine> SQLITE = Capability.of("auto-purge.engine.sqlite",
        Choice.way("chunked-deletes", "deletes old rows a small batch at a time, taking turns with CoreProtect's own"
            + " database work and its consumer", PurgeEngine::sqlite));

    public static final Capability<PurgeEngine> MYSQL = Capability.of("auto-purge.engine.mysql",
        Choice.way("chunked-deletes", "deletes old rows a small batch at a time, taking turns with CoreProtect's own"
            + " database work", PurgeEngine::mySQL));

    public static final Capability<PurgeEngine> DUCKDB = Capability.of("auto-purge.engine.duckdb",
        Choice.way("chunked-deletes", "deletes old rows a small batch at a time, taking turns with CoreProtect's own"
            + " database work, then checkpoints the database file while nothing else uses it", PurgeEngine::duckDB));

    public static final Capability<PurgeEngine> CLICKHOUSE = Capability.of("auto-purge.engine.clickhouse",
        Choice.way("retention", "CoreProtect's ClickHouse retention, under a manual purge's claim",
            ClickHouse::new));

    PurgeEngine() {
    }

    /**
     * @return the capability of purging an engine
     */
    public static Capability<PurgeEngine> capability(Engine engine) {
        switch (engine) {
            case SQLITE:
                return SQLITE;
            case MYSQL:
                return MYSQL;
            case DUCKDB:
                return DUCKDB;
            case CLICKHOUSE:
                return CLICKHOUSE;
            default:
                throw new IllegalArgumentException("No capability of purging " + engine.displayName());
        }
    }

    /**
     * @return something that changes when CoreProtect's database of this
     *         engine is replaced, or {@code null} if unknown
     */
    public abstract Object identity();

    /**
     * Take a lease for one unit of purge work on this engine.
     *
     * @see Leases#lease
     */
    public Lease lease(Leases leases, PurgeContext context, boolean exclusive, Leases.Stops stops)
        throws InterruptedException {
        return leases.lease(context, false, exclusive, stops);
    }

    /**
     * Delete rows older than {@code cutoff} with CoreProtect's own
     * retention, under an exclusive lease.
     *
     * @return rows removed
     * @throws UnsupportedOperationException for an engine purged in chunks
     */
    public long purge(long cutoff) throws SQLException {
        throw new UnsupportedOperationException("This engine is purged in chunks");
    }

    /**
     * Hand a failure to CoreProtect's recovery of this engine's database, if
     * it has one and the failure needs the database reopened.
     *
     * @return whether it was; the purge must stop
     */
    public boolean requestRecovery(SQLException failure) {
        return false;
    }

    /**
     * @return whether CoreProtect is about to reopen or reopening this
     *         engine's database after a failure
     */
    public boolean recoveryPending() {
        return false;
    }

    /**
     * Require what purging in chunks needs: what purging any engine needs,
     * the tables to purge, and leases to take turns with CoreProtect's own
     * database work.
     *
     * @throws Missing why one of them is unavailable
     */
    private static Leases chunked(Upstream upstream) throws Missing {
        CoreProtectPurge.requireForEveryEngine(upstream);
        PurgeTables.CAPABILITY.probe(upstream).require();
        return Leases.CAPABILITY.probe(upstream).require();
    }

    private static PurgeEngine sqlite(Upstream upstream) throws Missing {
        chunked(upstream);
        UpstreamClass handler = upstream.type(Names.CONFIG_HANDLER);
        StaticField path = handler.staticField("path", String.class);
        StaticField file = handler.staticField("sqlite", String.class);
        return new PurgeEngine() {
            /**
             * A manual purge on SQLite rebuilds the database in a new file
             * and moves it over the old one.
             */
            @Override
            public Object identity() {
                return DatabaseIdentity.ofFile(path.get() + String.valueOf(file.get()));
            }

            /**
             * On SQLite, the consumer and a purge would otherwise write at the
             * same time, and one of them would wait on SQLite's lock.
             */
            @Override
            public Lease lease(Leases leases, PurgeContext context, boolean exclusive, Leases.Stops stops)
                throws InterruptedException {
                return leases.lease(context, true, exclusive, stops);
            }
        };
    }

    private static PurgeEngine mySQL(Upstream upstream) throws Missing {
        chunked(upstream);
        UpstreamClass handler = upstream.type(Names.CONFIG_HANDLER);
        StaticField host = handler.staticField("host", String.class);
        StaticField port = handler.staticField("port", int.class);
        StaticField database = handler.staticField("database", String.class);
        return new PurgeEngine() {
            @Override
            public Object identity() {
                return DatabaseIdentity.ofServer((String) host.get(), port.getInt(), (String) database.get());
            }
        };
    }

    private static PurgeEngine duckDB(Upstream upstream) throws Missing {
        Designs.MULTI_ENGINE.requireIn(upstream);
        if (!chunked(upstream).exclusive()) {
            throw new Missing(upstream.name() + " has no claims that keep every other database user waiting, which"
                + " DuckDB's orphan cleanup and CHECKPOINT need");
        }
        // Only what purging uses of CoreProtect's recovery, which hook.duckdb-recovery offers more of
        UpstreamClass recovery = upstream.type(Names.DUCKDB_RECOVERY);
        StaticMethod<Boolean, RuntimeException> request = recovery.staticMethod("request", boolean.class,
            Throwable.class);
        StaticMethod<Boolean, RuntimeException> pending = recovery.staticMethod("isPending", boolean.class);
        upstream.relyOn("has CoreProtect reopen DuckDB after a failure that needs it, and says whether it will",
            request);
        UpstreamClass handler = upstream.type(Names.CONFIG_HANDLER);
        StaticField path = handler.staticField("path", String.class);
        StaticField file = handler.staticField("duckdb", String.class);
        upstream.doc("docs/auto-purge.md", "DuckDB removes old rows in small chunks too, and is checkpointed after"
            + " cleanup");
        return new PurgeEngine() {
            @Override
            public Object identity() {
                return DatabaseIdentity.ofFile(new File(String.valueOf(path.get()), String.valueOf(file.get()))
                    .getPath());
            }

            @Override
            public boolean requestRecovery(SQLException failure) {
                return request.call(failure);
            }

            @Override
            public boolean recoveryPending() {
                return pending.call();
            }
        };
    }

    /**
     * ClickHouse purges with its own connections, under the same exclusion
     * as CoreProtect's manual ClickHouse purge: its purge claim, which sets
     * {@code purgeRunning}, then a wait until the consumer has parked. Other
     * maintenance is refused, the consumer stays parked, and new lookups get
     * no connection ("database busy") rather than waiting.
     *
     * <p>A background purge claim would take CoreProtect's database write
     * lock instead, and hold it for the whole purge, which can take minutes:
     * every connection request would wait meanwhile, including API lookups
     * on the server thread.
     */
    static final class ClickHouse extends PurgeEngine {

        /** How long a purge waits for the consumer to finish its batch and park */
        private static final long CONSUMER_PARK_WAIT_MILLIS = 30_000;
        /** Longer than the consumer's 100 ms between checks of whether to stay parked */
        private static final long CONSUMER_RECHECK_MILLIS = 150;

        private final StaticMethod<?, RuntimeException> claim;
        private final StaticMethod<Void, RuntimeException> release;
        private final StaticMethod<Boolean, RuntimeException> consumerRunning;
        private final StaticField parked;
        private final StaticMethod<Long, SQLException> retention;
        private final StaticMethod<?, RuntimeException> global;
        private final InstanceField databaseLock;

        ClickHouse(Upstream upstream) throws Missing {
            Designs.MULTI_ENGINE.requireIn(upstream);
            CoreProtectPurge.requireForEveryEngine(upstream);
            UpstreamClass config = upstream.type(Names.CONFIG);
            global = config.staticMethod("getGlobal", config.type());
            databaseLock = config.field("DATABASE_LOCK", boolean.class);
            UpstreamClass consumer = upstream.type(Names.CONSUMER);
            claim = consumer.staticMethod("claimPurge", Object.class);
            upstream.type(claim.returnType()).asEnum().require(StartResult.Kind.STARTED.name());
            release = consumer.staticMethod("releasePurge", void.class);
            consumerRunning = consumer.staticMethod("isRunning", boolean.class);
            // Protected: CoreProtect's purge command reaches it by extending Consumer
            parked = consumer.staticField("pausedSuccess", boolean.class);
            retention = upstream.type(Names.DATABASE).staticMethod("purgeClickHouse", long.class, long.class,
                long.class, int.class, List.class, boolean.class).throwing(SQLException.class);

            upstream.relyOn("refuses while a purge, a rollback, a database reload or a persistence halt is on, and"
                + " otherwise sets purgeRunning, which those then refuse to start alongside", claim);
            upstream.relyOn("clears purgeRunning", release);
            upstream.relyOn("waits between batches while purgeRunning is set, with pausedSuccess set, checking every"
                + " 100 ms", Names.CONSUMER, "pauseConsumer(I)V");
            upstream.relyOn("gives no connection without force while purgeRunning is set", Names.DATABASE,
                "getConnection(ZZZI)Ljava/sql/Connection;");
            upstream.relyOn("refuses without database-lock, and otherwise has the active ClickHouse database purge",
                retention);
            String range = "(JJILjava/util/List;Z)J";
            upstream.relyOn("has its retention purge, once it's open and owns its dataset", Names.CLICKHOUSE_DATABASE,
                "purge" + range);
            upstream.relyOn("drops the monthly partitions that the time range covers, deletes the rest of its rows,"
                + " and cleans up what they leave of entities, one purge at a time; where CoreProtect has a lookup"
                + " index, it refuses while mutations of the event table are unfinished, such as an earlier purge's"
                + " deletions, and closes the index to lookups until it completes", Names.CLICKHOUSE_RETENTION,
                "purge" + range);
            upstream.relyOnSince(Designs.CLICKHOUSE_LOOKUP_INDEX, "opens the lookup index again when CoreProtect"
                + " opens the database after a purge that didn't complete, but refuses to open the database while"
                + " mutations of the event table are unfinished", Names.CLICKHOUSE_LOOKUP_INDEX,
                "recover(Ljava/sql/Connection;Ljava/lang/String;Ljava/lang/String;Ljava/util/UUID;)V");
            upstream.relyOnSince(Designs.CLICKHOUSE_LOOKUP_INDEX, "closes or opens the lookup index to lookups for"
                + " the installation that owns the purge, which lookups read only while no installation's is closed",
                Names.CLICKHOUSE_LOOKUP_INDEX, "setReady(Ljava/sql/Connection;Ljava/lang/String;Ljava/util/UUID;Z)V");
            upstream.relyOn("cancels purges in progress, then waits for purgeRunning to clear before it closes the"
                + " database", Names.SHUTDOWN_SERVICE, "safeShutdown(Lorg/bukkit/plugin/Plugin;)V");
            upstream.relyOn("waits, for up to 15 minutes, while purgeRunning is set", Names.SHUTDOWN_SERVICE,
                "waitForMaintenanceCompletion(J)V");
            upstream.relyOn("cancels a ClickHouse purge in progress, whoever started it", Names.PURGE_COMMAND,
                "cancelForShutdown()V");
            upstream.relyOn("has the active ClickHouse database cancel its purge in progress", Names.DATABASE,
                "cancelClickHousePurge()V");
            upstream.relyOn("has its retention cancel its purge in progress", Names.CLICKHOUSE_DATABASE,
                "cancelPurge()V");
            upstream.relyOn("makes a purge in progress fail", Names.CLICKHOUSE_RETENTION, "cancelPurge()V");
            upstream.doc("docs/auto-purge.md", "ClickHouse purges with its columnar retention, dropping monthly"
                + " partitions that the time range covers, and refuses to purge while database-lock is disabled");
        }

        /**
         * @return whether {@code database-lock} is on, without which
         *         CoreProtect refuses to purge ClickHouse
         */
        boolean databaseLock() {
            return databaseLock.getBoolean(global.call());
        }

        /**
         * A ClickHouse purge is one call, so there is nothing to tell apart.
         */
        @Override
        public Object identity() {
            return null;
        }

        @Override
        public Lease lease(Leases leases, PurgeContext context, boolean exclusive, Leases.Stops stops)
            throws InterruptedException {
            StartResult claimed = StartResult.of(claim.call());
            if (!claimed.started()) {
                return ClaimLeases.refused(claimed, context);
            }
            boolean granted = false;
            try {
                StopReason reason = stops.check(true);
                if (reason != null) {
                    return Lease.stop(reason);
                }
                if (!awaitConsumerParked(context, stops)) {
                    reason = stops.check(true);
                    return reason != null ? Lease.stop(reason) : Lease.busy("the consumer is still writing");
                }
                Lease lease = Lease.granted(null, this::releaseClaim);
                granted = true;
                return lease;
            } finally {
                if (!granted) {
                    releaseClaim();
                }
            }
        }

        /**
         * Wait until the consumer, told to pause by {@code purgeRunning}, is
         * parked between batches. It must stay parked across one of its
         * checks, so that a consumer that was just leaving its wait as the
         * claim was taken isn't mistaken for a parked one.
         *
         * @return whether it parked before the timeout and a stop
         */
        private boolean awaitConsumerParked(PurgeContext context, Leases.Stops stops) throws InterruptedException {
            long deadline = System.nanoTime() + CONSUMER_PARK_WAIT_MILLIS * 1_000_000L;
            while (!context.stopRequested() && stops.check(true) == null && System.nanoTime() - deadline < 0) {
                if (!consumerRunning.call()) {
                    return true;
                }
                if (parked.getBoolean()) {
                    context.pause(CONSUMER_RECHECK_MILLIS);
                    if (parked.getBoolean()) {
                        return !context.stopRequested();
                    }
                } else {
                    context.pause(10);
                }
            }
            return false;
        }

        private void releaseClaim() {
            try {
                release.call();
            } catch (RuntimeException e) {
                LibreProtectLogger.severe("Auto-purge couldn't release its purge claim: " + e);
            }
        }

        /**
         * All worlds, no block filter, no {@code OPTIMIZE FINAL}: the path of
         * an unfiltered {@code /co purge}.
         */
        @Override
        public long purge(long cutoff) throws SQLException {
            return retention.call(0L, cutoff, 0, Collections.emptyList(), false);
        }
    }
}
