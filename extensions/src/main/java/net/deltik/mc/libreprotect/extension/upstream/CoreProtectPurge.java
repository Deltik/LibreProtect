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
import net.deltik.mc.libreprotect.extension.purge.Lease;
import net.deltik.mc.libreprotect.extension.purge.PurgeBridge;
import net.deltik.mc.libreprotect.extension.purge.PurgeContext;
import net.deltik.mc.libreprotect.extension.purge.StopReason;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;

import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Automatic purging's side of whichever CoreProtect runs, by capability:
 * its settings ({@link PurgeSettings auto-purge.retention and
 * auto-purge.settings}), the signals it stops for, and what each database
 * engine needs ({@link PurgeEngine auto-purge.engine.*}), such as how it
 * takes turns with CoreProtect's own database work
 * ({@link Leases auto-purge.coordination}) and which tables it purges
 * ({@link PurgeTables auto-purge.tables}), each taken the newest way this
 * CoreProtect supports.
 *
 * <p>If this CoreProtect lacks something that purging its database needs,
 * purging stops before it touches the database, with
 * {@link StopReason#UNSUPPORTED_DATABASE}, and {@link #unavailableReason()}
 * says what. If it can't read {@code auto-purge}, so that whether purging
 * is on can't be told, {@link #settingsUnavailableReason()} says so.
 *
 * <p>Purging stops for every signal of this CoreProtect's that says to: a
 * shutdown, by any of the signals this CoreProtect gives (see
 * {@link Flags#shuttingDown()}); a migration; a manual purge, by
 * {@code purgeRunning} or a manual purge's worker; a conversion; a paused
 * consumer; a persistence halt; and a pending recovery of DuckDB.
 */
public final class CoreProtectPurge implements PurgeBridge {

    /**
     * What purging a database of any engine needs, which each engine's
     * {@link PurgeEngine} capability requires too; what one engine needs
     * besides, such as {@link Leases auto-purge.coordination} for all but
     * ClickHouse, is in its capability alone
     */
    private static final List<Capability<?>> REQUIRED = Collections.unmodifiableList(Arrays.asList(
        ActiveDatabase.CAPABILITY, Flags.CAPABILITY, ConsumerGate.CAPABILITY, PurgeSettings.RETENTION,
        PurgeSettings.CAPABILITY));
    /** What purging a database of any engine needs where this CoreProtect has it, as CoreProtect 25 does */
    private static final List<Capability<?>> REQUIRED_WHERE_PRESENT = Collections.unmodifiableList(Arrays.asList(
        Hooks.ENTITY_SPAWN_VERIFICATION, Hooks.PURGE_WORKER));

    private final ActiveDatabase database;
    private final Flags flags;
    private final ConsumerGate consumer;
    private final PurgeSettings.Retention retention;
    /** Why {@code auto-purge} can't be read, or {@code null} */
    private final String retentionUnavailable;
    private final PurgeSettings settings;
    private final PurgeTables tables;
    private final Leases leases;
    private final Hooks.AutoPurgeCounter counter;
    /** Why purged rows can't be counted for {@code /co status}, or {@code null} */
    private final String counterUnavailable;
    /** Whether the console was told that purged rows aren't counted */
    private final AtomicBoolean counterWarned = new AtomicBoolean();
    private final Hooks.EntitySpawnVerification verification;
    private final Hooks.PurgeWorker worker;
    private final Map<Engine, Choice<PurgeEngine>> engines = new EnumMap<>(Engine.class);
    /** Why no database can be purged, or {@code null} */
    private final String unavailable;

    private CoreProtectPurge(Capabilities capabilities) {
        database = capabilities.get(ActiveDatabase.CAPABILITY).orElse(null);
        flags = capabilities.get(Flags.CAPABILITY).orElse(null);
        consumer = capabilities.get(ConsumerGate.CAPABILITY).orElse(null);
        retention = capabilities.get(PurgeSettings.RETENTION).orElse(null);
        retentionUnavailable = unavailable(capabilities.get(PurgeSettings.RETENTION), false);
        settings = capabilities.get(PurgeSettings.CAPABILITY).orElse(null);
        // Only engines purged in chunks use these, and their capabilities require them
        tables = capabilities.get(PurgeTables.CAPABILITY).orElse(null);
        leases = capabilities.get(Leases.CAPABILITY).orElse(null);
        // Harmless without: rows purged just aren't counted, which rowsPurged says once
        counter = capabilities.get(Hooks.AUTO_PURGE_COUNTER).orElse(null);
        counterUnavailable = unavailable(capabilities.get(Hooks.AUTO_PURGE_COUNTER), true);
        verification = capabilities.get(Hooks.ENTITY_SPAWN_VERIFICATION).orElse(null);
        worker = capabilities.get(Hooks.PURGE_WORKER).orElse(null);
        for (Engine engine : Engine.values()) {
            engines.put(engine, capabilities.get(PurgeEngine.capability(engine)));
        }
        String reason = null;
        for (Capability<?> capability : REQUIRED) {
            reason = reason != null ? reason : unavailable(capabilities.get(capability), false);
        }
        for (Capability<?> capability : REQUIRED_WHERE_PRESENT) {
            reason = reason != null ? reason : unavailable(capabilities.get(capability), true);
        }
        unavailable = reason;
    }

    /**
     * @return automatic purging for the CoreProtect that shares
     *         LibreProtect's class loader
     */
    public static CoreProtectPurge create() {
        return create(Capabilities.current());
    }

    /**
     * @return automatic purging with these capabilities, such as those of an
     *         upstream that a test hid parts of
     */
    public static CoreProtectPurge create(Capabilities capabilities) {
        return new CoreProtectPurge(capabilities);
    }

    /**
     * For the probe of each engine's way: require what purging a database of
     * any engine needs, so that the capability report says that purging an
     * engine doesn't work whenever it doesn't, and why.
     *
     * @throws Missing why a capability that purging needs is unavailable, or
     *                 an absent feature if CoreProtect doesn't have one at all
     */
    static void requireForEveryEngine(Upstream upstream) throws Missing {
        for (Capability<?> capability : REQUIRED) {
            capability.probe(upstream).require();
        }
        for (Capability<?> capability : REQUIRED_WHERE_PRESENT) {
            Choice<?> choice = capability.probe(upstream);
            if (!choice.isAvailable() && !choice.isAbsent()) {
                throw new Missing(choice.reason());
            }
        }
    }

    /**
     * @param mayBeAbsent whether purging does without it where this
     *                    CoreProtect doesn't have it at all, as CoreProtect
     *                    24 has no manual purge worker to watch
     * @return why a capability that purging needs is unavailable, in the
     *         terms of what CoreProtect lacks, or {@code null} if purging can
     *         do with what there is
     */
    private static String unavailable(Choice<?> choice, boolean mayBeAbsent) {
        if (choice.isAvailable() || (mayBeAbsent && choice.isAbsent())) {
            return null;
        }
        return choice.reason();
    }

    @Override
    public Engine activeEngine() {
        return database == null ? null : database.activeEngine();
    }

    @Override
    public String retentionSetting() {
        return retention == null ? null : retention.value();
    }

    @Override
    public String settingsUnavailableReason() {
        return retentionUnavailable;
    }

    @Override
    public String timeSetting() {
        return settings == null ? null : settings.time();
    }

    /**
     * @return whether {@code database-lock} is on, as far as ClickHouse,
     *         which alone needs it, is concerned; false where ClickHouse
     *         can't be purged
     */
    @Override
    public boolean databaseLock() {
        PurgeEngine clickHouse = engines.get(Engine.CLICKHOUSE).orElse(null);
        return clickHouse instanceof PurgeEngine.ClickHouse && ((PurgeEngine.ClickHouse) clickHouse).databaseLock();
    }

    @Override
    public String tablePrefix() {
        return settings == null ? null : settings.tablePrefix();
    }

    @Override
    public List<String> purgeableTables() {
        return tables == null ? Collections.emptyList() : tables.purgeable();
    }

    /**
     * @return whether the schema of CoreProtect's database has
     *         {@code entity_spawn}, and leases can keep everyone else
     *         waiting while its orphans are cleaned up
     */
    @Override
    public boolean tracksEntitySpawns() {
        return Boolean.TRUE.equals(entitySpawnTracking());
    }

    /**
     * @return false only on a CoreProtect without any trace of CoreProtect
     *         25's design, whose schema never links rows to
     *         {@code entity_spawn}; otherwise true while CoreProtect's list
     *         of the schema's tables has {@code entity_spawn} and leases can
     *         be exclusive, or {@code null}. CoreProtect clears and refills
     *         that list whenever it creates a schema, so a list without
     *         {@code entity_spawn} may be one caught part-way
     */
    @Override
    public Boolean entitySpawnTracking() {
        if (tables == null) {
            return null;
        }
        if (!tables.mayLinkEntitySpawns()) {
            return false;
        }
        boolean cleanable = leases != null && leases.exclusive();
        return cleanable && tables.schema().contains("entity_spawn") ? Boolean.TRUE : null;
    }

    @Override
    public Object databaseIdentity() {
        PurgeEngine engine = supported(activeEngine());
        return engine == null ? null : engine.identity();
    }

    @Override
    public String unavailableReason() {
        return unsupported(activeEngine());
    }

    /**
     * @return why a database of the engine can't be purged, in the terms of
     *         what CoreProtect lacks, or {@code null} if it can
     */
    private String unsupported(Engine engine) {
        if (unavailable != null) {
            return unavailable;
        }
        if (engine == null) {
            return "CoreProtect uses a database engine that LibreProtect doesn't know";
        }
        Choice<PurgeEngine> choice = engines.get(engine);
        return choice.isAvailable() ? null : choice.reason() + ", which purging " + engine.displayName() + " needs";
    }

    /**
     * @return what purging a database of the engine needs, or {@code null}
     *         if it can't be purged
     */
    private PurgeEngine supported(Engine engine) {
        return unsupported(engine) == null ? engines.get(engine).orElse(null) : null;
    }

    @Override
    public StopReason stopReason() {
        return stopReason(false);
    }

    /**
     * @param holdingPurgeClaim whether this holds CoreProtect's purge claim,
     *                          which sets {@code purgeRunning} (ClickHouse)
     */
    private StopReason stopReason(boolean holdingPurgeClaim) {
        if (flags == null || consumer == null) {
            // Without the signals to stop for, purging can't start
            return StopReason.UNSUPPORTED_DATABASE;
        }
        if (flags.shuttingDown()) {
            return StopReason.SHUTDOWN;
        }
        // A migration on CoreProtect 24 sets purgeRunning too, so it comes first
        if (flags.migrationRunning()) {
            return StopReason.MIGRATION;
        }
        if ((flags.purgeRunning() && !holdingPurgeClaim) || (worker != null && worker.running())) {
            return StopReason.MANUAL_PURGE;
        }
        if (flags.converterRunning()) {
            return StopReason.CONVERSION;
        }
        if (flags.pauseConsumer()) {
            return StopReason.CONSUMER_PAUSED;
        }
        if (consumer.persistenceHalted()) {
            return StopReason.PERSISTENCE_HALTED;
        }
        Engine engine = activeEngine();
        PurgeEngine duckDB = engines.get(Engine.DUCKDB).orElse(null);
        if (engine == Engine.DUCKDB && duckDB != null && duckDB.recoveryPending()) {
            return StopReason.DATABASE_RECOVERY;
        }
        return unsupported(engine) != null ? StopReason.UNSUPPORTED_DATABASE : null;
    }

    @Override
    public Lease lease(PurgeContext context, boolean exclusive) throws InterruptedException {
        StopReason reason = stopReason();
        if (reason != null) {
            return Lease.stop(reason, reason == StopReason.UNSUPPORTED_DATABASE ? unavailableReason() : null);
        }
        PurgeEngine engine = supported(activeEngine());
        if (engine == null) {
            // The engine changed since
            return Lease.stop(StopReason.UNSUPPORTED_DATABASE, unavailableReason());
        }
        return engine.lease(leases, context, exclusive, this::stopReason);
    }

    @Override
    public long purgeClickHouse(long cutoff) throws SQLException {
        PurgeEngine engine = supported(Engine.CLICKHOUSE);
        if (engine == null) {
            throw new UnsupportedOperationException(unsupported(Engine.CLICKHOUSE));
        }
        return engine.purge(cutoff);
    }

    /**
     * CoreProtect itself takes up only failures of DuckDB that need it
     * reopened.
     */
    @Override
    public boolean requestRecovery(SQLException failure) {
        PurgeEngine duckDB = engines.get(Engine.DUCKDB).orElse(null);
        return duckDB != null && duckDB.requestRecovery(failure);
    }

    /**
     * Without CoreProtect's counter, warn the first time that rows it would
     * count were purged, since {@code /co status} leaves them out.
     */
    @Override
    public void rowsPurged(long rows) {
        if (counter != null) {
            counter.add(rows);
        } else if (rows > 0 && counterUnavailable != null && counterWarned.compareAndSet(false, true)) {
            LibreProtectLogger.warning("Auto-purge can't update /co status's count of purged rows with this CoreProtect"
                + " build: " + counterUnavailable + ".");
        }
    }

    @Override
    public void purged() {
        if (verification != null) {
            verification.invalidate();
        }
    }

    @Override
    public long stopTimeoutMillis() {
        return leases == null ? 0 : leases.stopTimeoutMillis();
    }

    @Override
    public void abandon() {
        if (leases != null) {
            leases.abandon();
        }
    }
}
