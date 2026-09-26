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

import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.MigrationBridge;
import net.deltik.mc.libreprotect.extension.migration.MigrationException;
import net.deltik.mc.libreprotect.extension.migration.MigrationSession;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;

import java.sql.SQLDataException;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executor;

/**
 * {@code /co migrate-db} for whichever CoreProtect runs, by what it offers:
 * the {@link MigrationProtocol} that holds and switches it, and for each
 * engine, how the migration reads it as the source and writes it as the
 * target, which are capabilities of their own. So one engine that CoreProtect
 * changed turns off migrations from or to that engine, not all of them.
 *
 * <p>An engine is a source or a target if CoreProtect's database selector
 * has it, the migration has {@linkplain #ENDPOINTS endpoints} for it that
 * CoreProtect supports, such as its schema code for a target, and
 * CoreProtect has what the engine needs besides, such as its settings (see
 * {@link EngineSide}). Between an engine of the legacy encoding and a
 * columnar one, the migration needs CoreProtect's conversions too.
 */
public final class CoreProtectMigration implements MigrationBridge {

    /**
     * How the migration reads and writes each engine; one line per engine.
     * An engine that CoreProtect has without a line here is unavailable as a
     * source and a target.
     */
    private static final List<EndpointWays> ENDPOINTS = Arrays.asList(
        JdbcEndpoints.SQLITE,
        JdbcEndpoints.MYSQL,
        JdbcEndpoints.DUCKDB);

    private static final Map<Engine, Capability<EngineSide>> SOURCES = new EnumMap<>(Engine.class);
    private static final Map<Engine, Capability<EngineSide>> TARGETS = new EnumMap<>(Engine.class);

    static {
        for (Engine engine : Engine.values()) {
            EndpointWays ways = null;
            for (EndpointWays candidate : ENDPOINTS) {
                if (candidate.engine == engine) {
                    ways = candidate;
                }
            }
            SOURCES.put(engine, capability(engine, ways == null ? null : ways.source, false));
            TARGETS.put(engine, capability(engine, ways == null ? null : ways.target, true));
        }
    }

    private final Choice<ActiveDatabase> database;
    private final Choice<MigrationProtocol> protocol;
    private final Choice<Codecs> codecs;
    private final Map<Engine, Choice<EngineSide>> sources = new EnumMap<>(Engine.class);
    private final Map<Engine, Choice<EngineSide>> targets = new EnumMap<>(Engine.class);
    /** Where the protocol runs tasks on the server's thread, if not where CoreProtect's scheduler runs them */
    private final Executor serverThread;

    /**
     * @param capabilities what this CoreProtect offers, such as one that a
     *                     test probed with parts hidden
     */
    public CoreProtectMigration(Capabilities capabilities) {
        this(capabilities, null);
    }

    /**
     * @param serverThread runs the protocol's tasks for the server's thread,
     *                     for tests without a server, or {@code null} for
     *                     CoreProtect's scheduler
     */
    CoreProtectMigration(Capabilities capabilities, Executor serverThread) {
        database = capabilities.get(ActiveDatabase.CAPABILITY);
        protocol = capabilities.get(MigrationProtocol.CAPABILITY);
        codecs = capabilities.get(Codecs.CAPABILITY);
        for (Engine engine : Engine.values()) {
            sources.put(engine, capabilities.get(source(engine)));
            targets.put(engine, capabilities.get(target(engine)));
        }
        this.serverThread = serverThread;
    }

    /**
     * @return migrations for the CoreProtect that shares LibreProtect's class loader
     */
    public static CoreProtectMigration create() {
        return new CoreProtectMigration(Capabilities.current());
    }

    /**
     * @return the migrations that this CoreProtect has but LibreProtect
     *         can't do with it, for the console: why not, by what users know
     *         them as, such as {@code /co migrate-db to ClickHouse}. Without
     *         the protocol, that's all of them, and one entry.
     */
    static Map<String, String> unavailableFeatures(Capabilities capabilities) {
        Map<String, String> features = new LinkedHashMap<>();
        Choice<MigrationProtocol> protocol = capabilities.get(MigrationProtocol.CAPABILITY);
        if (!protocol.isAvailable()) {
            if (!protocol.isAbsent()) {
                features.put("/co migrate-db", protocol.reason());
            }
            return features;
        }
        for (Engine engine : Engine.values()) {
            Choice<EngineSide> from = capabilities.get(source(engine));
            Choice<EngineSide> to = capabilities.get(target(engine));
            boolean noSource = !from.isAvailable() && !from.isAbsent();
            boolean noTarget = !to.isAvailable() && !to.isAbsent();
            if (noSource && noTarget && from.reason().equals(to.reason())) {
                features.put("/co migrate-db from and to " + engine.displayName(), from.reason());
                continue;
            }
            if (noSource) {
                features.put("/co migrate-db from " + engine.displayName(), from.reason());
            }
            if (noTarget) {
                features.put("/co migrate-db to " + engine.displayName(), to.reason());
            }
        }
        Choice<Codecs> codecs = capabilities.get(Codecs.CAPABILITY);
        if (!codecs.isAvailable() && !codecs.isAbsent()) {
            features.put("/co migrate-db between SQLite or MySQL and DuckDB or ClickHouse", codecs.reason());
        }
        return features;
    }

    /**
     * @return the capability of reading an engine as a migration's source,
     *         {@code migrate-db.source.<engine>}
     */
    public static Capability<EngineSide> source(Engine engine) {
        return SOURCES.get(engine);
    }

    /**
     * @return the capability of writing an engine as a migration's target,
     *         {@code migrate-db.target.<engine>}
     */
    public static Capability<EngineSide> target(Engine engine) {
        return TARGETS.get(engine);
    }

    /**
     * @return the engines that CoreProtect has and a migration can write
     */
    @Override
    public Set<Engine> engines() {
        Set<Engine> engines = EnumSet.noneOf(Engine.class);
        for (Map.Entry<Engine, Choice<EngineSide>> target : targets.entrySet()) {
            if (target.getValue().isAvailable()) {
                engines.add(target.getKey());
            }
        }
        return Collections.unmodifiableSet(engines);
    }

    /**
     * @return the engine CoreProtect uses now, or {@code null} if it's one
     *         LibreProtect doesn't know, or its selector isn't available
     */
    @Override
    public Engine activeEngine() {
        ActiveDatabase active = database.orElse(null);
        return active == null ? null : active.activeEngine();
    }

    @Override
    public String unavailableReason() {
        return protocol.isAvailable() ? null : protocol.reason();
    }

    /**
     * An engine that CoreProtect doesn't have at all has no reason: it's
     * simply not one of the {@link #engines()}.
     */
    @Override
    public String unavailableReason(Engine target) {
        Choice<EngineSide> writes = targets.get(target);
        if (!writes.isAvailable()) {
            return writes.isAbsent() ? null : writes.reason();
        }
        Engine source = activeEngine();
        if (source == null) {
            return "CoreProtect uses a database engine that LibreProtect doesn't know";
        }
        if (source == target) {
            return null;
        }
        Choice<EngineSide> reads = sources.get(source);
        if (!reads.isAvailable()) {
            return "CoreProtect's " + source.displayName() + " database can't be read: " + reads.reason();
        }
        if (source.isColumnar() != target.isColumnar() && !codecs.isAvailable()) {
            return source.displayName() + " and " + target.displayName() + " encode data differently, and"
                + " CoreProtect's conversions aren't available: " + codecs.reason();
        }
        return null;
    }

    /**
     * Set {@code migrationRunning} unless something rules the migration out
     * now. On CoreProtect 24, this runs on the thread that runs commands,
     * like CoreProtect's shutdown, which clears {@code purgeRunning} once it
     * sees {@code migrationRunning}; so the two can't interleave. On
     * CoreProtect 25, the migration's thread begins the database reload that
     * pauses persistence later; CoreProtect's shutdown refuses to begin one
     * once it starts, and waits while {@code migrationRunning} is set.
     *
     * <p>CoreProtect checks the unfinished-migration mark of a database it
     * starts on only with {@code database-lock: true}.
     */
    @Override
    public MigrationSession claim(Engine target) throws MigrationException {
        MigrationProtocol protocol = requireProtocol();
        Flags flags = protocol.flags();
        if (flags.shuttingDown()) {
            throw new MigrationException("CoreProtect isn't running: it didn't start, or the server is stopping.");
        }
        if (flags.migrationRunning()) {
            throw new MigrationException("A migration is already running.");
        }
        if (flags.converterRunning()) {
            throw new MigrationException("CoreProtect is upgrading its database. Wait for it to finish.");
        }
        String refusal = protocol.pause().refusal();
        if (refusal != null) {
            throw new MigrationException(refusal);
        }
        if (flags.rollbacksRunning()) {
            throw new MigrationException("A rollback or restore is running. Wait for it to finish.");
        }
        if (!protocol.selection().databaseLockEnabled()) {
            throw new MigrationException("Migrations need database-lock: true in config.yml, so that CoreProtect"
                + " refuses to start on an unfinished target. Set it, restart the server, and try again.");
        }
        if (protocol.gate().persistenceHalted()) {
            throw new MigrationException("CoreProtect stopped saving events after a database failure. Restart the"
                + " server before migrating.");
        }
        Engine source = activeEngine();
        if (source == target) {
            throw new MigrationException("CoreProtect already uses " + target.displayName() + ".");
        }
        String unavailable = unavailableReason(target);
        if (unavailable != null) {
            throw new MigrationException("Migrating to " + target.displayName() + " isn't available with this"
                + " CoreProtect build: " + unavailable);
        }
        if (!targets.get(target).isAvailable()) {
            throw new MigrationException(target.displayName() + " isn't available with this CoreProtect version.");
        }
        MigrationSession session = new CoreProtectMigrationSession(protocol, source, target, requireSide(sources, source),
            requireSide(targets, target));
        flags.setMigrationRunning(true);
        return session;
    }

    private MigrationProtocol requireProtocol() throws MigrationException {
        MigrationProtocol chosen = protocol.orElse(null);
        if (chosen == null) {
            throw new MigrationException("/co migrate-db isn't available with this CoreProtect build: "
                + protocol.reason());
        }
        return serverThread == null ? chosen : chosen.onServerThread(serverThread);
    }

    private static EngineSide requireSide(Map<Engine, Choice<EngineSide>> sides, Engine engine)
        throws MigrationException {
        try {
            return sides.get(engine).require();
        } catch (Missing e) {
            throw new MigrationException(e.getMessage(), e);
        }
    }

    /**
     * Convert entity data and block metadata between the legacy encoding of
     * SQLite and MySQL and the columnar one of DuckDB and ClickHouse.
     */
    @Override
    public Object transcode(String table, String column, Object value, Engine from, Engine to) throws SQLException {
        if (from.isColumnar() == to.isColumnar()) {
            return value;
        }
        Codecs chosen = codecs.orElse(null);
        if (chosen == null) {
            throw new SQLDataException("CoreProtect can't convert " + table + "." + column + " for "
                + to.displayName() + ": " + codecs.reason());
        }
        return chosen.transcode(table, column, value, from, to);
    }

    /**
     * Without CoreProtect's conversions, no migration crosses encodings, so
     * values compare as they are.
     */
    @Override
    public Object canonical(String table, String column, Object value) throws SQLException {
        Codecs chosen = codecs.orElse(null);
        return chosen == null ? value : chosen.canonical(table, column, value);
    }

    /**
     * The capability of reading or writing an engine: CoreProtect must have
     * the engine, and the migration a way to reach it that CoreProtect
     * supports, with what CoreProtect has of the engine besides, such as
     * its settings (see {@link EngineSide}).
     *
     * @param way how, or {@code null} if the migration has none for the engine
     * @param target whether it's the target's capability rather than the source's
     */
    private static Capability<EngineSide> capability(Engine engine, Way way, boolean target) {
        String id = (target ? "migrate-db.target." : "migrate-db.source.") + engine.configName();
        if (way == null) {
            return Capability.of(id, Choice.way("endpoints", "the migration's endpoints for "
                + engine.displayName(), upstream -> {
                    requireEngine(upstream, engine);
                    throw new Missing("LibreProtect can't " + (target ? "write " : "read ") + engine.displayName()
                        + " databases in migrations yet");
                }));
        }
        return Capability.of(id, Choice.way(way.strategy, way.description, upstream -> {
            requireEngine(upstream, engine);
            return EngineSide.probe(upstream, engine, way.probe.probe(upstream), target);
        }));
    }

    /**
     * Only a CoreProtect without the multi-engine design lacks the columnar
     * engines, however it names their classes. Every migration needs the
     * protocol, so an engine's side does too: the capability report says
     * that migrating from or to an engine doesn't work whenever it doesn't.
     *
     * @throws Missing an absent feature for a columnar engine on a
     *                 CoreProtect without the multi-engine design, and
     *                 otherwise why its database selector doesn't offer it,
     *                 or why the protocol is unavailable
     */
    private static void requireEngine(Upstream upstream, Engine engine) throws Missing {
        if (engine.isColumnar()) {
            Designs.MULTI_ENGINE.requireIn(upstream);
        }
        ActiveDatabase selector = MigrationProtocol.need(upstream, ActiveDatabase.CAPABILITY);
        if (!selector.engines().contains(engine)) {
            throw new Missing(upstream.name() + "'s database selector has no " + engine.displayName() + ", only "
                + selector);
        }
        MigrationProtocol.CAPABILITY.probe(upstream).require();
    }

    /**
     * One way of reading or writing an engine, before what every engine
     * needs is checked.
     */
    private static final class Way {
        final String strategy;
        final String description;
        final Choice.Probe<? extends EngineEndpoints> probe;

        Way(String strategy, String description, Choice.Probe<? extends EngineEndpoints> probe) {
            this.strategy = Objects.requireNonNull(strategy, "strategy");
            this.description = Objects.requireNonNull(description, "description");
            this.probe = Objects.requireNonNull(probe, "probe");
        }
    }

    /**
     * How a migration reads one engine as its source and writes it as its
     * target: the ways of the engine's {@code migrate-db.source} and
     * {@code migrate-db.target} capabilities, such as
     * <pre>
     * EndpointWays.of(Engine.SQLITE)
     *     .source("jdbc", "the migration's own SQLite connections", probe)
     *     .target("jdbc", "CoreProtect's schema code, through ...", probe)
     * </pre>
     * where each probe resolves what it needs of CoreProtect. Whether
     * CoreProtect has the engine is checked before.
     */
    public static final class EndpointWays {
        private final Engine engine;
        private final Way source;
        private final Way target;

        private EndpointWays(Engine engine, Way source, Way target) {
            this.engine = Objects.requireNonNull(engine, "engine");
            this.source = source;
            this.target = target;
        }

        /**
         * @return no ways yet of reading or writing the engine
         */
        public static EndpointWays of(Engine engine) {
            return new EndpointWays(engine, null, null);
        }

        /**
         * @param strategy the way's name in the capability report, such as {@code jdbc}
         * @param description the way in short plain English
         * @return these ways, reading the engine as a source with {@code probe}'s endpoints
         */
        public EndpointWays source(String strategy, String description, Choice.Probe<? extends EngineEndpoints> probe) {
            return new EndpointWays(engine, new Way(strategy, description, probe), target);
        }

        /**
         * @return these ways, writing the engine as a target with {@code probe}'s endpoints
         */
        public EndpointWays target(String strategy, String description, Choice.Probe<? extends EngineEndpoints> probe) {
            return new EndpointWays(engine, source, new Way(strategy, description, probe));
        }
    }
}
