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

import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Design;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;

import java.sql.Connection;
import java.util.concurrent.Executor;

/**
 * How {@code /co migrate-db} holds CoreProtect and switches it to another
 * database: a {@link Pause} and a {@link Selection} that belong together,
 * with what both need of CoreProtect. They come as one capability, so that
 * one CoreProtect's way of pausing is never paired with another's way of
 * switching:
 * <ol>
 *   <li>{@code reload-lifecycle}, CoreProtect's database reload lifecycle and
 *       its {@code database-type} setting, as CoreProtect 25 has them;</li>
 *   <li>{@code flag-protocol}, the purge, pause and gate flags and the
 *       {@code use-mysql} setting of CoreProtect 24.</li>
 * </ol>
 * CoreProtect 25 keeps CoreProtect 24's flags with other meanings, so the
 * flag protocol is only taken when CoreProtect shows no trace of the
 * multi-engine design or of the reload lifecycle. A CoreProtect with only
 * part of the reload lifecycle leaves migrations unavailable.
 *
 * <p>The protocol needs only what every engine needs; what one engine
 * needs belongs to its {@link EngineSide}. Hooks that tidy up after the
 * switch are used where CoreProtect has them: without one, the switch says
 * so and goes on.
 */
public final class MigrationProtocol {

    public static final Capability<MigrationProtocol> CAPABILITY = Capability.of("migrate-db.protocol",
        Choice.way("reload-lifecycle", "CoreProtect's database reload lifecycle, and its database-type setting",
            Designs.MULTI_ENGINE, MigrationProtocol::reloadLifecycle),
        Choice.way("flag-protocol", "CoreProtect's purge, pause and gate flags, and its use-mysql setting",
            MigrationProtocol::flagProtocol));

    /**
     * The parts of CoreProtect's database reload lifecycle that aren't
     * traces of the multi-engine design, which rules out the flag protocol
     * by itself: any of them rules it out too
     */
    static final Design RELOAD_LIFECYCLE = Design.of("database reload lifecycle",
        Names.CONSUMER + "#lockDatabaseReload",
        Names.CONSUMER + "#endDatabaseReload",
        Names.CONSUMER + "#blockDatabaseReloadForShutdown",
        Names.CONSUMER + "#databaseReloadShutdownSignal",
        Names.CONSUMER + "#haltPersistence",
        Names.CONSUMER + "#isDatabaseReloadRunning",
        Names.CONSUMER + "#isDatabaseReloadPaused",
        Names.CONSUMER + "#isDatabaseReloadBlocked");

    private static final String DOC = "docs/database-migration.md";

    private final Pause pause;
    private final Selection selection;
    private final ActiveDatabase database;
    private final Flags flags;
    private final ConsumerGate gate;
    private final StaticMethod<Connection, RuntimeException> getConnection;
    /** How to wait for CoreProtect's connections to close, or {@code null} where it doesn't track them */
    private final StaticMethod<Boolean, InterruptedException> awaitDrain;
    private final Choice<Hooks.LockHeartbeat> heartbeat;
    private final Choice<Hooks.EntitySpawnVerification> spawnVerification;
    private final Choice<Hooks.DuckDBRecovery> recovery;

    private MigrationProtocol(Pause pause, Selection selection, ActiveDatabase database, Flags flags,
                              ConsumerGate gate, StaticMethod<Connection, RuntimeException> getConnection,
                              StaticMethod<Boolean, InterruptedException> awaitDrain,
                              Choice<Hooks.LockHeartbeat> heartbeat,
                              Choice<Hooks.EntitySpawnVerification> spawnVerification,
                              Choice<Hooks.DuckDBRecovery> recovery) {
        this.pause = pause;
        this.selection = selection;
        this.database = database;
        this.flags = flags;
        this.gate = gate;
        this.getConnection = getConnection;
        this.awaitDrain = awaitDrain;
        this.heartbeat = heartbeat;
        this.spawnVerification = spawnVerification;
        this.recovery = recovery;
    }

    private static MigrationProtocol reloadLifecycle(Upstream upstream) throws Missing {
        Pause pause = ReloadLifecyclePause.probe(upstream);
        Selection selection = DatabaseTypeSelection.probe(upstream);
        UpstreamClass databaseClass = upstream.type(Names.DATABASE);
        StaticMethod<Boolean, InterruptedException> awaitDrain = databaseClass.staticMethod("awaitConnectionDrain",
            boolean.class, long.class).throwing(InterruptedException.class);
        upstream.doc(DOC, "a migration pauses persistence through a database reload, copies from the loaded"
            + " settings, and changes database-type only once CoreProtect uses the target");
        return new MigrationProtocol(pause, selection, need(upstream, ActiveDatabase.CAPABILITY),
            flags(upstream), need(upstream, ConsumerGate.CAPABILITY), getConnection(upstream),
            awaitDrain, Hooks.LOCK_HEARTBEAT.probe(upstream), Hooks.ENTITY_SPAWN_VERIFICATION.probe(upstream),
            Hooks.DUCKDB_RECOVERY.probe(upstream));
    }

    private static MigrationProtocol flagProtocol(Upstream upstream) throws Missing {
        for (String trace : RELOAD_LIFECYCLE.traces()) {
            int hash = trace.indexOf('#');
            upstream.requireAbsent(hash < 0 ? trace : trace.substring(0, hash),
                hash < 0 ? null : trace.substring(hash + 1), "part of its " + RELOAD_LIFECYCLE + ", which replaced"
                    + " the flag protocol for migrations");
        }
        Pause pause = FlagProtocolPause.probe(upstream);
        Selection selection = UseMySQLSelection.probe(upstream);
        upstream.doc(DOC, "a migration copies to the target that config.yml sets up while CoreProtect keeps using"
            + " the source, then switches CoreProtect over");
        return new MigrationProtocol(pause, selection, need(upstream, ActiveDatabase.CAPABILITY),
            flags(upstream), need(upstream, ConsumerGate.CAPABILITY), getConnection(upstream), null,
            Hooks.LOCK_HEARTBEAT.probe(upstream), Hooks.ENTITY_SPAWN_VERIFICATION.probe(upstream),
            Hooks.DUCKDB_RECOVERY.probe(upstream));
    }

    /**
     * @return CoreProtect's lifecycle flags, with those that a migration sets
     *         found writable, which only migrations need
     */
    static Flags flags(Upstream upstream) throws Missing {
        return need(upstream, Flags.CAPABILITY).forMigrations(upstream);
    }

    private static StaticMethod<Connection, RuntimeException> getConnection(Upstream upstream) throws Missing {
        return upstream.type(Names.DATABASE).staticMethod("getConnection", Connection.class, boolean.class,
            int.class);
    }

    /**
     * @return what another capability gives, which this way can't do without
     * @throws Missing why it's unavailable, never as an absent feature: the
     *                 way needs it, so the way isn't possible
     */
    static <T> T need(Upstream upstream, Capability<T> capability) throws Missing {
        Choice<T> choice = capability.probe(upstream);
        if (!choice.isAvailable()) {
            throw new Missing(choice.reason());
        }
        return choice.orElse(null);
    }

    /**
     * @return what another capability gives, or {@code null} if it isn't
     *         available, for steps that are skipped without it
     */
    static <T> T orNull(Upstream upstream, Capability<T> capability) {
        return capability.probe(upstream).orElse(null);
    }

    Pause pause() {
        return pause;
    }

    Selection selection() {
        return selection;
    }

    ActiveDatabase database() {
        return database;
    }

    Flags flags() {
        return flags;
    }

    ConsumerGate gate() {
        return gate;
    }

    /**
     * @return a connection to CoreProtect's active database, skipping its
     *         wait for the consumer's gate, or {@code null} if CoreProtect's
     *         database is busy
     */
    Connection connection() {
        return getConnection.call(true, 0);
    }

    /**
     * @return whether every connection CoreProtect handed out is closed;
     *         true at once where CoreProtect doesn't track them
     */
    boolean awaitDrain(long timeoutMillis) throws InterruptedException {
        return awaitDrain == null || awaitDrain.call(timeoutMillis);
    }

    /**
     * @return CoreProtect's lock heartbeat, as far as it has one
     */
    Choice<Hooks.LockHeartbeat> heartbeat() {
        return heartbeat;
    }

    /**
     * @return CoreProtect's check of tracked entities, as far as it has one
     */
    Choice<Hooks.EntitySpawnVerification> spawnVerification() {
        return spawnVerification;
    }

    /**
     * @return CoreProtect's recovery of DuckDB, as far as it has one
     */
    Choice<Hooks.DuckDBRecovery> recovery() {
        return recovery;
    }

    /**
     * For tests without a server: the same protocol, with the tasks it runs
     * on the server's thread run by {@code executor} instead.
     */
    MigrationProtocol onServerThread(Executor executor) {
        return new MigrationProtocol(pause.onServerThread(executor), selection, database, flags, gate, getConnection,
            awaitDrain, heartbeat, spawnVerification, recovery);
    }
}
