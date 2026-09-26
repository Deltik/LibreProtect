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
import net.deltik.mc.libreprotect.extension.migration.jdbc.IncompleteMarker;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseServerVersion;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.testutil.AssumeCapability;
import net.deltik.mc.libreprotect.testutil.ChangedUpstream;
import net.deltik.mc.libreprotect.testutil.CoreProtectFixture;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Every capability on the CoreProtect being built: the ways it takes, which
 * depend on its generation, and what they do with CoreProtect's state. The
 * exact ways expected are those of the upstream JARs that
 * {@code audit/baseline.json} lists as {@code reviewedUpstreams}; on another
 * upstream, those tests are skipped.
 */
class CapabilitiesTest {

    /** Whether the CoreProtect being built has the multi-engine design of CoreProtect 25 */
    private static final boolean ENGINE_TYPES = Designs.MULTI_ENGINE.isIn(Upstream.coreProtect());

    @RegisterExtension
    final CoreProtectFixture coreProtect = new CoreProtectFixture();

    private final Capabilities capabilities = Capabilities.current();

    @Test
    @DisplayName("should probe once per class loader")
    void once() {
        assertSame(Capabilities.current(), Capabilities.current());
        assertEquals(Capabilities.known().size(), capabilities.all().size());
    }

    @Test
    @DisplayName("should know the upstream JAR for reviewedUpstreams by the SHA-256 that its capability report gives")
    void upstreamIdentity() throws Exception {
        String jar = System.getProperty("upstream.jar");
        assumeTrue(jar != null, "scripts/lp passes the upstream JAR as -Dupstream.jar");

        assertEquals(CapabilityReport.sha256(Path.of(jar)), AssumeCapability.upstreamSha256());
    }

    @Test
    @DisplayName("should take one of each capability's ways, or say why it takes none")
    void waysOrReasons() {
        for (Capability<?> capability : Capabilities.known()) {
            Choice<?> choice = capabilities.get(capability.id());
            List<String> ways = capability.ways().stream().map(Choice.Way::strategy).toList();
            if (choice.isAvailable()) {
                assertTrue(ways.contains(choice.strategy()), choice::toString);
            } else {
                assertEquals(choice.isAbsent() ? Choice.ABSENT : Choice.UNAVAILABLE, choice.strategy());
                assertFalse(choice.reason() == null || choice.reason().isBlank(), choice::toString);
            }
        }
    }

    @Test
    @DisplayName("should take the ways of this CoreProtect's generation, with none unavailable")
    void strategies() {
        AssumeCapability.reviewedUpstream();
        Map<String, String> expected = new LinkedHashMap<>();
        expected.put("database.selector", ENGINE_TYPES ? "database-type" : "use-mysql");
        expected.put("lifecycle.flags", "static-flags");
        expected.put("consumer.gate", "pause-flags");
        expected.put("config.lock", ENGINE_TYPES ? "class-monitor" : "absent");
        expected.put("server.thread", "scheduler");
        expected.put("consumer.start-result", ENGINE_TYPES ? "named-results" : "absent");
        expected.put("hook.auto-purge-counter", "rows-purged");
        expected.put("hook.lock-heartbeat", "last-lock-update");
        expected.put("hook.entity-spawn-verification", ENGINE_TYPES ? "invalidate" : "absent");
        expected.put("hook.duckdb-recovery", ENGINE_TYPES ? "recovery-requests" : "absent");
        expected.put("hook.purge-worker", ENGINE_TYPES ? "worker-running" : "absent");
        expected.put("migrate-db.incomplete-mark", ENGINE_TYPES ? "dedicated-status" : "locked-forever");
        expected.put("migrate-db.schema", ENGINE_TYPES ? "by-engine-type" : "by-use-mysql");
        expected.put("migrate-db.transcoding", ENGINE_TYPES ? "statement-codecs" : "absent");
        expected.put("migrate-db.duckdb-writes", ENGINE_TYPES ? "appender" : "absent");
        expected.put("clickhouse.reads", ENGINE_TYPES ? "migration-reads" : "absent");
        expected.put("clickhouse.writes", ENGINE_TYPES ? "compatibility-rows" : "absent");
        expected.put("migrate-db.clickhouse-version", ENGINE_TYPES ? "coreprotect-check" : "absent");
        expected.put("migrate-db.protocol", ENGINE_TYPES ? "reload-lifecycle" : "flag-protocol");
        expected.put("migrate-db.source.sqlite", "jdbc");
        expected.put("migrate-db.source.mysql", "jdbc");
        expected.put("migrate-db.source.duckdb", ENGINE_TYPES ? "coreprotect-connection" : "absent");
        expected.put("migrate-db.source.clickhouse", ENGINE_TYPES ? "migration-reads" : "absent");
        expected.put("migrate-db.target.sqlite", "jdbc");
        expected.put("migrate-db.target.mysql", "jdbc");
        expected.put("migrate-db.target.duckdb", ENGINE_TYPES ? "jdbc" : "absent");
        expected.put("migrate-db.target.clickhouse", ENGINE_TYPES ? "compatibility-rows" : "absent");
        expected.put("auto-purge.retention", "config-field");
        expected.put("auto-purge.settings", "config-fields");
        expected.put("auto-purge.tables", ENGINE_TYPES ? "purge-policy" : "purge-command-list");
        expected.put("auto-purge.coordination", ENGINE_TYPES ? "background-claims" : "cooperative-flags");
        expected.put("auto-purge.engine.sqlite", "chunked-deletes");
        expected.put("auto-purge.engine.mysql", "chunked-deletes");
        expected.put("auto-purge.engine.duckdb", ENGINE_TYPES ? "chunked-deletes" : "absent");
        expected.put("auto-purge.engine.clickhouse", ENGINE_TYPES ? "retention" : "absent");

        Map<String, String> actual = new LinkedHashMap<>();
        for (Choice<?> choice : capabilities.all()) {
            actual.put(choice.id(), choice.strategy());
        }
        assertEquals(expected, actual, () -> CapabilityReport.render(capabilities, null));
    }

    @Test
    @DisplayName("should describe every way in plain language, which DIFFERENCES.md shows, naming no capability")
    void plainDescriptions() {
        List<String> ids = Capabilities.known().stream().map(Capability::id).toList();
        for (Capability<?> capability : Capabilities.known()) {
            for (Choice.Way<?> way : capability.ways()) {
                for (String id : ids) {
                    assertFalse(way.description().contains(id), () -> capability.id() + "'s way " + way.strategy()
                        + " names " + id + ": " + way.description());
                }
            }
        }
        // As this CoreProtect's report says, whichever way each took
        for (Choice<?> choice : capabilities.all()) {
            for (String id : ids) {
                assertFalse(choice.reason().contains(id), () -> choice + " names " + id);
            }
        }
    }

    @Test
    @DisplayName("should turn off each feature that needs a shared capability that's unavailable, saying why")
    void dependentFeatures() {
        AssumeCapability.reviewedUpstream();
        Capabilities changed = Capabilities.probe(Upstream.coreProtect().hiding(Names.CONFIG_HANDLER
            + "#migrationRunning"));
        String reason = "CoreProtect has no ConfigHandler.migrationRunning";
        assertEquals(reason, changed.get(Flags.CAPABILITY).reason());

        List<Capability<?>> features = new ArrayList<>(List.of(MigrationProtocol.CAPABILITY,
            Codecs.CAPABILITY, IncompleteMarks.CAPABILITY, DuckDBWrites.CAPABILITY,
            ClickHouseServerVersion.CAPABILITY));
        for (Engine engine : Engine.values()) {
            features.addAll(List.of(CoreProtectMigration.source(engine), CoreProtectMigration.target(engine),
                PurgeEngine.capability(engine)));
        }
        for (Capability<?> feature : features) {
            Choice<?> choice = changed.get(feature);
            if (capabilities.get(feature).isAbsent()) {
                assertTrue(choice.isAbsent(), choice::toString);
            } else {
                assertEquals(Choice.UNAVAILABLE + ": " + reason, choice.strategy() + ": " + choice.reason(),
                    feature::id);
            }
        }
        // CoreProtect 24's way of taking turns watches the flags; CoreProtect 25's claims don't need them
        Choice<Leases> coordination = changed.get(Leases.CAPABILITY);
        assertEquals(ENGINE_TYPES ? "background-claims" : Choice.UNAVAILABLE + ": " + reason, ENGINE_TYPES
            ? coordination.strategy() : coordination.strategy() + ": " + coordination.reason());
        // What only reads CoreProtect's settings still works, and so does reading ClickHouse
        assertTrue(changed.get(PurgeSettings.RETENTION).isAvailable());
        assertEquals(capabilities.get(ClickHouseApi.READS).strategy(), changed.get(ClickHouseApi.READS).strategy());
    }

    @Test
    @DisplayName("should refuse an unknown capability")
    void unknown() {
        assertThrows(IllegalArgumentException.class, () -> capabilities.get("no.such.thing"));
    }

    @Nested
    @DisplayName("database.selector")
    class Selector {

        @Test
        @DisplayName("should know this CoreProtect's engines and which one it uses")
        void activeEngine() throws Missing {
            AssumeCapability.reviewedUpstream();
            ActiveDatabase database = capabilities.require(ActiveDatabase.CAPABILITY);

            assertEquals(ENGINE_TYPES ? EnumSet.allOf(Engine.class) : EnumSet.of(Engine.SQLITE, Engine.MYSQL),
                database.engines());
            for (Engine engine : database.engines()) {
                coreProtect.useEngine(engine);
                assertEquals(engine, database.activeEngine());
                assertEquals(engine.displayName(), database.displayName(engine));
            }
            assertEquals(ENGINE_TYPES ? List.of("clickhouse", "duckdb", "mysql", "sqlite") : List.of("sqlite", "mysql"),
                database.engineNames());
        }
    }

    @Nested
    @DisplayName("lifecycle.flags")
    class LifecycleFlags {

        @Test
        @DisplayName("should read CoreProtect's flags, and set them only as a migration's")
        void flags() throws Missing {
            Flags reading = capabilities.require(Flags.CAPABILITY);
            Flags flags = reading.forMigrations(Upstream.coreProtect());
            coreProtect.set("ConfigHandler.serverRunning", true).set("ConfigHandler.migrationRunning", false)
                .set("ConfigHandler.purgeRunning", false).set("ConfigHandler.pauseConsumer", false);

            assertEquals("CoreProtect's ConfigHandler.migrationRunning was found for reading only",
                assertThrows(IllegalStateException.class, () -> reading.setMigrationRunning(true)).getMessage());
            assertTrue(flags.serverRunning());
            assertFalse(flags.shuttingDown());
            flags.setMigrationRunning(true);
            assertEquals(true, coreProtect.get("ConfigHandler.migrationRunning"));
            assertTrue(flags.migrationRunning());
            assertFalse(flags.converterRunning());
            assertFalse(flags.rollbacksRunning());
            coreProtect.set("ConfigHandler.serverRunning", false);
            assertTrue(flags.shuttingDown());
            // The fixture's reset puts back what the flags changed too
            coreProtect.reset();
            assertFalse(flags.migrationRunning());
        }

        @Test
        @DisplayName("should turn off migrations alone when CoreProtect makes a flag final that they set, saying so")
        void finalFlag() throws Exception {
            Capabilities changed = Capabilities.probe(ChangedUpstream.makingFinal(Names.CONFIG_HANDLER,
                "migrationRunning"));
            String reason = "CoreProtect's ConfigHandler.migrationRunning is final, so LibreProtect can't set it";

            // Auto-purge only reads the flags
            assertTrue(changed.get(Flags.CAPABILITY).isAvailable(), changed.get(Flags.CAPABILITY)::toString);
            assertEquals(Choice.UNAVAILABLE, changed.get(MigrationProtocol.CAPABILITY).strategy());
            assertEquals(reason, changed.get(MigrationProtocol.CAPABILITY).reason());
            assertEquals(Map.of("/co migrate-db", reason), CoreProtectMigration.unavailableFeatures(changed));
            // Purging an engine needs all that purging needs
            assertTrue(changed.get(PurgeEngine.SQLITE).isAvailable(), changed.get(PurgeEngine.SQLITE)::toString);
        }

        @Test
        @DisplayName("should need purgeRunning writable only where migrations set it, for CoreProtect 24's protocol")
        void finalPurgeFlag() throws Exception {
            Capabilities changed = Capabilities.probe(ChangedUpstream.makingFinal(Names.CONFIG_HANDLER,
                "purgeRunning"));
            Choice<MigrationProtocol> protocol = changed.get(MigrationProtocol.CAPABILITY);

            assertTrue(changed.get(Flags.CAPABILITY).isAvailable(), changed.get(Flags.CAPABILITY)::toString);
            if (ENGINE_TYPES) {
                assertTrue(protocol.isAvailable(), protocol::toString);
            } else {
                assertEquals("CoreProtect's ConfigHandler.purgeRunning is final, so LibreProtect can't set it",
                    protocol.reason());
                // Every part of a migration is unavailable with it, as DIFFERENCES.md shows
                for (Capability<?> part : List.of(IncompleteMarks.CAPABILITY, CoreProtectMigration.source(Engine.SQLITE),
                    CoreProtectMigration.target(Engine.MYSQL))) {
                    assertEquals(Choice.UNAVAILABLE + ": " + protocol.reason(), changed.get(part).strategy() + ": "
                        + changed.get(part).reason(), part::id);
                }
            }
            assertTrue(changed.get(PurgeEngine.SQLITE).isAvailable(), changed.get(PurgeEngine.SQLITE)::toString);
        }

        @Test
        @DisplayName("should set the purge and pause flags only for CoreProtect 24's protocol")
        void olderProtocol() throws Missing {
            Flags flags = capabilities.require(Flags.CAPABILITY).forMigrations(Upstream.coreProtect());
            coreProtect.set("ConfigHandler.purgeRunning", false).set("ConfigHandler.pauseConsumer", false);

            if (ENGINE_TYPES) {
                IllegalStateException refused = assertThrows(IllegalStateException.class,
                    () -> flags.setPurgeRunning(true));
                assertTrue(refused.getMessage().startsWith("Setting purgeRunning is CoreProtect 24's protocol, but"
                    + " CoreProtect has class DatabaseType, part of its multi-engine database layer"),
                    refused.getMessage());
                assertThrows(IllegalStateException.class, () -> flags.setPauseConsumer(true));
                assertFalse(flags.purgeRunning());
                assertFalse(flags.pauseConsumer());
            } else {
                flags.setPurgeRunning(true);
                assertTrue(flags.purgeRunning());
                flags.setPauseConsumer(true);
                assertTrue(flags.pauseConsumer());
            }
        }

        @Test
        @DisplayName("should see CoreProtect 25's shutdown before serverRunning clears")
        void shutdownSignals() throws Missing {
            AssumeCapability.strategy("database.selector", "database-type");
            Flags flags = capabilities.require(Flags.CAPABILITY);
            coreProtect.set("ConfigHandler.serverRunning", true).set("ConfigHandler.shutdownDrainRunning", true);

            assertTrue(flags.shuttingDown());
        }
    }

    @Nested
    @DisplayName("consumer.gate")
    class Gate {

        @Test
        @DisplayName("should hold the gate and see the consumer parked, through its protected flag")
        void gate() throws Missing {
            ConsumerGate gate = capabilities.require(ConsumerGate.CAPABILITY);
            coreProtect.set("Consumer.isPaused", false).set("Consumer.pausedSuccess", false);

            gate.setPaused(true);
            assertTrue(gate.isPaused());
            assertEquals(true, coreProtect.get("Consumer.isPaused"));
            assertFalse(gate.parked());
            coreProtect.set("Consumer.pausedSuccess", true);
            assertTrue(gate.parked());
            assertFalse(gate.running());
            assertFalse(gate.persistenceHalted());
        }
    }

    @Nested
    @DisplayName("migrate-db")
    class Migration {

        @Test
        @DisplayName("should mark a target unfinished the way this CoreProtect refuses to start on")
        void incompleteMark() throws Missing {
            AssumeCapability.reviewedUpstream();
            IncompleteMarks marks = capabilities.require(IncompleteMarks.CAPABILITY);

            IncompleteMarker marker = marks.marker();
            assertNotNull(marker);
            assertEquals(0, marks.inactiveStatus());
            assertEquals(ENGINE_TYPES ? "dedicated-status" : "locked-forever",
                capabilities.get(IncompleteMarks.CAPABILITY).strategy());
        }

        @Test
        @DisplayName("should create CoreProtect's tables with its own schema code")
        void schema(@TempDir Path folder) throws Exception {
            Schema schema = capabilities.require(Schema.CAPABILITY);
            String url = "jdbc:sqlite:" + folder.resolve("target.db");

            assertTrue(schema.engines().containsAll(EnumSet.of(Engine.SQLITE, Engine.MYSQL)));
            assertFalse(schema.engines().contains(Engine.CLICKHOUSE));
            schema.creator(Engine.SQLITE).create(DriverManager.getConnection(url), "co_");
            try (Connection connection = DriverManager.getConnection(url);
                 ResultSet tables = connection.getMetaData().getTables(null, null, "co_block", null)) {
                assertTrue(tables.next());
            }
            assertThrows(IllegalArgumentException.class, () -> schema.creator(Engine.CLICKHOUSE));
        }

        @Test
        @DisplayName("should write DuckDB with SQL when its driver's appender is gone, and say why")
        void duckDBFallback() throws Missing {
            AssumeCapability.strategy("migrate-db.duckdb-writes", "appender");
            assertTrue(capabilities.require(DuckDBWrites.CAPABILITY).usesAppender());

            Choice<DuckDBWrites> choice = Capabilities.probe(Upstream.coreProtect()
                .hiding(Names.DUCKDB_CONNECTION + "#createAppender")).get(DuckDBWrites.CAPABILITY);

            assertEquals("sql-inserts", choice.strategy());
            assertTrue(choice.usesFallback());
            assertNull(choice.require().bulkInsert());
            assertEquals(List.of("appender: DuckDB's JDBC driver has no DuckDBConnection.createAppender(String,"
                + " String)"), choice.rejected());
        }
    }

    @Test
    @DisplayName("should count purged rows where CoreProtect shows them, and reset the lock's heartbeat")
    void hooks() throws Missing {
        AtomicLong counter = (AtomicLong) coreProtect.get("ConfigHandler.autoPurgeRowsPurged");
        long before = counter.get();
        coreProtect.set("Process.lastLockUpdate", 12345);

        capabilities.require(Hooks.AUTO_PURGE_COUNTER).add(5);
        capabilities.require(Hooks.LOCK_HEARTBEAT).reset();

        assertEquals(before + 5, counter.get());
        assertEquals(0, coreProtect.get("Process.lastLockUpdate"));
    }

    @Test
    @DisplayName("should see CoreProtect 25's DuckDB recovery and manual purge worker")
    void newerHooks() throws Missing {
        AssumeCapability.strategy("hook.purge-worker", "worker-running");

        assertFalse(capabilities.require(Hooks.DUCKDB_RECOVERY).pending());
        assertFalse(capabilities.require(Hooks.PURGE_WORKER).running());
    }

    @Test
    @DisplayName("should map CoreProtect's answers to starting maintenance by name")
    void startResults() {
        assertEquals(StartResult.Kind.STARTED, StartResult.of("STARTED").kind());
        assertTrue(StartResult.of("STARTED").started());
        assertNull(StartResult.of("STARTED").refusal());
        assertEquals("A rollback or restore is running. Wait for it to finish.",
            StartResult.of("ROLLBACK_RUNNING").refusal());
        assertEquals("CoreProtect's database is busy (SOMETHING_ELSE).", StartResult.of("SOMETHING_ELSE").refusal());
    }
}
