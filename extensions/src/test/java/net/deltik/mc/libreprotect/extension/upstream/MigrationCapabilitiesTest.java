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

import net.coreprotect.consumer.Consumer;
import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.MigrationException;
import net.deltik.mc.libreprotect.extension.migration.RowSink;
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.testutil.AssumeCapability;
import net.deltik.mc.libreprotect.testutil.CoreProtectFixture;
import net.deltik.mc.libreprotect.testutil.ChangedUpstream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.sql.SQLDataException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * How migrations cope with a CoreProtect that changed what they rely on:
 * they become unavailable and say what's missing, rather than take a way of
 * an older CoreProtect whose names a newer one keeps with other meanings;
 * and an engine that one side can't use turns off only the migrations from
 * or to it.
 */
class MigrationCapabilitiesTest {

    private static final Capabilities REAL = Capabilities.probe(Upstream.coreProtect());

    @RegisterExtension
    final CoreProtectFixture coreProtect = new CoreProtectFixture();

    /**
     * @return the capabilities of migrations on the CoreProtect being built
     */
    private static List<Choice<?>> migrations() {
        List<Choice<?>> choices = new ArrayList<>();
        choices.add(REAL.get(MigrationProtocol.CAPABILITY));
        for (Engine engine : Engine.values()) {
            choices.add(REAL.get(CoreProtectMigration.source(engine)));
            choices.add(REAL.get(CoreProtectMigration.target(engine)));
        }
        return choices;
    }

    private static List<String[]> lines(Choice<?> choice) {
        List<String[]> lines = new ArrayList<>();
        for (String line : choice.reportLines()) {
            lines.add(line.split("\t"));
        }
        return lines;
    }

    /**
     * @return every member and relied-on method that the ways chosen for
     *         migrations need, by capability
     */
    static Stream<Arguments> needed() {
        List<Arguments> needed = new ArrayList<>();
        for (Choice<?> choice : migrations()) {
            for (String[] fields : lines(choice)) {
                if (fields[0].equals("member") || fields[0].equals("relies")) {
                    needed.add(Arguments.of(choice.id(), fields[2]));
                }
            }
        }
        return needed.stream();
    }

    /**
     * @return each class that the ways chosen for migrations need, with
     *         every member and relied-on method whose signature names it, as
     *         a rename of the class would take them all
     */
    static Stream<Arguments> renames() {
        Set<String> all = new TreeSet<>();
        for (Choice<?> choice : migrations()) {
            for (String[] fields : lines(choice)) {
                if (fields[0].equals("member") || fields[0].equals("relies")) {
                    all.add(fields[2]);
                }
            }
        }
        List<Arguments> renames = new ArrayList<>();
        for (String type : all) {
            if (type.contains("#")) {
                continue;
            }
            List<String> group = new ArrayList<>();
            group.add(type);
            for (String member : all) {
                if (member.contains("#") && member.contains("L" + type + ";")) {
                    group.add(member);
                }
            }
            renames.add(Arguments.of(group));
        }
        return renames.stream();
    }

    @ParameterizedTest(name = "{0} without {1}")
    @MethodSource("needed")
    @DisplayName("should become unavailable without anything its way needs or relies on, saying what, and never fall"
        + " back")
    void without(String id, String member) {
        assertUnavailable(id, List.of(member), Capabilities.probe(Upstream.coreProtect().hiding(member)).get(id));
    }

    @ParameterizedTest(name = "without {0}")
    @MethodSource("renames")
    @DisplayName("should become unavailable, not fall back, when a class is renamed with its uses")
    void renamed(List<String> group) {
        Capabilities after = Capabilities.probe(Upstream.coreProtect().hiding(group.toArray(new String[0])));

        for (Choice<?> choice : migrations()) {
            boolean affected = false;
            for (String[] fields : lines(choice)) {
                affected |= fields.length > 2 && (group.contains(fields[2]) || fields[2].startsWith(group.get(0) + "#"));
            }
            if (affected) {
                assertUnavailable(choice.id(), group, after.get(choice.id()));
            }
        }
    }

    /**
     * @param hidden what upstream lost
     */
    private static void assertUnavailable(String id, List<String> hidden, Choice<?> after) {
        List<String> names = new ArrayList<>();
        for (String member : hidden) {
            names.add(Missing.readableName(member));
        }
        assertEquals(Choice.UNAVAILABLE, after.strategy(), () -> id + " without " + hidden + ": " + after);
        assertTrue(names.stream().anyMatch(after.reason()::contains), () -> id + "'s reason names none of " + names
            + ": " + after.reason());
        for (String rejected : REAL.get(id).rejected()) {
            String strategy = rejected.substring(0, rejected.indexOf(':'));
            assertTrue(after.rejected().stream().anyMatch(reason -> reason.startsWith(strategy + ":")),
                () -> id + " didn't refuse " + strategy + " without " + hidden + ": " + after.rejected());
        }
    }

    @Nested
    @DisplayName("migrate-db.protocol")
    class Protocol {

        @Test
        @DisplayName("should not take the flag protocol while CoreProtect keeps any one trace of the reload lifecycle")
        void anyTrace() {
            AssumeCapability.strategy("migrate-db.protocol", "reload-lifecycle");
            Set<String> traces = new LinkedHashSet<>(Designs.MULTI_ENGINE.traces());
            traces.addAll(MigrationProtocol.RELOAD_LIFECYCLE.traces());
            for (String kept : traces) {
                List<String> hidden = new ArrayList<>(traces);
                hidden.remove(kept);
                Choice<?> protocol = Capabilities.probe(Upstream.coreProtect().hiding(hidden.toArray(new String[0])))
                    .get(MigrationProtocol.CAPABILITY);

                assertEquals(Choice.UNAVAILABLE, protocol.strategy(), () -> "with only " + kept + " left: " + protocol);
                assertTrue(protocol.rejected().get(1).startsWith("flag-protocol: CoreProtect has "),
                    () -> "with only " + kept + " left: " + protocol.rejected());
            }
        }

        @Test
        @DisplayName("should turn migrations off without Consumer.lockDatabaseReload, saying so, rather than use the"
            + " flag protocol")
        void withoutReloadLock() {
            AssumeCapability.strategy("migrate-db.protocol", "reload-lifecycle");
            Capabilities capabilities = Capabilities.probe(Upstream.coreProtect().hiding(Names.CONSUMER
                + "#lockDatabaseReload"));
            Choice<MigrationProtocol> protocol = capabilities.get(MigrationProtocol.CAPABILITY);
            CoreProtectMigration migration = new CoreProtectMigration(capabilities);

            assertEquals(Choice.UNAVAILABLE, protocol.strategy());
            assertEquals("CoreProtect has no Consumer.lockDatabaseReload(long)", protocol.reason());
            assertEquals("flag-protocol: CoreProtect has class DatabaseType, part of its multi-engine database layer"
                + " (CoreProtect 25), which replaced flag-protocol", protocol.rejected().get(1));
            assertEquals(protocol.reason(), migration.unavailableReason());
            MigrationException refusal = assertThrows(MigrationException.class, () -> migration.claim(Engine.MYSQL));
            assertEquals("/co migrate-db isn't available with this CoreProtect build: CoreProtect has no"
                + " Consumer.lockDatabaseReload(long)", refusal.getMessage());
            // What doesn't need it keeps working, such as auto-purge's
            for (Capability<?> unaffected : List.of(ActiveDatabase.CAPABILITY, Flags.CAPABILITY,
                ConsumerGate.CAPABILITY, StartResult.CAPABILITY, Hooks.PURGE_WORKER)) {
                assertTrue(capabilities.get(unaffected).isAvailable(), unaffected::id);
            }
        }

        @Test
        @DisplayName("should refuse the flag protocol on a CoreProtect with a class of the multi-engine design")
        void newerClass() {
            AssumeCapability.strategy("migrate-db.protocol", "flag-protocol");
            Choice<?> protocol = Capabilities.probe(Upstream.coreProtect()
                .replacing(Names.DATABASE_CONFIG_WRITER, NewerConfigWriter.class)).get(MigrationProtocol.CAPABILITY);

            assertEquals(Choice.UNAVAILABLE, protocol.strategy());
            assertEquals("flag-protocol: CoreProtect has class DatabaseConfigWriter, part of its multi-engine database"
                + " layer (CoreProtect 25), which replaced flag-protocol", protocol.rejected().get(1));
        }

        @Test
        @DisplayName("should refuse the flag protocol on a CoreProtect with a member of the reload lifecycle")
        void newerMember() {
            AssumeCapability.strategy("migrate-db.protocol", "flag-protocol");
            Choice<?> protocol = Capabilities.probe(Upstream.coreProtect()
                .replacing(Names.CONSUMER, ConsumerWithReloadLock.class)).get(MigrationProtocol.CAPABILITY);

            assertEquals(Choice.UNAVAILABLE, protocol.strategy());
            assertEquals("flag-protocol: CoreProtect has Consumer.lockDatabaseReload, part of its database reload"
                + " lifecycle, which replaced the flag protocol for migrations", protocol.rejected().get(1));
        }

        @Test
        @DisplayName("should record what it relies on of CoreProtect's behavior, for the build to watch")
        void relies() {
            Choice<?> protocol = REAL.get(MigrationProtocol.CAPABILITY);
            List<String> relied = new ArrayList<>();
            for (String[] fields : lines(protocol)) {
                if (fields[0].equals("relies")) {
                    relied.add(fields[2]);
                }
            }
            List<String> expected = new ArrayList<>(List.of(
                "net/coreprotect/services/ShutdownService#safeShutdown(Lorg/bukkit/plugin/Plugin;)V",
                "net/coreprotect/config/ConfigHandler#loadDatabase()V",
                "net/coreprotect/config/ConfigHandler#loadConfig()V"));
            if (protocol.strategy().equals("reload-lifecycle")) {
                expected.addAll(List.of(
                    "net/coreprotect/consumer/Consumer#beginDatabaseReload()"
                        + "Lnet/coreprotect/consumer/Consumer$OperationStartResult;",
                    "net/coreprotect/consumer/Consumer#lockDatabaseReload(J)Z",
                    "net/coreprotect/consumer/Consumer#endDatabaseReload(Z)V",
                    "net/coreprotect/consumer/Consumer#haltPersistence()V",
                    "net/coreprotect/services/ShutdownService#waitForMaintenanceCompletion(J)V",
                    "net/coreprotect/config/ConfigHandler#loadDatabase(Lnet/coreprotect/database/clickhouse/"
                        + "ClickHouseDatabase;Z)V",
                    "net/coreprotect/config/DatabaseConfigWriter#persistDatabaseType("
                        + "Lnet/coreprotect/database/DatabaseType;)V"));
            } else {
                expected.addAll(List.of(
                    "net/coreprotect/consumer/Consumer#pauseConsumer(I)V",
                    "net/coreprotect/command/ReloadCommand#runCommand(Lorg/bukkit/command/CommandSender;Z"
                        + "[Ljava/lang/String;)V",
                    "net/coreprotect/command/PurgeCommand#runCommand(Lorg/bukkit/command/CommandSender;Z"
                        + "[Ljava/lang/String;)V",
                    "net/coreprotect/command/LookupCommand#runCommand(Lorg/bukkit/command/CommandSender;"
                        + "Lorg/bukkit/command/Command;Z[Ljava/lang/String;)V",
                    "net/coreprotect/command/RollbackRestoreCommand#runCommand(Lorg/bukkit/command/CommandSender;"
                        + "Lorg/bukkit/command/Command;Z[Ljava/lang/String;Lorg/bukkit/Location;JJ)V",
                    "net/coreprotect/database/Database#createDatabaseTables(Ljava/lang/String;ZLjava/sql/Connection;ZZ)V",
                    "net/coreprotect/config/Config#load(Ljava/io/InputStream;)V"));
            }

            assertTrue(relied.containsAll(expected), () -> "missing: " + expected.stream()
                .filter(member -> !relied.contains(member)).toList());
            assertTrue(protocol.reportLines().stream().anyMatch(line -> line.startsWith("doc\tmigrate-db.protocol\t"
                + "docs/database-migration.md\t")), protocol.reportLines()::toString);
            // What only one engine needs is that engine's
            assertTrue(protocol.reportLines().stream().noneMatch(line -> line.contains("CLICKHOUSE_")
                || line.contains("loadMigrationDatabase") || line.contains("ConfigHandler#duckdb")),
                protocol.reportLines()::toString);
        }
    }

    /** Endpoints of an engine that CoreProtect takes over, as ClickHouse's are */
    private static EngineEndpoints handingOver(Engine engine) {
        return new EngineEndpoints() {
            @Override
            public Engine engine() {
                return engine;
            }

            @Override
            public RowSource openSource(DatabaseSettings settings) {
                throw new UnsupportedOperationException();
            }

            @Override
            public RowSink openSink(DatabaseSettings settings) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Object handOver(RowSink sink) {
                throw new UnsupportedOperationException();
            }
        };
    }

    @Test
    @DisplayName("should find where ClickHouse is and how CoreProtect takes it over, for endpoints registered for it")
    void clickHouseSide() throws Exception {
        AssumeCapability.strategy("migrate-db.protocol", "reload-lifecycle");
        Choice<EngineSide> target = Capability.of("test.target", Choice.way("stub", "stub endpoints",
            upstream -> EngineSide.probe(upstream, Engine.CLICKHOUSE, handingOver(Engine.CLICKHOUSE), true)))
            .probe(Upstream.coreProtect());
        Choice<EngineSide> source = Capability.of("test.source", Choice.way("stub", "stub endpoints",
            upstream -> EngineSide.probe(upstream, Engine.CLICKHOUSE, handingOver(Engine.CLICKHOUSE), false)))
            .probe(Upstream.coreProtect());
        coreProtect.set("Config.CLICKHOUSE_HOST", "clickhouse.example").set("Config.CLICKHOUSE_PORT", 8443)
            .set("Config.CLICKHOUSE_DATABASE", "coreprotect").set("Config.CLICKHOUSE_TLS", true);

        assertTrue(target.require().handsOver());
        assertFalse(source.require().handsOver());
        assertEquals("ClickHouse database 'coreprotect' on clickhouse.example:8443 (table prefix 'lp_')",
            target.require().settings("lp_").describe());
        assertTrue(target.require().settings("lp_").tls());
        String takeOver = "relies\ttest.target\tnet/coreprotect/config/ConfigHandler#loadMigrationDatabase("
            + "Lnet/coreprotect/database/clickhouse/ClickHouseDatabase;)V\t";
        assertTrue(target.reportLines().stream().anyMatch(line -> line.startsWith(takeOver)),
            target.reportLines()::toString);
        assertTrue(source.reportLines().stream().anyMatch(line -> line.startsWith("relies\ttest.source\t"
            + "net/coreprotect/database/Database#detachClickHouseDatabase()")), source.reportLines()::toString);
        // CoreProtect takes over only ClickHouse's prepared databases
        Choice<EngineSide> duckDB = Capability.of("test.duckdb", Choice.way("stub", "stub endpoints",
            upstream -> EngineSide.probe(upstream, Engine.DUCKDB, handingOver(Engine.DUCKDB), true)))
            .probe(Upstream.coreProtect());
        assertEquals("CoreProtect can't take over a prepared DuckDB database", duckDB.reason());
    }

    /** A class of CoreProtect 25's multi-engine design, on a CoreProtect without it otherwise */
    static final class NewerConfigWriter {
    }

    /** CoreProtect's consumer, with a member of the reload lifecycle besides */
    static final class ConsumerWithReloadLock extends Consumer {
        public static boolean lockDatabaseReload(long timeoutMillis) {
            return false;
        }
    }

    @Nested
    @DisplayName("the engines")
    class Engines {

        @Test
        @DisplayName("should have no migrations from or to engines that CoreProtect doesn't have, nor a reason")
        void absentEngines() {
            AssumeCapability.strategy("migrate-db.protocol", "flag-protocol");
            CoreProtectMigration migration = new CoreProtectMigration(REAL);

            for (Engine engine : EnumSet.of(Engine.DUCKDB, Engine.CLICKHOUSE)) {
                assertTrue(REAL.get(CoreProtectMigration.source(engine)).isAbsent(), engine::name);
                assertTrue(REAL.get(CoreProtectMigration.target(engine)).isAbsent(), engine::name);
                assertNull(migration.unavailableReason(engine));
            }
            assertEquals(EnumSet.of(Engine.SQLITE, Engine.MYSQL), migration.engines());
            assertNull(migration.unavailableReason());
        }

        @Test
        @DisplayName("should migrate from and to ClickHouse through its registered endpoints")
        void clickHouseRegistered() {
            AssumeCapability.strategy("migrate-db.protocol", "reload-lifecycle");
            CoreProtectMigration migration = new CoreProtectMigration(REAL);

            assertEquals("migration-reads", REAL.get(CoreProtectMigration.source(Engine.CLICKHOUSE)).strategy());
            assertEquals("compatibility-rows", REAL.get(CoreProtectMigration.target(Engine.CLICKHOUSE)).strategy());
            assertEquals(EnumSet.allOf(Engine.class), migration.engines());
            coreProtect.useEngine(Engine.SQLITE);
            assertNull(migration.unavailableReason(Engine.CLICKHOUSE));
            coreProtect.useEngine(Engine.CLICKHOUSE);
            assertNull(migration.unavailableReason(Engine.SQLITE));
            assertNull(migration.unavailableReason(Engine.DUCKDB));
            // CoreProtect takes a prepared ClickHouse target over, and closes what it gives up the same way
            String closes = "member\tmigrate-db.target.clickhouse\tnet/coreprotect/database/clickhouse/"
                + "ClickHouseDatabase#close()V";
            assertTrue(REAL.get(CoreProtectMigration.target(Engine.CLICKHOUSE)).reportLines().contains(closes),
                REAL.get(CoreProtectMigration.target(Engine.CLICKHOUSE)).reportLines()::toString);
        }

        @Test
        @DisplayName("should name each migration it can't do as users know it, with what CoreProtect lacks, for the"
            + " console")
        void unavailableFeatures() {
            assertEquals(Map.of(), CoreProtectMigration.unavailableFeatures(REAL));

            Map<String, String> none = CoreProtectMigration.unavailableFeatures(Capabilities.probe(Upstream.coreProtect()
                .hiding(Names.CONFIG_HANDLER + "#migrationRunning")));
            assertEquals(List.of("/co migrate-db"), List.copyOf(none.keySet()), none::toString);
            assertTrue(none.get("/co migrate-db").contains("ConfigHandler.migrationRunning"), none::toString);

            if (REAL.get(CoreProtectMigration.target(Engine.CLICKHOUSE)).isAvailable()) {
                assertEquals(Map.of("/co migrate-db from and to ClickHouse", "CoreProtect has no Config.CLICKHOUSE_TLS"),
                    CoreProtectMigration.unavailableFeatures(Capabilities.probe(Upstream.coreProtect()
                        .hiding(Names.CONFIG + "#CLICKHOUSE_TLS"))));
                Map<String, String> target = CoreProtectMigration.unavailableFeatures(Capabilities.probe(
                    Upstream.coreProtect().hiding(Names.CLICKHOUSE_EVENT_BATCH + "#addCompatibilityRow")));
                assertEquals(List.of("/co migrate-db to ClickHouse"), List.copyOf(target.keySet()), target::toString);
            }
        }

        @Test
        @DisplayName("should keep migrations from ClickHouse when CoreProtect's ClickHouse writer changed")
        void clickHouseWriterChanged() {
            AssumeCapability.strategy("migrate-db.protocol", "reload-lifecycle");
            Capabilities capabilities = Capabilities.probe(Upstream.coreProtect().hiding(Names.CLICKHOUSE_EVENT_BATCH
                + "#addCompatibilityRow"));
            CoreProtectMigration migration = new CoreProtectMigration(capabilities);

            Choice<?> target = capabilities.get(CoreProtectMigration.target(Engine.CLICKHOUSE));
            assertEquals(Choice.UNAVAILABLE, target.strategy(), target::toString);
            assertTrue(target.reason().startsWith("CoreProtect has no ClickHouseEventBatch.addCompatibilityRow("),
                target::reason);
            assertEquals("migration-reads", capabilities.get(CoreProtectMigration.source(Engine.CLICKHOUSE))
                .strategy());
            coreProtect.useEngine(Engine.CLICKHOUSE);
            assertNull(migration.unavailableReason(Engine.MYSQL));
            coreProtect.useEngine(Engine.SQLITE);
            assertEquals(target.reason(), migration.unavailableReason(Engine.CLICKHOUSE));
        }

        @ParameterizedTest(name = "without {0}")
        @ValueSource(strings = {
            Names.CONFIG + "#CLICKHOUSE_TLS",
            Names.CONFIG_HANDLER + "#loadMigrationDatabase",
            Names.CONFIG_HANDLER + "#duckdb",
            Names.DATABASE + "#detachClickHouseDatabase",
            Names.DUCKDB_DATABASE + "#createTables",
            Names.DUCKDB_RECOVERY + "#reset",
            Names.ENTITY_SPAWN_TRACKING + "#invalidateDatabaseVerification"})
        @DisplayName("should keep migrations between other engines when CoreProtect changes what one engine, or a hook"
            + " after the switch, needs")
        void otherEnginesChange(String hidden) throws Exception {
            AssumeCapability.strategy("migrate-db.protocol", "reload-lifecycle");
            Capabilities capabilities = Capabilities.probe(Upstream.coreProtect().hiding(hidden));
            CoreProtectMigration migration = new CoreProtectMigration(capabilities, Runnable::run);
            coreProtect.useEngine(Engine.SQLITE).set("ConfigHandler.serverRunning", true)
                .set("ConfigHandler.migrationRunning", false).set("ConfigHandler.purgeRunning", false)
                .set("Config.DATABASE_LOCK", true);

            assertEquals("reload-lifecycle", capabilities.get(MigrationProtocol.CAPABILITY).strategy(),
                () -> capabilities.get(MigrationProtocol.CAPABILITY).toString());
            assertNull(migration.unavailableReason());
            assertNull(migration.unavailableReason(Engine.MYSQL));
            migration.claim(Engine.MYSQL).close();
            assertEquals(false, coreProtect.get("ConfigHandler.migrationRunning"));
            // The engine whose members changed is turned off, saying why, where it uses them
            String member = Missing.readableName(hidden);
            if (hidden.contains("#duckdb") || hidden.contains("DuckDBRecovery")) {
                Choice<?> duckDB = capabilities.get(CoreProtectMigration.source(Engine.DUCKDB));
                assertEquals(Choice.UNAVAILABLE, duckDB.strategy(), duckDB::toString);
                assertTrue(duckDB.reason().contains(member), duckDB::reason);
                coreProtect.useEngine(Engine.DUCKDB);
                assertTrue(migration.unavailableReason(Engine.SQLITE).contains(member),
                    () -> migration.unavailableReason(Engine.SQLITE));
            }
        }

        @Test
        @DisplayName("should keep migrations between the other engines when CoreProtect renames its ClickHouse database"
            + " class")
        void clickHouseClassRenamed() throws Exception {
            AssumeCapability.strategy("migrate-db.protocol", "reload-lifecycle");
            String renamedClass = Names.CLICKHOUSE_DATABASE.replace("ClickHouseDatabase", "ClickHouseStore");
            Capabilities renamed = Capabilities.probe(ChangedUpstream.renaming(Map.of(Names.CLICKHOUSE_DATABASE,
                renamedClass)));
            CoreProtectMigration migration = new CoreProtectMigration(renamed);

            Choice<?> protocol = renamed.get(MigrationProtocol.CAPABILITY);
            assertEquals("reload-lifecycle", protocol.strategy(), protocol::toString);
            assertEquals("dedicated-status", renamed.get(IncompleteMarks.CAPABILITY).strategy(),
                () -> renamed.get(IncompleteMarks.CAPABILITY).toString());
            assertNull(migration.unavailableReason());
            for (Engine engine : EnumSet.of(Engine.SQLITE, Engine.MYSQL, Engine.DUCKDB)) {
                Choice<?> source = renamed.get(CoreProtectMigration.source(engine));
                Choice<?> target = renamed.get(CoreProtectMigration.target(engine));
                assertTrue(source.isAvailable(), source::toString);
                assertTrue(target.isAvailable(), target::toString);
            }
            assertEquals(EnumSet.of(Engine.SQLITE, Engine.MYSQL, Engine.DUCKDB), migration.engines());
            // What they rely on is the same method, under its new signature
            String relied = "relies\tmigrate-db.protocol\tnet/coreprotect/config/ConfigHandler#loadDatabase(L"
                + renamedClass.replace('.', '/') + ";Z)V\t";
            assertTrue(protocol.reportLines().stream().anyMatch(line -> line.startsWith(relied)),
                protocol.reportLines()::toString);
            // Only ClickHouse's own migrations name the class, and turn off
            Choice<?> clickHouse = renamed.get(CoreProtectMigration.target(Engine.CLICKHOUSE));
            assertEquals(Choice.UNAVAILABLE, clickHouse.strategy(), clickHouse::toString);
            assertTrue(clickHouse.reason().contains("ClickHouseDatabase"), clickHouse::reason);
        }

        @Test
        @DisplayName("should turn off only DuckDB targets without CoreProtect's DuckDB settings")
        void withoutDuckDBSettings() {
            AssumeCapability.strategy("migrate-db.target.duckdb", "jdbc");
            Capabilities capabilities = Capabilities.probe(Upstream.coreProtect().hiding(Names.CONFIG_HANDLER
                + "#duckdbThreads"));

            assertEquals("CoreProtect has no ConfigHandler.duckdbThreads",
                capabilities.get(CoreProtectMigration.target(Engine.DUCKDB)).reason());
            assertTrue(capabilities.get(CoreProtectMigration.source(Engine.DUCKDB)).isAvailable());
            assertTrue(capabilities.get(CoreProtectMigration.target(Engine.SQLITE)).isAvailable());
            assertTrue(capabilities.get(MigrationProtocol.CAPABILITY).isAvailable());
        }

        @Test
        @DisplayName("should turn off targets without CoreProtect's schema code, and sources only if the protocol needs it")
        void withoutSchema() {
            Capabilities capabilities = Capabilities.probe(Upstream.coreProtect().hiding(Names.DATABASE
                + "#createDatabaseTables"));
            Choice<MigrationProtocol> protocol = capabilities.get(MigrationProtocol.CAPABILITY);

            for (Engine engine : REAL.get(ActiveDatabase.CAPABILITY).orElse(null).engines()) {
                if (engine == Engine.CLICKHOUSE) {
                    continue;
                }
                Choice<?> target = capabilities.get(CoreProtectMigration.target(engine));
                assertEquals(Choice.UNAVAILABLE, target.strategy(), engine::name);
                assertTrue(target.reason().startsWith("CoreProtect has no Database.createDatabaseTables("),
                    target::reason);
                // Sources need only the protocol, whose use-mysql selection relies on the schema code's fallback
                Choice<?> source = capabilities.get(CoreProtectMigration.source(engine));
                if (protocol.isAvailable()) {
                    assertTrue(source.isAvailable(), engine::name);
                } else {
                    assertEquals(protocol.reason(), source.reason(), engine::name);
                }
            }
        }

        @Test
        @DisplayName("should need CoreProtect's conversions only between engines that encode data differently")
        void withoutConversions() throws Exception {
            AssumeCapability.strategy("migrate-db.transcoding", "statement-codecs");
            Capabilities capabilities = Capabilities.probe(Upstream.coreProtect().hiding(Names.BLOCK_STATEMENT
                + "#transcodeMetadata"));
            CoreProtectMigration migration = new CoreProtectMigration(capabilities);
            coreProtect.useEngine(Engine.SQLITE);

            assertTrue(migration.unavailableReason(Engine.DUCKDB).startsWith("SQLite and DuckDB encode data"
                + " differently, and CoreProtect's conversions aren't available: CoreProtect has no"
                + " BlockStatement.transcodeMetadata("), migration.unavailableReason(Engine.DUCKDB));
            assertNull(migration.unavailableReason(Engine.MYSQL));
            assertThrows(SQLDataException.class, () -> migration.transcode("block", "meta", new byte[]{1},
                Engine.SQLITE, Engine.DUCKDB));
            byte[] unchanged = {1};
            assertSame(unchanged, migration.transcode("block", "meta", unchanged, Engine.SQLITE, Engine.MYSQL));
        }
    }
}
