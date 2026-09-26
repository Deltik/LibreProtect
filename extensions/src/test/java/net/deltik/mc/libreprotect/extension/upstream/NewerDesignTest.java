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
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.testutil.AssumeCapability;
import net.deltik.mc.libreprotect.testutil.CoreProtectFixture;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.sql.Connection;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

/**
 * CoreProtect 25 keeps many names of CoreProtect 24 with other meanings, so
 * none of CoreProtect 24's ways may be taken on it, however much of its
 * design is renamed: they only run on an upstream without any trace of it.
 */
class NewerDesignTest {

    private static final boolean MULTI_ENGINE = Designs.MULTI_ENGINE.isIn(Upstream.coreProtect());

    @RegisterExtension
    final CoreProtectFixture coreProtect = new CoreProtectFixture();

    private static final List<Capability<?>> WITH_OLDER_WAYS = List.of(ActiveDatabase.CAPABILITY,
        Schema.CAPABILITY, IncompleteMarks.CAPABILITY, PurgeTables.CAPABILITY, Leases.CAPABILITY);

    @Test
    @DisplayName("should know CoreProtect 25 by every one of its traces, and CoreProtect 24 by none")
    void traces() {
        // A reviewed CoreProtect has all or none; a renamed trace leaves the design known by the others
        AssumeCapability.reviewedUpstream();
        Upstream upstream = Upstream.coreProtect();
        for (String trace : Designs.MULTI_ENGINE.traces()) {
            assertEquals(MULTI_ENGINE, upstream.has(trace), trace);
        }
    }

    @Test
    @DisplayName("should not take CoreProtect 24's ways when CoreProtect 25 renames its engine types")
    void renamedEngineTypes() throws Exception {
        AssumeCapability.strategy("database.selector", "database-type");
        // As if DatabaseType and its field became StorageEngine and storageEngine
        Upstream renamed = Upstream.coreProtect().hiding(Names.DATABASE_TYPE, Names.CONFIG_HANDLER + "#databaseType");
        Capabilities capabilities = Capabilities.probe(renamed);
        Choice<ActiveDatabase> selector = capabilities.get(ActiveDatabase.CAPABILITY);
        Choice<Schema> schema = capabilities.get(Schema.CAPABILITY);

        assertEquals("unavailable", selector.strategy(), selector::toString);
        assertEquals("CoreProtect has no ConfigHandler.databaseType", selector.reason());
        assertEquals(List.of("database-type: CoreProtect has no ConfigHandler.databaseType",
            "use-mysql: CoreProtect has Config.DATABASE_TYPE, part of its multi-engine database layer (CoreProtect 25),"
                + " which replaced use-mysql"), selector.rejected());
        assertEquals("unavailable", schema.strategy(), schema::toString);
        assertTrue(schema.rejected().get(1).startsWith("by-use-mysql: CoreProtect has Config.DATABASE_TYPE, part of"
            + " its multi-engine database layer"), schema.rejected().toString());
        // With DuckDB active, CoreProtect 24's way would have seen SQLite
        coreProtect.useEngine(Engine.DUCKDB);
        assertEquals(Engine.DUCKDB, Capabilities.current().require(ActiveDatabase.CAPABILITY).activeEngine());
    }

    @Test
    @DisplayName("should not take CoreProtect 24's ways while any one trace of CoreProtect 25 is left")
    void anyTrace() {
        AssumeCapability.strategy("database.selector", "database-type");
        List<String> traces = Designs.MULTI_ENGINE.traces();
        for (String kept : traces) {
            List<String> hidden = new ArrayList<>(traces);
            hidden.remove(kept);
            Capabilities capabilities = Capabilities.probe(Upstream.coreProtect().hiding(hidden.toArray(new String[0])));
            for (Capability<?> capability : WITH_OLDER_WAYS) {
                Choice<?> choice = capabilities.get(capability);
                assertFalse(choice.isAvailable() && !choice.strategy().equals(Capabilities.current()
                    .get(capability).strategy()), () -> capability + " took " + choice.strategy() + " with only "
                    + kept + " left");
            }
        }
    }

    @Test
    @DisplayName("should need what CoreProtect 25 brought, rather than behave like CoreProtect 24 without it")
    void newerMembers() {
        AssumeCapability.strategy("database.selector", "database-type");
        Capabilities capabilities = Capabilities.probe(Upstream.coreProtect().hiding(
            Names.CONSUMER + "#isPersistenceHalted", Names.CONFIG_HANDLER + "#shutdownDrainRunning"));

        assertEquals("CoreProtect has no Database.awaitConnectionDrain(long)",
            Capabilities.probe(Upstream.coreProtect().hiding(Names.DATABASE + "#awaitConnectionDrain"))
                .get(Leases.CAPABILITY).reason());
        assertEquals("CoreProtect has no Consumer.isPersistenceHalted()",
            capabilities.get(ConsumerGate.CAPABILITY).reason());
        assertEquals("CoreProtect has no ConfigHandler.shutdownDrainRunning",
            capabilities.get(Flags.CAPABILITY).reason());
    }

    @Test
    @DisplayName("should need the behavior it relies on from CoreProtect 25 rather than drop it quietly")
    void newerRelies() {
        AssumeCapability.strategy("database.selector", "database-type");
        AssumeCapability.reviewedUpstream();
        assertEquals("CoreProtect has no Consumer.processConsumerBatch(int, boolean)", Capabilities.probe(
            Upstream.coreProtect().hiding(Names.CONSUMER + "#processConsumerBatch")).get(ConsumerGate.CAPABILITY)
            .reason());

        Capabilities capabilities = Capabilities.probe(Upstream.coreProtect().hiding(
            Names.DUCKDB_DATABASE + "#createTables"));
        assertEquals("CoreProtect has no DuckDBDatabase.createTables(String, Connection, boolean)",
            capabilities.get(CoreProtectMigration.target(Engine.DUCKDB)).reason());
        // Only DuckDB targets rely on DuckDB's tables, not CoreProtect's schema code for every engine
        assertEquals("by-engine-type", capabilities.get(Schema.CAPABILITY).strategy());
        assertEquals("jdbc", capabilities.get(CoreProtectMigration.target(Engine.SQLITE)).strategy());
        assertEquals("jdbc", capabilities.get(CoreProtectMigration.target(Engine.MYSQL)).strategy());
    }

    @Test
    @DisplayName("should take an older way on CoreProtect 24 even though the newer way looked up a class both have")
    void sharedClasses() {
        AssumeCapability.reviewedUpstream();
        Choice<String> choice = Choice.first(Upstream.coreProtect(), "test.drain",
            Choice.way("drain", "CoreProtect 25's connection drain", Designs.MULTI_ENGINE, u -> {
                u.type(Names.DATABASE).staticMethod("awaitConnectionDrain", boolean.class, long.class);
                return "drain";
            }),
            Choice.way("no-drain", "CoreProtect 24's untracked connections", u -> {
                u.type(Names.DATABASE).staticMethod("getConnection", Connection.class, boolean.class, int.class);
                return "no-drain";
            }));

        assertEquals(MULTI_ENGINE ? "drain" : "no-drain", choice.strategy(), choice.rejected()::toString);
    }

    @Test
    @DisplayName("should not call DuckDB writes absent when CoreProtect 25 renames and moves its DuckDB classes")
    void movedDuckDB() {
        AssumeCapability.strategy("migrate-db.duckdb-writes", "appender");
        // As if DatabaseType became StorageEngine and DuckDB's classes moved to a package of their own
        Capabilities capabilities = Capabilities.probe(Upstream.coreProtect().hiding(Names.DATABASE_TYPE,
            Names.DUCKDB_DATABASE, Names.DUCKDB_RECOVERY));

        // Not absent, since CoreProtect still has its multi-engine design; only unavailable with the migrations
        // that write DuckDB, which need DatabaseType
        Choice<DuckDBWrites> writes = capabilities.get(DuckDBWrites.CAPABILITY);
        assertEquals("unavailable", writes.strategy());
        assertEquals(capabilities.get(MigrationProtocol.CAPABILITY).reason(), writes.reason());
        assertEquals("CoreProtect has no class DuckDBRecovery", capabilities.get(Hooks.DUCKDB_RECOVERY).reason());
        assertEquals("unavailable", capabilities.get(Schema.CAPABILITY).strategy());
    }

    @Test
    @DisplayName("should take CoreProtect 24's ways on CoreProtect 24")
    void olderWays() {
        assumeFalse(MULTI_ENGINE, "needs CoreProtect 24");
        AssumeCapability.reviewedUpstream();
        for (Capability<?> capability : WITH_OLDER_WAYS) {
            Choice<?> choice = Capabilities.current().get(capability);
            assertTrue(choice.isAvailable(), choice::toString);
            assertEquals(1, choice.rejected().size(), choice::toString);
        }
    }
}
