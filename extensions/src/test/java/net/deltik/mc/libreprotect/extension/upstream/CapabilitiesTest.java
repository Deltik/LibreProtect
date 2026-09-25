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
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.testutil.AssumeCapability;
import net.deltik.mc.libreprotect.testutil.CoreProtectFixture;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Every capability on the CoreProtect being built: the ways it takes, which
 * depend on its generation, and what they do with CoreProtect's state.
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
        Map<String, String> expected = new LinkedHashMap<>();
        expected.put("database.selector", ENGINE_TYPES ? "database-type" : "use-mysql");
        expected.put("lifecycle.flags", "static-flags");
        expected.put("consumer.gate", "pause-flags");
        expected.put("consumer.start-result", ENGINE_TYPES ? "named-results" : "absent");

        Map<String, String> actual = new LinkedHashMap<>();
        for (Choice<?> choice : capabilities.all()) {
            actual.put(choice.id(), choice.strategy());
        }
        assertEquals(expected, actual, () -> CapabilityReport.render(capabilities, null));
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
        @DisplayName("should read CoreProtect's flags")
        void flags() throws Missing {
            Flags flags = capabilities.require(Flags.CAPABILITY);
            coreProtect.set("ConfigHandler.serverRunning", true).set("ConfigHandler.migrationRunning", true)
                .set("ConfigHandler.purgeRunning", false).set("ConfigHandler.pauseConsumer", false);

            assertTrue(flags.serverRunning());
            assertFalse(flags.shuttingDown());
            assertTrue(flags.migrationRunning());
            assertFalse(flags.converterRunning());
            assertFalse(flags.purgeRunning());
            assertFalse(flags.pauseConsumer());
            assertFalse(flags.rollbacksRunning());
            coreProtect.set("ConfigHandler.serverRunning", false);
            assertTrue(flags.shuttingDown());
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
