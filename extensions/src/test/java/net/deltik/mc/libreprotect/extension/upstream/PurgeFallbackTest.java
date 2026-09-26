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
import net.deltik.mc.libreprotect.extension.purge.PurgeContext;
import net.deltik.mc.libreprotect.extension.purge.StopReason;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.testutil.AssumeCapability;
import net.deltik.mc.libreprotect.testutil.CoreProtectFixture;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.lang.reflect.Method;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * What automatic purging does when CoreProtect loses something that it
 * needs, as when a new version renames or removes it: purging the databases
 * that need it stops before it touches them, and says what's missing, rather
 * than going on without it or falling back to an older way whose names
 * CoreProtect still has but whose meaning it changed.
 */
class PurgeFallbackTest {

    private static final Capabilities REAL = Capabilities.probe(Upstream.coreProtect());

    /** The capabilities automatic purging needs for a database of every engine */
    private static final List<String> COMMON = List.of("database.selector", "lifecycle.flags", "consumer.gate",
        "auto-purge.retention", "auto-purge.settings", "hook.entity-spawn-verification", "hook.purge-worker");
    /** The capabilities it needs to purge in chunks, which it does on every engine but ClickHouse */
    private static final List<String> CHUNKED = List.of("auto-purge.coordination", "auto-purge.tables");
    /** What it does without */
    private static final String COUNTER = "hook.auto-purge-counter";

    /** The engines whose databases it purges on the CoreProtect being built */
    private static final Set<Engine> ENGINES = EnumSet.noneOf(Engine.class);

    static {
        for (Engine engine : Engine.values()) {
            if (REAL.get(PurgeEngine.capability(engine)).isAvailable()) {
                ENGINES.add(engine);
            }
        }
    }

    @RegisterExtension
    final CoreProtectFixture coreProtect = new CoreProtectFixture();

    @BeforeEach
    void runningServer() {
        coreProtect.set("ConfigHandler.serverRunning", true).set("ConfigHandler.purgeRunning", false)
            .set("ConfigHandler.migrationRunning", false).set("ConfigHandler.converterRunning", false)
            .set("ConfigHandler.pauseConsumer", false).set("Consumer.isPaused", false);
    }

    /**
     * @return the engines whose databases a capability is needed to purge,
     *         of those purged on the CoreProtect being built
     */
    private static Set<Engine> needing(String id) {
        Set<Engine> engines = EnumSet.noneOf(Engine.class);
        if (COMMON.contains(id)) {
            engines.addAll(ENGINES);
        } else if (CHUNKED.contains(id)) {
            engines.addAll(EnumSet.of(Engine.SQLITE, Engine.MYSQL, Engine.DUCKDB));
        } else if (id.startsWith("auto-purge.engine.")) {
            engines.add(Engine.fromConfigName(id.substring("auto-purge.engine.".length())));
        }
        engines.retainAll(ENGINES);
        return engines;
    }

    /**
     * @return every line of the capability report of the capabilities that
     *         automatic purging uses, each split into its fields
     */
    private static List<String[]> lines() {
        List<String[]> lines = new ArrayList<>();
        for (Choice<?> choice : REAL.all()) {
            if (needing(choice.id()).isEmpty() && !choice.id().equals(COUNTER)) {
                continue;
            }
            for (String line : choice.reportLines()) {
                lines.add(line.split("\t"));
            }
        }
        return lines;
    }

    /**
     * @return every member and relied-on method of the ways chosen on the
     *         CoreProtect being built, with the capabilities that need it
     */
    private static Map<String, Set<String>> users() {
        Map<String, Set<String>> users = new LinkedHashMap<>();
        for (String[] fields : lines()) {
            if (fields[0].equals("member") || fields[0].equals("relies")) {
                users.computeIfAbsent(fields[2], member -> new TreeSet<>()).add(fields[1]);
            }
        }
        return users;
    }

    /**
     * @return the engines whose databases any of these capabilities are
     *         needed to purge
     */
    private static Set<Engine> needing(Set<String> ids) {
        Set<Engine> engines = EnumSet.noneOf(Engine.class);
        for (String id : ids) {
            engines.addAll(needing(id));
        }
        return engines;
    }

    /**
     * Check that exactly the engines whose purging needs what's gone stop
     * before touching their databases, and that the others still purge.
     */
    private void assertOnlyUnsupported(CoreProtectPurge bridge, Set<Engine> engines, List<String> hidden)
        throws Exception {
        for (Engine engine : ENGINES) {
            if (engines.contains(engine)) {
                assertUnsupported(bridge, engine, hidden);
            } else {
                assertStillPurges(bridge, engine);
            }
        }
    }

    static Stream<Arguments> needed() {
        List<Arguments> needed = new ArrayList<>();
        for (Map.Entry<String, Set<String>> member : users().entrySet()) {
            needed.add(Arguments.of(member.getValue(), member.getKey()));
        }
        return needed.stream();
    }

    /**
     * @return each class that automatic purging needs, with every member
     *         and relied-on method of the report that it declares or whose
     *         signature names it, as a rename of the class would take them
     *         all, and the capabilities that need any of them
     */
    static Stream<Arguments> renames() {
        Map<String, Set<String>> users = users();
        List<Arguments> renames = new ArrayList<>();
        for (String type : users.keySet()) {
            if (type.contains("#")) {
                continue;
            }
            List<String> group = new ArrayList<>();
            Set<String> ids = new TreeSet<>(users.get(type));
            group.add(type);
            for (Map.Entry<String, Set<String>> member : users.entrySet()) {
                if (member.getKey().startsWith(type + "#") || member.getKey().contains("L" + type + ";")) {
                    group.add(member.getKey());
                    ids.addAll(member.getValue());
                }
            }
            renames.add(Arguments.of(group, ids));
        }
        return renames.stream();
    }

    @ParameterizedTest(name = "{0} without {1}")
    @MethodSource("needed")
    @DisplayName("should stop before touching a database whose purging needs what's gone, saying what, and only then")
    void withoutMember(Set<String> ids, String member) throws Exception {
        CoreProtectPurge bridge = CoreProtectPurge.create(Capabilities.probe(Upstream.coreProtect().hiding(member)));

        assertOnlyUnsupported(bridge, needing(ids), List.of(member));
    }

    @ParameterizedTest(name = "without {0}")
    @MethodSource("renames")
    @DisplayName("should stop before touching a database whose purging needs a class that was renamed with its uses,"
        + " and only then")
    void renamed(List<String> group, Set<String> ids) throws Exception {
        CoreProtectPurge bridge = CoreProtectPurge.create(Capabilities.probe(Upstream.coreProtect()
            .hiding(group.toArray(new String[0]))));

        assertOnlyUnsupported(bridge, needing(ids), group);
    }

    @Test
    @DisplayName("should purge ClickHouse without auto-purge.coordination, which only the other engines use")
    void clickHouseWithoutCoordination() throws Exception {
        AssumeCapability.strategy("auto-purge.engine.clickhouse", "retention");
        Capabilities after = Capabilities.probe(Upstream.coreProtect()
            .hiding(Names.DATABASE + "#awaitConnectionDrain"));
        CoreProtectPurge bridge = CoreProtectPurge.create(after);

        assertEquals("unavailable", after.get(Leases.CAPABILITY).strategy());
        assertEquals("retention", after.get(PurgeEngine.CLICKHOUSE).strategy());
        assertStillPurges(bridge, Engine.CLICKHOUSE);
        assertEquals("CoreProtect has no Database.awaitConnectionDrain(long), which purging SQLite needs",
            unavailable(bridge, Engine.SQLITE));
    }

    @Test
    @DisplayName("should purge DuckDB without the parts of CoreProtect's recovery of it that purging doesn't use")
    void withoutRecoveryReset() throws Exception {
        AssumeCapability.strategy("auto-purge.engine.duckdb", "chunked-deletes");
        Capabilities after = Capabilities.probe(Upstream.coreProtect().hiding(Names.DUCKDB_RECOVERY + "#reset"));
        CoreProtectPurge bridge = CoreProtectPurge.create(after);

        assertEquals("unavailable", after.get(Hooks.DUCKDB_RECOVERY).strategy());
        assertEquals("chunked-deletes", after.get(PurgeEngine.DUCKDB).strategy());
        assertStillPurges(bridge, Engine.DUCKDB);
        assertFalse(bridge.requestRecovery(new SQLException("a failure that needs nothing reopened")));
        assertEquals("CoreProtect has no DuckDBRecovery.isPending(), which purging DuckDB needs",
            unavailable(CoreProtectPurge.create(Capabilities.probe(Upstream.coreProtect()
                .hiding(Names.DUCKDB_RECOVERY + "#isPending"))), Engine.DUCKDB));
    }

    @Test
    @DisplayName("should need database-lock only to purge ClickHouse")
    void withoutDatabaseLock() throws Exception {
        CoreProtectPurge bridge = CoreProtectPurge.create(Capabilities.probe(Upstream.coreProtect()
            .hiding(Names.CONFIG + "#DATABASE_LOCK")));

        coreProtect.set("Config.AUTO_PURGE", "180d");
        assertEquals("180d", bridge.retentionSetting());
        assertNull(bridge.settingsUnavailableReason());
        assertStillPurges(bridge, Engine.SQLITE);
        assertFalse(bridge.databaseLock());
        if (ENGINES.contains(Engine.CLICKHOUSE)) {
            assertEquals("CoreProtect has no Config.DATABASE_LOCK, which purging ClickHouse needs",
                unavailable(bridge, Engine.CLICKHOUSE));
        }
    }

    @Test
    @DisplayName("should say that it can't read auto-purge, rather than take it as off, and stop")
    void withoutRetention() throws Exception {
        CoreProtectPurge bridge = CoreProtectPurge.create(Capabilities.probe(Upstream.coreProtect()
            .hiding(Names.CONFIG + "#AUTO_PURGE")));

        coreProtect.set("Config.AUTO_PURGE_TIME", "03:30");
        assertEquals("CoreProtect has no Config.AUTO_PURGE",
            bridge.settingsUnavailableReason());
        assertNull(bridge.retentionSetting());
        assertEquals("03:30", bridge.timeSetting());
        assertUnsupported(bridge, Engine.SQLITE, List.of(Names.CONFIG + "#AUTO_PURGE"));
    }

    @Test
    @DisplayName("should read auto-purge whatever else of its settings CoreProtect renamed")
    void retentionAlone() throws Exception {
        CoreProtectPurge bridge = CoreProtectPurge.create(Capabilities.probe(Upstream.coreProtect()
            .hiding(Names.CONFIG + "#AUTO_PURGE_TIME", Names.CONFIG + "#DATABASE_LOCK",
                Names.CONFIG_HANDLER + "#prefix")));

        coreProtect.set("Config.AUTO_PURGE", "180d");
        assertEquals("180d", bridge.retentionSetting());
        assertNull(bridge.settingsUnavailableReason());
        assertEquals("CoreProtect has no Config.AUTO_PURGE_TIME",
            unavailable(bridge, Engine.SQLITE));
    }

    private String unavailable(CoreProtectPurge bridge, Engine engine) {
        coreProtect.useEngine(engine);
        return bridge.unavailableReason();
    }

    @Test
    @DisplayName("should not count purged rows where CoreProtect has no counter, say so once, and still purge")
    void withoutCounter() throws Exception {
        CoreProtectPurge bridge = CoreProtectPurge.create(Capabilities.probe(Upstream.coreProtect()
            .hiding(Names.CONFIG_HANDLER + "#autoPurgeRowsPurged")));
        TestLogger log = new TestLogger();
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(log);
        try {
            assertTrue(bridge.purgeableTables().contains("block"));
            bridge.rowsPurged(0);
            assertEquals(List.of(), log.getMessages(), "warned before anything went uncounted");
            bridge.rowsPurged(5);
            bridge.rowsPurged(7);
            assertEquals(List.of(LibreProtectLogger.PREFIX + "Auto-purge can't update /co status's count of purged"
                + " rows with this CoreProtect build: CoreProtect has no ConfigHandler.autoPurgeRowsPurged."),
                log.getMessages());
            assertStillPurges(bridge, Engine.SQLITE);
        } finally {
            LibreProtectLogger.reset();
        }
    }

    @Test
    @DisplayName("should stop for a database engine LibreProtect doesn't know")
    void unknownEngine() throws Exception {
        AssumeCapability.strategy("database.selector", "database-type");
        CoreProtectPurge bridge = CoreProtectPurge.create(REAL);
        // No engine it knows, as with one that CoreProtect added (see NewConstantsTest)
        coreProtect.set("ConfigHandler.databaseType", null);

        assertNull(bridge.activeEngine());
        assertEquals("CoreProtect uses a database engine that LibreProtect doesn't know", bridge.unavailableReason());
        assertEquals(StopReason.UNSUPPORTED_DATABASE, bridge.stopReason());
        assertNull(bridge.databaseIdentity());
        Lease lease = bridge.lease(new PurgeContext(), false);
        assertEquals(StopReason.UNSUPPORTED_DATABASE, lease.stopReason());
        assertEquals(bridge.unavailableReason(), lease.stopDetail());
    }

    @Test
    @DisplayName("should stop, naming it, for an answer to a claim that CoreProtect added, and wait for known ones")
    void newAnswer() {
        PurgeContext context = new PurgeContext();

        Lease lease = ClaimLeases.refused(StartResult.of("SOMETHING_NEW"), context);

        assertEquals(StopReason.DATABASE_BUSY, lease.stopReason());
        assertEquals("CoreProtect refused a purge claim with SOMETHING_NEW", lease.stopDetail());
        assertEquals(StopReason.MANUAL_PURGE, ClaimLeases.refused(StartResult.of("PURGE_RUNNING"), context).stopReason());
        assertEquals(StopReason.PERSISTENCE_HALTED,
            ClaimLeases.refused(StartResult.of("PERSISTENCE_HALTED"), context).stopReason());
        assertEquals("a rollback is running", ClaimLeases.refused(StartResult.of("ROLLBACK_RUNNING"), context)
            .busyReason());
        assertEquals("CoreProtect is reloading the database", ClaimLeases.refused(StartResult.of("RELOAD_RUNNING"),
            context).busyReason());
        assertEquals("interrupted", ClaimLeases.refused(StartResult.of("INTERRUPTED"), context).busyReason());
    }

    @Test
    @DisplayName("should stop for the shutdown, not a busy database, when told to stop while CoreProtect refuses")
    void newAnswerWhileStopping() throws Exception {
        PurgeContext stopping = new PurgeContext();
        // Package-private in purge, where the auto-purge thread's scheduler calls it
        Method requestStop = PurgeContext.class.getDeclaredMethod("requestStop");
        requestStop.setAccessible(true);
        requestStop.invoke(stopping);

        Lease lease = ClaimLeases.refused(StartResult.of("SOMETHING_NEW"), stopping);

        assertEquals(StopReason.SHUTDOWN, lease.stopReason());
        assertNull(lease.stopDetail());
        assertEquals(StopReason.SHUTDOWN, ClaimLeases.refused(StartResult.of("INTERRUPTED"), stopping).stopReason());
    }

    @Test
    @DisplayName("should never take CoreProtect 24's ways on CoreProtect 25, however much of its claims are gone")
    void noOlderWays() {
        AssumeCapability.strategy("auto-purge.coordination", "background-claims");
        List<String> claims = new ArrayList<>();
        List<String> policy = new ArrayList<>();
        for (String[] fields : lines()) {
            if (fields.length > 2 && (fields[0].equals("member") || fields[0].equals("relies"))) {
                if (fields[1].equals("auto-purge.coordination")) {
                    claims.add(fields[2]);
                } else if (fields[1].equals("auto-purge.tables")) {
                    policy.add(fields[2]);
                }
            }
        }
        List<String> both = new ArrayList<>(claims);
        both.addAll(policy);

        Capabilities after = Capabilities.probe(Upstream.coreProtect().hiding(both.toArray(new String[0])));

        Choice<Leases> coordination = after.get(Leases.CAPABILITY);
        Choice<PurgeTables> tables = after.get(PurgeTables.CAPABILITY);
        assertEquals("unavailable", coordination.strategy(), coordination::toString);
        assertTrue(coordination.rejected().get(1).startsWith("cooperative-flags: CoreProtect has "),
            coordination.rejected()::toString);
        assertTrue(coordination.rejected().get(1).endsWith(", which replaced cooperative-flags"),
            coordination.rejected()::toString);
        assertEquals("unavailable", tables.strategy(), tables::toString);
        assertTrue(tables.rejected().get(1).endsWith(", which replaced purge-command-list"),
            tables.rejected()::toString);
        for (String engine : List.of("sqlite", "mysql", "duckdb")) {
            assertEquals("unavailable", after.get("auto-purge.engine." + engine).strategy());
        }
    }

    /**
     * Check that purging a database of the engine stops before it touches
     * the database, and says why, naming something that's gone.
     *
     * @param hidden what upstream lost
     */
    private void assertUnsupported(CoreProtectPurge bridge, Engine engine, List<String> hidden) throws Exception {
        coreProtect.useEngine(engine);
        List<String> names = new ArrayList<>();
        for (String member : hidden) {
            names.add(Missing.readableName(member));
        }
        String reason = bridge.unavailableReason();
        assertNotNull(reason, () -> engine + " can still be purged without " + hidden);
        assertTrue(names.stream().anyMatch(reason::contains), () -> "The reason names none of " + names + ": "
            + reason);
        assertEquals(StopReason.UNSUPPORTED_DATABASE, bridge.stopReason());
        Lease lease = bridge.lease(new PurgeContext(), true);
        assertFalse(lease.isGranted());
        assertEquals(StopReason.UNSUPPORTED_DATABASE, lease.stopReason());
        assertEquals(reason, lease.stopDetail());
        assertFalse(coreProtect.backgroundPurgeClaimed());
        assertEquals(false, coreProtect.get("Consumer.isPaused"));
    }

    private void assertStillPurges(CoreProtectPurge bridge, Engine engine) {
        coreProtect.useEngine(engine);
        String reason = bridge.unavailableReason();
        assertNull(reason, () -> engine + " can't be purged: " + reason);
        assertNull(bridge.stopReason(), engine::toString);
    }
}
