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
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import net.deltik.mc.libreprotect.extension.upstream.Capabilities;
import net.deltik.mc.libreprotect.extension.upstream.Designs;
import net.deltik.mc.libreprotect.extension.upstream.Names;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.testutil.AssumeCapability;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Path;
import java.sql.SQLFeatureNotSupportedException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The two capabilities that reach CoreProtect 25's ClickHouse storage, and
 * what becomes of them when upstream loses part of what they need: only the
 * direction that needs it becomes unavailable, naming it, and reads survive
 * a writer that changed.
 */
class ClickHouseApiTest {

    private static final boolean CLICKHOUSE = Upstream.coreProtect().has(Names.CLICKHOUSE_DATABASE);
    private static final Capabilities REAL = Capabilities.probe(Upstream.coreProtect());
    private static final String BATCH_RECEIPT_FAMILY = "net/coreprotect/database/clickhouse/ClickHouseSchema"
        + "#BATCH_RECEIPT_FAMILY:Ljava/lang/String;";

    /**
     * @return what a capability's chosen way needs and relies on, as the report writes it
     */
    private static Set<String> needs(String id) {
        Set<String> needs = new TreeSet<>();
        for (String line : REAL.get(id).reportLines()) {
            String[] fields = line.split("\t");
            if (fields[0].equals("member") || fields[0].equals("relies")) {
                needs.add(fields[2]);
            }
        }
        return needs;
    }

    /**
     * @return what only writing needs: not what reading needs, nor a class
     *         that has something reading needs
     */
    static Stream<Arguments> writerNeeds() {
        Set<String> reader = needs(ClickHouseApi.READS.id());
        List<Arguments> arguments = new ArrayList<>();
        for (String need : needs(ClickHouseApi.WRITES.id())) {
            if (!reader.contains(need) && reader.stream().noneMatch(read -> read.startsWith(need + "#"))) {
                arguments.add(Arguments.of(need));
            }
        }
        return arguments.stream();
    }

    /**
     * @return what reading needs, which writing needs too
     */
    static Stream<Arguments> readerNeeds() {
        List<Arguments> arguments = new ArrayList<>();
        for (String need : needs(ClickHouseApi.READS.id())) {
            arguments.add(Arguments.of(need));
        }
        return arguments.stream();
    }

    @Test
    @DisplayName("should read and write CoreProtect 25's ClickHouse, and be quietly absent from a CoreProtect without it")
    void generations() throws Missing {
        Choice<ClickHouseApi> reads = REAL.get(ClickHouseApi.READS);
        Choice<ClickHouseApi> writes = REAL.get(ClickHouseApi.WRITES);

        if (CLICKHOUSE) {
            AssumeCapability.reviewedUpstream();
            assertEquals("migration-reads", reads.strategy(), reads::toString);
            assertEquals("compatibility-rows", writes.strategy(), writes::toString);
            assertFalse(reads.require().canWrite());
            assertTrue(writes.require().canWrite());
        } else {
            for (Choice<ClickHouseApi> choice : List.of(reads, writes)) {
                assertTrue(choice.isAbsent(), choice::toString);
                assertEquals("CoreProtect has no multi-engine database layer (CoreProtect 25)", choice.reason());
            }
        }
    }

    @Test
    @DisplayName("should be absent only without CoreProtect 25's design, and unavailable when ClickHouse moved")
    void absentOnlyWithoutDesign() {
        assumeTrue(CLICKHOUSE, "needs CoreProtect with ClickHouse");
        Capabilities older = Capabilities.probe(Upstream.coreProtect().hiding(Designs.MULTI_ENGINE.traces()
            .toArray(new String[0])));
        assertTrue(older.get(ClickHouseApi.READS).isAbsent(), () -> older.get(ClickHouseApi.READS).toString());
        assertTrue(older.get(ClickHouseApi.WRITES).isAbsent(), () -> older.get(ClickHouseApi.WRITES).toString());

        // As if CoreProtect moved its ClickHouse classes to another package
        List<String> moved = new ArrayList<>();
        for (String need : needs(ClickHouseApi.WRITES.id())) {
            if (need.startsWith("net/coreprotect/database/clickhouse/") && !need.contains("#")) {
                moved.add(need);
            }
        }
        Capabilities renamed = Capabilities.probe(Upstream.coreProtect().hiding(moved.toArray(new String[0])));
        for (Choice<ClickHouseApi> choice : List.of(renamed.get(ClickHouseApi.READS),
            renamed.get(ClickHouseApi.WRITES))) {
            assertEquals(Choice.UNAVAILABLE, choice.strategy(), choice::toString);
            assertTrue(choice.reason().startsWith("CoreProtect has no class ClickHouse"), choice::reason);
        }
    }

    // A CoreProtect without ClickHouse has nothing to lose
    @ParameterizedTest(name = "without {0}", allowZeroInvocations = true)
    @MethodSource("writerNeeds")
    @DisplayName("should leave reads alone when the writer loses something, and name it")
    void brokenWriter(String need) {
        assumeTrue(CLICKHOUSE, "needs CoreProtect with ClickHouse");
        Capabilities after = Capabilities.probe(Upstream.coreProtect().hiding(need));
        Choice<ClickHouseApi> reads = after.get(ClickHouseApi.READS);
        Choice<ClickHouseApi> writes = after.get(ClickHouseApi.WRITES);
        String name = Missing.readableName(need);

        assertEquals("migration-reads", reads.strategy(), reads::toString);
        assertEquals(Choice.UNAVAILABLE, writes.strategy(), writes::toString);
        assertTrue(writes.reason().contains(name), () -> writes.reason() + " doesn't name " + name);
    }

    @ParameterizedTest(name = "without {0}", allowZeroInvocations = true)
    @MethodSource("readerNeeds")
    @DisplayName("should stop both directions when reads lose something, and name it")
    void brokenReader(String need) {
        assumeTrue(CLICKHOUSE, "needs CoreProtect with ClickHouse");
        Capabilities after = Capabilities.probe(Upstream.coreProtect().hiding(need));
        String name = Missing.readableName(need);

        for (Choice<ClickHouseApi> choice : List.of(after.get(ClickHouseApi.READS), after.get(ClickHouseApi.WRITES))) {
            assertEquals(Choice.UNAVAILABLE, choice.strategy(), choice::toString);
            assertTrue(choice.reason().contains(name), () -> choice.reason() + " doesn't name " + name);
        }
    }

    /**
     * The checks of values rest on where CoreProtect's writer stores each
     * column, which it keeps private: a copy of it could go stale unnoticed,
     * and let a value be wrapped or stored as zero.
     */
    @Test
    @DisplayName("should stop writing, and say why, when CoreProtect's mapping of columns changes, rather than guess")
    void changedColumnMapping() {
        assumeTrue(CLICKHOUSE, "needs CoreProtect with ClickHouse");
        Capabilities after = Capabilities.probe(Upstream.coreProtect().hiding(
            Names.CLICKHOUSE_EVENT_BATCH + "#compatibilityColumn"));
        Choice<ClickHouseApi> writes = after.get(ClickHouseApi.WRITES);

        assertEquals(Choice.UNAVAILABLE, writes.strategy(), writes::toString);
        assertEquals("CoreProtect has no ClickHouseEventBatch.compatibilityColumn(ClickHouseFamily, String)",
            writes.reason());
        assertEquals("migration-reads", after.get(ClickHouseApi.READS).strategy());
    }

    @Test
    @DisplayName("should read the family of batch receipts from CoreProtect, and know it without")
    void batchReceipts() throws Missing {
        ClickHouseApi api = ClickHouseTestServer.writes();
        assertEquals("_batch_receipt", api.batchReceiptFamily());
        assertTrue(REAL.get(ClickHouseApi.WRITES).reportLines().contains("optional\tclickhouse.writes\t"
            + BATCH_RECEIPT_FAMILY + "\tpresent"));

        Choice<ClickHouseApi> without = Capabilities.probe(Upstream.coreProtect().hiding(BATCH_RECEIPT_FAMILY))
            .get(ClickHouseApi.WRITES);

        assertEquals("compatibility-rows", without.strategy());
        assertEquals(ClickHouseApi.BATCH_RECEIPT_FAMILY, without.require().batchReceiptFamily());
    }

    @Test
    @DisplayName("should leave writing to the writes capability")
    void readsOnly(@TempDir Path controlDirectory) {
        ClickHouseApi reads = ClickHouseTestServer.reads();
        ClickHouseApi.Config config = reads.config("127.0.0.1", 1, "coreprotect", "coreprotect", "", false);

        assertFalse(reads.canWrite());
        assertEquals("coreprotect", config.database());
        assertEquals("`coreprotect`.`co_block`", reads.qualified("coreprotect", "co_block"));
        assertEquals(21, reads.families().size());
        assertThrows(IllegalArgumentException.class, () -> reads.family("co_block"));
        assertThrows(IllegalStateException.class, reads::eventColumns);
        assertThrows(IllegalStateException.class, () -> reads.initialize(config, "co_", controlDirectory));
        assertThrows(IllegalArgumentException.class, () -> new ClickHouseRowSink(reads, config, "co_",
            controlDirectory, "2.24.1", (map, floor, candidates) -> List.of(),
            new PublishDeadline(ClickHouseRowSink.PUBLISH_LIMIT, () -> false),
            ClickHouseServerVersion.checking(connection -> { })));
    }

    @Test
    @DisplayName("should still read ClickHouse when it can't write it, and say why it can't")
    void endpointsWithoutWriter() throws Exception {
        assumeTrue(CLICKHOUSE, "needs CoreProtect with ClickHouse");
        ClickHouseEndpoints endpoints = new ClickHouseEndpoints(Capabilities.probe(Upstream.coreProtect().hiding(
            Names.CLICKHOUSE_DATABASE + "#publish")));
        DatabaseSettings settings = DatabaseSettings.server(Engine.CLICKHOUSE, "127.0.0.1", 1, "coreprotect",
            "coreprotect", "", false, "co_");

        try (RowSource source = endpoints.openSource(settings)) {
            assertEquals(Engine.CLICKHOUSE, source.engine());
        }
        SQLFeatureNotSupportedException refused = assertThrows(SQLFeatureNotSupportedException.class,
            () -> endpoints.openSink(settings));
        assertEquals("LibreProtect can't write this CoreProtect's ClickHouse storage: CoreProtect has no"
            + " ClickHouseDatabase.publish(ClickHouseWriteBatch)", refused.getMessage());
    }

    @Test
    @DisplayName("should say that a CoreProtect without ClickHouse has none to read or write")
    void endpointsWithoutClickHouse() {
        ClickHouseEndpoints endpoints = new ClickHouseEndpoints(Capabilities.probe(Upstream.coreProtect().hiding(
            Designs.MULTI_ENGINE.traces().toArray(new String[0]))));
        DatabaseSettings settings = DatabaseSettings.server(Engine.CLICKHOUSE, "127.0.0.1", 1, "coreprotect",
            "coreprotect", "", false, "co_");

        assertEquals("LibreProtect can't read this CoreProtect's ClickHouse storage: CoreProtect has no multi-engine"
            + " database layer (CoreProtect 25)", assertThrows(SQLFeatureNotSupportedException.class,
            () -> endpoints.openSource(settings)).getMessage());
        assertThrows(SQLFeatureNotSupportedException.class, () -> endpoints.openSink(settings));
    }
}
