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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * An upstream that adds constants LibreProtect doesn't know, such as a new
 * database engine or a new answer to starting maintenance: they're reported
 * as such, and nothing throws.
 */
class NewConstantsTest {

    /** CoreProtect's engine enum, with an engine it might add */
    enum FutureEngines {
        CLICKHOUSE("ClickHouse"), DUCKDB("DuckDB"), MYSQL("MySQL"), POSTGRESQL("PostgreSQL"), SQLITE("SQLite");

        private final String displayName;

        FutureEngines(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    /** CoreProtect 25's ConfigHandler, as far as the selector goes */
    static final class FutureHandler {
        static volatile FutureEngines databaseType = FutureEngines.SQLITE;
    }

    /** CoreProtect 25's answers to starting maintenance, with one it might add */
    enum FutureResults {
        STARTED, PURGE_RUNNING, SOMETHING_NEW
    }

    private final Upstream future = Upstream.coreProtect()
        .replacing(Names.CONFIG_HANDLER, FutureHandler.class)
        .replacing(Names.DATABASE_TYPE, FutureEngines.class)
        .replacing(Names.OPERATION_START_RESULT, FutureResults.class);

    @AfterEach
    void restore() {
        FutureHandler.databaseType = FutureEngines.SQLITE;
    }

    @Test
    @DisplayName("should list an unknown engine as unsupported, and know no engine while it's active")
    void newEngine() throws Exception {
        Choice<ActiveDatabase> choice = Capabilities.probe(future).get(ActiveDatabase.CAPABILITY);
        ActiveDatabase database = choice.require();

        assertEquals("database-type", choice.strategy());
        assertEquals(List.of("clickhouse", "duckdb", "mysql", "postgresql(unsupported)", "sqlite"),
            database.engineNames());
        assertEquals(EnumSet.allOf(Engine.class), database.engines());
        assertEquals(Engine.SQLITE, database.activeEngine());
        FutureHandler.databaseType = FutureEngines.POSTGRESQL;
        assertNull(database.activeEngine());
        FutureHandler.databaseType = FutureEngines.MYSQL;
        assertEquals(Engine.MYSQL, database.activeEngine());
        assertTrue(choice.reportLines().contains("enum\tdatabase.selector\tnet/coreprotect/database/DatabaseType"
            + "\tCLICKHOUSE,DUCKDB,MYSQL,POSTGRESQL,SQLITE"));
    }

    @Test
    @DisplayName("should keep an unknown answer's name, and refuse with it")
    void newStartResult() throws Exception {
        Choice<?> choice = Capabilities.probe(future).get(StartResult.CAPABILITY);
        StartResult result = StartResult.of(FutureResults.SOMETHING_NEW);

        assertEquals("named-results", choice.strategy());
        assertEquals(StartResult.Kind.OTHER, result.kind());
        assertEquals("SOMETHING_NEW", result.name());
        assertFalse(result.started());
        assertEquals("CoreProtect's database is busy (SOMETHING_NEW).", result.refusal());
        assertEquals(StartResult.Kind.PURGE_RUNNING, StartResult.of(FutureResults.PURGE_RUNNING).kind());
        assertTrue(choice.reportLines().contains("enum\tconsumer.start-result"
            + "\tnet/coreprotect/consumer/Consumer$OperationStartResult\tSTARTED,PURGE_RUNNING,SOMETHING_NEW"));
    }

    @Test
    @DisplayName("should probe and report every capability of such an upstream without throwing")
    void nothingThrows() {
        Capabilities capabilities = assertDoesNotThrow(() -> Capabilities.probe(future));

        String report = assertDoesNotThrow(() -> CapabilityReport.render(capabilities, null));
        assertTrue(report.contains("capability\tdatabase.selector\tdatabase-type\t"), report);
    }
}
