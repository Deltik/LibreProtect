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

package net.deltik.mc.libreprotect.extension.purge;

import net.deltik.mc.libreprotect.extension.common.Engine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ChunkedPurge: DuckDB checkpoint")
class ChunkedPurgeCheckpointTest extends ChunkedPurgeFixture {

    private final List<String> statements = new CopyOnWriteArrayList<>();

    private void seed(Engine engine) throws SQLException {
        setUp(engine);
        insert("block", range(1, 10), repeat(CUTOFF - DAY, 10));
        insert("block", new long[]{11}, new long[]{CUTOFF + DAY});
        bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> statements.add(sql));
    }

    @Test
    @DisplayName("should checkpoint DuckDB, exclusively, after removing rows")
    void checkpoints() throws SQLException {
        seed(Engine.DUCKDB);

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals("CHECKPOINT", statements.get(statements.size() - 1));
        assertEquals(1, bridge.exclusiveLeases.get());
    }

    @Test
    @DisplayName("should not checkpoint SQLite")
    void notSQLite() throws SQLException {
        seed(Engine.SQLITE);
        assertEquals(10, purge(CUTOFF).removed());
        assertFalse(statements.contains("CHECKPOINT"));
    }

    @Test
    @DisplayName("should not checkpoint DuckDB when nothing was removed")
    void notWhenNothingRemoved() throws SQLException {
        seed(Engine.DUCKDB);
        assertEquals(0, purge(CUTOFF - 2 * DAY).removed());
        assertFalse(statements.contains("CHECKPOINT"));
        assertEquals(0, bridge.exclusiveLeases.get());
    }

    @Test
    @DisplayName("should only warn when the checkpoint fails")
    void failure() throws SQLException {
        setUp(Engine.DUCKDB);
        insert("block", range(1, 10), repeat(CUTOFF - DAY, 10));
        bridge.connections = connection -> StatementHooks.wrap(connection, (sql, parameters) -> {
            if (sql.equals("CHECKPOINT")) {
                throw new SQLException("Could not checkpoint");
            }
        });

        PurgeResult result = purge(CUTOFF);

        assertTrue(result.completed());
        assertEquals(10, result.removed());
        assertEquals(1, log.containing("couldn't checkpoint the DuckDB database").size(), log::toString);
    }
}
