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

package net.deltik.mc.libreprotect.extension.migration;

import net.deltik.mc.libreprotect.extension.common.Engine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.OptionalLong;

import static org.junit.jupiter.api.Assertions.*;

class RowSourceReadRangesTest {

    @Test
    @DisplayName("should read several ranges one after another unless the engine reads them together")
    void defaultReadRanges() throws Exception {
        List<String> asked = new ArrayList<>();
        RowSource source = new RowSource() {
            @Override
            public Engine engine() {
                return Engine.SQLITE;
            }

            @Override
            public List<String> tables() {
                return List.of();
            }

            @Override
            public List<String> columns(String table) {
                return List.of();
            }

            @Override
            public TableStats stats(String table) {
                return new TableStats(0, 0, 0);
            }

            @Override
            public OptionalLong highWater(String table) {
                return OptionalLong.empty();
            }

            @Override
            public List<Row> read(String table, List<String> columns, long afterRowId, int limit) {
                return List.of();
            }

            @Override
            public List<Row> readRange(String table, List<String> columns, long fromRowId, long toRowId) {
                asked.add(table + " " + fromRowId + "-" + toRowId);
                return List.of(new Row(fromRowId, new Object[0]), new Row(toRowId, new Object[0]));
            }

            @Override
            public void close() {
            }
        };

        List<Row> rows = source.readRanges("block", List.of(), List.of(new long[]{1, 2}, new long[]{7, 9}));

        assertEquals(List.of("block 1-2", "block 7-9"), asked);
        assertEquals(List.of(1L, 2L, 7L, 9L), rows.stream().map(Row::rowId).toList());
        assertEquals(List.of(), source.readRanges("block", List.of(), List.of()));
    }
}
