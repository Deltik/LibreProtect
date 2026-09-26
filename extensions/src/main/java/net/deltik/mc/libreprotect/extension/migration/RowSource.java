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

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalLong;

/**
 * Reads a CoreProtect database table by table, in row ID order. A migration
 * reads its source through one, and validation reads the target back through
 * another.
 *
 * <p>Table names are unprefixed, e.g. {@code block} for {@code co_block}.
 * Column lists never include the row ID, which every table has under some
 * name ({@code rowid}, or {@code id} where SQLite aliases it).
 */
public interface RowSource extends AutoCloseable {

    Engine engine();

    /**
     * @return the CoreProtect tables present, unprefixed
     */
    List<String> tables() throws SQLException;

    /**
     * @return the table's columns other than the row ID, in the database's order
     */
    List<String> columns(String table) throws SQLException;

    TableStats stats(String table) throws SQLException;

    /**
     * @return the highest row ID the engine's allocator has handed out for the
     *         table, which can exceed the largest surviving row ID; empty if
     *         the engine has no allocator state beyond the rows themselves
     *         (SQLite)
     */
    OptionalLong highWater(String table) throws SQLException;

    /**
     * @return up to {@code limit} rows with a row ID greater than
     *         {@code afterRowId}, in row ID order, with values in the order of
     *         {@code columns}
     */
    List<Row> read(String table, List<String> columns, long afterRowId, int limit) throws SQLException;

    /**
     * @return the rows with row IDs from {@code fromRowId} to {@code toRowId}
     *         inclusive, in row ID order
     */
    List<Row> readRange(String table, List<String> columns, long fromRowId, long toRowId) throws SQLException;

    /**
     * Read several ranges at once. Engines that scan a whole table for any
     * row ID range, like ClickHouse, read them all in one scan.
     *
     * @param ranges row ID ranges as {@code {fromRowId, toRowId}}, inclusive,
     *               in ascending order and not overlapping
     * @return the rows in the ranges, in row ID order
     */
    default List<Row> readRanges(String table, List<String> columns, List<long[]> ranges) throws SQLException {
        List<Row> rows = new ArrayList<>();
        for (long[] range : ranges) {
            rows.addAll(readRange(table, columns, range[0], range[1]));
        }
        return rows;
    }

    /**
     * Make a call that another thread is waiting in fail soon, and every
     * later call fail, such as by aborting network connections. Called from
     * another thread when the migration has to stop, such as when the server
     * shuts down; {@link #close()} still follows on the migration's thread.
     * Never throws. The default does nothing, for sources that can't hang.
     */
    default void abort() {
    }

    @Override
    void close() throws SQLException;
}
