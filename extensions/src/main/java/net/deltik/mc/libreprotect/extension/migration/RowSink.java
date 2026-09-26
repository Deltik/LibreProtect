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
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Writes a migration's target database. Used in this order:
 * {@link #nonEmptyReason()}, {@link #prepare}, {@link #markIncomplete()},
 * {@link #write} for every batch, {@link #finish}, validation through
 * {@link #readBack()}, and finally {@link #markComplete()} during activation.
 *
 * <p>Rows keep their row IDs. Values arrive already converted to this
 * engine's encoding.
 */
public interface RowSink extends AutoCloseable {

    Engine engine();

    /**
     * @return why the target can't be used because it already holds
     *         CoreProtect data, or empty if it holds none
     */
    Optional<String> nonEmptyReason() throws SQLException;

    /**
     * Create CoreProtect's schema, set up so row ID allocation continues
     * after the source's.
     *
     * @param highWater for each unprefixed table, the highest row ID the
     *                  source has handed out
     */
    void prepare(Map<String, Long> highWater) throws SQLException;

    /**
     * @return the table's columns other than the row ID, as created by {@link #prepare}
     */
    List<String> columns(String table) throws SQLException;

    /**
     * Mark the target as holding an unfinished migration, so CoreProtect
     * refuses to use it until {@link #markComplete()}.
     */
    void markIncomplete() throws SQLException;

    /**
     * Write a batch of rows, keeping their row IDs, atomically if the engine can.
     *
     * <p>After a transient failure, the caller retries with the identical
     * table, columns and rows before writing anything else, and the sink
     * must not duplicate rows that the failed attempt wrote after all.
     */
    void write(String table, List<String> columns, List<Row> rows) throws SQLException;

    /**
     * Finish writing, making sure row ID allocation continues after
     * {@code highWater} for each table.
     */
    void finish(Map<String, Long> highWater) throws SQLException;

    /**
     * @return a reader of what was written, for validation
     */
    RowSource readBack() throws SQLException;

    /**
     * Clear the unfinished-migration mark.
     */
    void markComplete() throws SQLException;

    /**
     * Make a call that another thread is waiting in fail soon, and every
     * later call fail, such as by aborting network connections. Called from
     * another thread when the migration has to stop, such as when the server
     * shuts down; {@link #close()} still follows on the migration's thread.
     * Never throws. The default does nothing, for sinks that can't hang.
     */
    default void abort() {
    }

    @Override
    void close() throws SQLException;
}
