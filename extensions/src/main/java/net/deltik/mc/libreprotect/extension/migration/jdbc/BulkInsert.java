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

package net.deltik.mc.libreprotect.extension.migration.jdbc;

import net.deltik.mc.libreprotect.extension.migration.Row;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

/**
 * A faster way than SQL statements to insert rows into one engine.
 */
@FunctionalInterface
public interface BulkInsert {

    /**
     * Insert rows with their row IDs, within the connection's transaction,
     * which has started.
     *
     * @param table the prefixed table name
     * @param columns the columns of each row's values
     * @return whether the rows were inserted; {@code false}, with nothing
     *         inserted, if a value doesn't fit exactly, so that the caller
     *         inserts the rows with SQL, which converts or rejects it
     */
    boolean insert(Connection connection, String table, List<String> columns, List<Row> rows) throws SQLException;
}
