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

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Creates CoreProtect's tables in a database, the way the running
 * CoreProtect version does. {@code upstream.Schema} gives one that runs
 * CoreProtect's own schema code; tests give their own.
 */
@FunctionalInterface
public interface SchemaCreator {

    /**
     * @param connection a connection to the database, which the creator may close
     * @param prefix the table prefix, such as {@code co_}
     */
    void create(Connection connection, String prefix) throws SQLException;
}
