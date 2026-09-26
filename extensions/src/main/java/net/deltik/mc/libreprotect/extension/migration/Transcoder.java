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

import java.sql.SQLException;

/**
 * Converts a column value, such as from one engine's encoding to another's.
 */
@FunctionalInterface
interface Transcoder {

    /**
     * @param table the unprefixed table the value belongs to
     * @param column the column the value belongs to
     */
    Object apply(String table, String column, Object value) throws SQLException;

    /** Leaves every value as it is */
    Transcoder NONE = (table, column, value) -> value;
}
