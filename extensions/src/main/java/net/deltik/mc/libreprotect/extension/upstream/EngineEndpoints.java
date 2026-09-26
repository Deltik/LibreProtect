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

import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.RowSink;
import net.deltik.mc.libreprotect.extension.migration.RowSource;

import java.sql.SQLException;

/**
 * Reading and writing an engine that the migration's JDBC code can't handle
 * alone, through CoreProtect's own classes for it, such as ClickHouse.
 */
public interface EngineEndpoints {

    Engine engine();

    /**
     * @return a reader of an existing database of the engine, which may be
     *         the active one
     */
    RowSource openSource(DatabaseSettings settings) throws SQLException;

    /**
     * @return a writer of a new, empty database of the engine
     */
    RowSink openSink(DatabaseSettings settings) throws SQLException;

    /**
     * Hand the database behind a prepared sink from {@link #openSink} over
     * to CoreProtect, which activates it as it is, rather than connecting to
     * it anew, and without checking its unfinished-migration mark. So the
     * sink keeps the mark until CoreProtect uses the database; the caller
     * clears it through the sink then, and marks the database unfinished
     * again through the sink if the activation fails.
     *
     * @return CoreProtect's object for the database, for activation
     * @throws IllegalArgumentException if the sink isn't from {@link #openSink}
     * @throws IllegalStateException    if the sink isn't prepared or is closed
     */
    Object handOver(RowSink sink);
}
