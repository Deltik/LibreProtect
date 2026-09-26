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

import net.deltik.mc.libreprotect.extension.common.Console;
import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Connector;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Dialect;

import java.io.File;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * The migration's own core and test databases, for tests elsewhere that run
 * whole migrations through other endpoints, such as ClickHouse's.
 */
public final class MigrationTestAccess {

    private MigrationTestAccess() {
    }

    /**
     * Migrate as {@code /co migrate-db} does, validating a sample of the rows
     * of larger tables.
     */
    public static void migrate(MigrationBridge bridge, MigrationSession session, Console console, Engine target,
                               Random random) {
        new Migration(bridge, session, console, target, false, System::nanoTime, random).run();
    }

    /**
     * @see TestDatabases#createLegacySqlite
     */
    public static void createLegacySqlite(File file, int blocks) throws SQLException {
        TestDatabases.createLegacySqlite(file, blocks);
    }

    /**
     * @return every table's rows, with encoded values in the bridge's
     *         canonical encoding
     * @see TestDatabases#dump(Dialect, Connector, Transcoder)
     */
    public static Map<String, List<String>> dump(Dialect dialect, Connector connector, MigrationBridge bridge)
        throws SQLException {
        return TestDatabases.dump(dialect, connector, bridge::canonical);
    }

    /**
     * @return a connector to a test database: SQLite, DuckDB or MySQL
     */
    public static Connector connector(DatabaseSettings settings) {
        return FakeBridge.FakeSession.connector(settings);
    }
}
