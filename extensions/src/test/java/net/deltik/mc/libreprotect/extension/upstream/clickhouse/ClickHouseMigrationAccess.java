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

package net.deltik.mc.libreprotect.extension.upstream.clickhouse;

import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.RowSink;
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import net.deltik.mc.libreprotect.extension.upstream.Capabilities;

import java.io.IOException;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.Properties;

/**
 * The ClickHouse container's endpoints, with the real ClickHouse sink and
 * source, for whole migrations through the migration's copier and validator.
 */
final class ClickHouseMigrationAccess implements AutoCloseable {

    private final ClickHouseTestServer server;
    private final Properties endpoints;

    private ClickHouseMigrationAccess(ClickHouseTestServer server, Properties endpoints) {
        this.server = server;
        this.endpoints = endpoints;
    }

    /**
     * @return access to the container, or a skipped test without one
     */
    static ClickHouseMigrationAccess connect() throws IOException, SQLException {
        ClickHouseTestServer server = ClickHouseTestServer.connect();
        server.assumeWriterSupported();
        return new ClickHouseMigrationAccess(server, ClickHouseTestServer.endpoints());
    }

    /**
     * @return settings for a new prefix, whose tables are dropped on {@link #close()}
     */
    DatabaseSettings newDatabase() {
        return DatabaseSettings.server(Engine.CLICKHOUSE, endpoints.getProperty("CLICKHOUSE_HOST"),
            Integer.parseInt(endpoints.getProperty("CLICKHOUSE_PORT")), server.database(),
            endpoints.getProperty("CLICKHOUSE_USERNAME"), endpoints.getProperty("CLICKHOUSE_PASSWORD"), false,
            server.newPrefix());
    }

    /**
     * @return a sink for the database, whose writer lock is in the control directory
     */
    RowSink sink(DatabaseSettings settings, Path controlDirectory) throws SQLException {
        ClickHouseApi api = server.api();
        return new ClickHouseRowSink(api, ClickHouseEndpoints.config(api, settings), settings.prefix(),
            controlDirectory, ClickHouseFixture.CORE_VERSION, new ClickHouseRowSinkTest.RecordingAssignments(),
            new PublishDeadline(ClickHouseRowSink.PUBLISH_LIMIT, () -> false));
    }

    /**
     * @return a source that reads the database
     */
    RowSource source(DatabaseSettings settings) throws SQLException {
        return new ClickHouseEndpoints(Capabilities.current()).openSource(settings);
    }

    @Override
    public void close() throws SQLException {
        server.close();
    }
}
