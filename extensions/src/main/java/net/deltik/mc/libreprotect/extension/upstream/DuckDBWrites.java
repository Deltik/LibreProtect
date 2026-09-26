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

import net.deltik.mc.libreprotect.extension.migration.jdbc.BulkInsert;
import net.deltik.mc.libreprotect.extension.migration.jdbc.DuckDBAppenderInsert;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;

/**
 * How a migration writes a DuckDB target: through the appender of the
 * DuckDB driver that CoreProtect brings along, or with SQL, which is always
 * safe, only slower.
 *
 * <p>Only a CoreProtect without the multi-engine layer lacks DuckDB, so that
 * alone makes this absent, however CoreProtect names its DuckDB classes.
 */
public final class DuckDBWrites {

    public static final Capability<DuckDBWrites> CAPABILITY = Capability.of("migrate-db.duckdb-writes",
        Choice.way("appender", "DuckDB's appender", DuckDBWrites::appender),
        Choice.fallback("sql-inserts", "SQL batch inserts, slower than DuckDB's appender", DuckDBWrites::sql));

    private final boolean appender;

    private DuckDBWrites(boolean appender) {
        this.appender = appender;
    }

    /**
     * The driver isn't in CoreProtect's JAR, which only names it among its
     * plugin libraries, so the report has nothing of it to list.
     */
    private static DuckDBWrites appender(Upstream upstream) throws Missing {
        Designs.MULTI_ENGINE.requireIn(upstream);
        requireProtocol(upstream);
        Upstream driver = upstream.library("DuckDB's JDBC driver");
        DuckDBAppenderInsert.requireAppender(driver, driver.type(Names.DUCKDB_CONNECTION).type());
        return new DuckDBWrites(true);
    }

    private static DuckDBWrites sql(Upstream upstream) throws Missing {
        Designs.MULTI_ENGINE.requireIn(upstream);
        requireProtocol(upstream);
        return new DuckDBWrites(false);
    }

    /**
     * Only migrations write DuckDB this way, and every migration needs the
     * protocol, so the capability report says that these writes don't work
     * whenever migrations don't.
     */
    private static void requireProtocol(Upstream upstream) throws Missing {
        MigrationProtocol.CAPABILITY.probe(upstream).require();
    }

    public boolean usesAppender() {
        return appender;
    }

    /**
     * @return a bulk insert for a DuckDB sink, or {@code null} for SQL
     */
    public BulkInsert bulkInsert() {
        return appender ? new DuckDBAppenderInsert() : null;
    }
}
