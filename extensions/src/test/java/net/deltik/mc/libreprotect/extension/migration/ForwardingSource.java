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
import java.util.OptionalLong;

/**
 * A source that passes everything on, for tests to override one step.
 */
class ForwardingSource implements RowSource {

    private final RowSource delegate;

    ForwardingSource(RowSource delegate) {
        this.delegate = delegate;
    }

    @Override
    public Engine engine() {
        return delegate.engine();
    }

    @Override
    public List<String> tables() throws SQLException {
        return delegate.tables();
    }

    @Override
    public List<String> columns(String table) throws SQLException {
        return delegate.columns(table);
    }

    @Override
    public TableStats stats(String table) throws SQLException {
        return delegate.stats(table);
    }

    @Override
    public OptionalLong highWater(String table) throws SQLException {
        return delegate.highWater(table);
    }

    @Override
    public List<Row> read(String table, List<String> columns, long afterRowId, int limit) throws SQLException {
        return delegate.read(table, columns, afterRowId, limit);
    }

    @Override
    public List<Row> readRange(String table, List<String> columns, long fromRowId, long toRowId) throws SQLException {
        return delegate.readRange(table, columns, fromRowId, toRowId);
    }

    @Override
    public void abort() {
        delegate.abort();
    }

    @Override
    public void close() throws SQLException {
        delegate.close();
    }
}
