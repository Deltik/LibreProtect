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
 * A sink that passes everything on, for tests to override one step.
 */
public class ForwardingSink implements RowSink {

    private final RowSink delegate;

    public ForwardingSink(RowSink delegate) {
        this.delegate = delegate;
    }

    @Override
    public Engine engine() {
        return delegate.engine();
    }

    @Override
    public Optional<String> nonEmptyReason() throws SQLException {
        return delegate.nonEmptyReason();
    }

    @Override
    public void prepare(Map<String, Long> highWater) throws SQLException {
        delegate.prepare(highWater);
    }

    @Override
    public List<String> columns(String table) throws SQLException {
        return delegate.columns(table);
    }

    @Override
    public void markIncomplete() throws SQLException {
        delegate.markIncomplete();
    }

    @Override
    public void write(String table, List<String> columns, List<Row> rows) throws SQLException {
        delegate.write(table, columns, rows);
    }

    @Override
    public void finish(Map<String, Long> highWater) throws SQLException {
        delegate.finish(highWater);
    }

    @Override
    public RowSource readBack() throws SQLException {
        return delegate.readBack();
    }

    @Override
    public void markComplete() throws SQLException {
        delegate.markComplete();
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
