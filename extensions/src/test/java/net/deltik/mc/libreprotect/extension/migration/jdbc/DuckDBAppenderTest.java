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

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.extension.migration.Row;
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Writing DuckDB through its appender, found by reflection on the driver's
 * connection class, and through SQL when the appender can't be found.
 */
class DuckDBAppenderTest {

    private static final List<String> TABLES = List.of("database_lock", "sample");
    private static final List<String> COLUMNS = List.of("big", "whole", "small", "tiny", "wide", "narrow", "text",
        "bytes");
    private static final String CONNECTION = "org.duckdb.DuckDBConnection";
    private static final String APPENDER = "org.duckdb.DuckDBAppender";

    @TempDir
    Path folder;

    private final TestLogger log = new TestLogger();

    @BeforeEach
    void logging() {
        // Without messages that earlier tests left buffered, such as warnings about capabilities
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(log);
    }

    @AfterEach
    void quiet() {
        LibreProtectLogger.reset();
    }

    /** Remembers whether each insert went through the appender */
    private static final class Recording implements BulkInsert {
        final BulkInsert inner;
        final List<Boolean> results = new ArrayList<>();

        Recording(BulkInsert inner) {
            this.inner = inner;
        }

        @Override
        public boolean insert(Connection connection, String table, List<String> columns, List<Row> rows)
            throws SQLException {
            boolean inserted = inner.insert(connection, table, columns, rows);
            results.add(inserted);
            return inserted;
        }
    }

    /** A table with every column type the appender takes */
    private static final SchemaCreator SCHEMA = (connection, prefix) -> {
        try (Statement statement = connection.createStatement()) {
            statement.execute("CREATE SEQUENCE IF NOT EXISTS " + prefix + "sample_rowid_seq START 1");
            statement.execute("CREATE TABLE " + prefix + "sample (rowid BIGINT NOT NULL DEFAULT nextval('" + prefix
                + "sample_rowid_seq'), big BIGINT, whole INTEGER, small SMALLINT, tiny TINYINT, wide DOUBLE,"
                + " narrow FLOAT, text VARCHAR, bytes BLOB)");
        }
    };

    private static final List<Row> ROWS = List.of(
        new Row(1, new Object[]{Long.MAX_VALUE, (long) Integer.MIN_VALUE, (long) Short.MAX_VALUE,
            (long) Byte.MIN_VALUE, Math.PI, 1.5, "Bessie éè 🐄", new byte[]{0, -1, 7}}),
        new Row(2, new Object[]{null, null, null, null, null, null, null, null}),
        new Row(5_000_000_000L, new Object[]{-1L, 0L, -2L, 3L, -0.25, 0.25, "", new byte[0]}));

    private JdbcRowSink sink(String name, BulkInsert bulkInsert, boolean wrapped) {
        File file = folder.resolve(name).toFile();
        Properties properties = new Properties();
        properties.setProperty("threads", "1");
        Connector duckDB = Connectors.duckdb(file, properties);
        return new JdbcRowSink(Dialect.DUCKDB, wrapped ? () -> wrap(duckDB.open()) : duckDB, "co_", TABLES, SCHEMA,
            IncompleteMarker.status(2), file, bulkInsert);
    }

    /**
     * @return a connection that wraps DuckDB's, as a pool's would, and
     *         gives it out through JDBC's unwrap
     */
    private static Connection wrap(Connection duckDB) {
        return (Connection) Proxy.newProxyInstance(DuckDBAppenderTest.class.getClassLoader(),
            new Class<?>[]{Connection.class}, (proxy, method, args) -> {
                if (method.getName().equals("unwrap")) {
                    return ((Class<?>) args[0]).isInstance(duckDB) ? duckDB : null;
                }
                if (method.getName().equals("isWrapperFor")) {
                    return ((Class<?>) args[0]).isInstance(duckDB);
                }
                try {
                    return method.invoke(duckDB, args);
                } catch (InvocationTargetException e) {
                    throw e.getCause();
                }
            });
    }

    private List<Row> copy(String name, BulkInsert bulkInsert) throws SQLException {
        return copy(name, bulkInsert, false);
    }

    /**
     * @return the rows the sink wrote, as they read back
     */
    private List<Row> copy(String name, BulkInsert bulkInsert, boolean wrapped) throws SQLException {
        try (JdbcRowSink sink = sink(name, bulkInsert, wrapped)) {
            sink.prepare(Map.of("sample", 5_000_000_000L));
            sink.write("sample", COLUMNS, ROWS);
            try (RowSource copy = sink.readBack()) {
                return copy.read("sample", COLUMNS, 0, 100);
            }
        }
    }

    private static void assertSameRows(List<Row> expected, List<Row> actual) {
        assertEquals(expected.size(), actual.size());
        for (int i = 0; i < expected.size(); i++) {
            assertEquals(expected.get(i).rowId(), actual.get(i).rowId());
            assertArrayEquals(expected.get(i).values(), actual.get(i).values(), "Row ID " + expected.get(i).rowId());
        }
    }

    @Test
    @DisplayName("should write every value exactly through the appender")
    void appender() throws SQLException {
        Recording appender = new Recording(new DuckDBAppenderInsert());

        List<Row> copy = copy("appender.duckdb", appender);

        assertEquals(List.of(true), appender.results);
        assertSameRows(ROWS, copy);
        assertTrue(log.getMessages().isEmpty(), log.getMessages().toString());
    }

    @Test
    @DisplayName("should find the appender behind a connection that wraps DuckDB's")
    void wrapped() throws SQLException {
        Recording appender = new Recording(new DuckDBAppenderInsert());

        List<Row> copy = copy("wrapped.duckdb", appender, true);

        assertEquals(List.of(true), appender.results);
        assertSameRows(ROWS, copy);
        assertTrue(log.getMessages().isEmpty(), log.getMessages().toString());
    }

    @Test
    @DisplayName("should write an identical copy through SQL when the appender is hidden, with one note")
    void sqlFallback() throws SQLException {
        Upstream withoutAppender = Upstream.coreProtect().hiding(CONNECTION + "#createAppender");
        Recording sql = new Recording(new DuckDBAppenderInsert(withoutAppender));

        List<Row> viaSql = copy("sql.duckdb", sql);
        List<Row> viaAppender = copy("appender.duckdb", new DuckDBAppenderInsert());

        assertEquals(List.of(false), sql.results);
        assertSameRows(viaAppender, viaSql);
        assertSameRows(ROWS, viaSql);
        assertEquals(1, log.getMessages().size(), log.getMessages().toString());
        assertTrue(log.getMessages().get(0).contains("DuckDB's JDBC driver has no DuckDBConnection.createAppender"
            + "(String, String)"), log.getMessages().get(0));
    }

    @Test
    @DisplayName("should need every appender method it binds, whatever they return")
    void requiredMethods() throws Exception {
        Upstream driver = Upstream.coreProtect();
        Class<?> connection = Class.forName(CONNECTION, false, getClass().getClassLoader());

        DuckDBAppenderInsert.requireAppender(driver, connection);
        for (String method : Arrays.asList("beginRow", "endRow", "appendNull", "append", "flush", "close")) {
            Missing missing = assertThrows(Missing.class, () -> DuckDBAppenderInsert.requireAppender(
                driver.hiding(APPENDER + "#" + method), connection));
            assertTrue(missing.getMessage().startsWith("DuckDB's JDBC driver has no DuckDBAppender." + method + "("),
                missing.getMessage());
        }
    }
}
