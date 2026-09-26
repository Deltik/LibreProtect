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

import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.Row;
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import net.deltik.mc.libreprotect.extension.migration.TableStats;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLDataException;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.*;

class JdbcTest {

    private static final List<String> TABLES = List.of("database_lock", "thing");

    @TempDir
    Path folder;

    private File file(String name) {
        return folder.resolve(name).toFile();
    }

    private static Connector connector(Dialect dialect, File file) {
        if (dialect == Dialect.DUCKDB) {
            Properties properties = new Properties();
            properties.setProperty("threads", "1");
            return Connectors.duckdb(file, properties);
        }
        return Connectors.sqlite(file);
    }

    /** A CoreProtect-like table with a UNIQUE column, like entity_spawn's uuid */
    private static SchemaCreator schema(Dialect dialect) {
        return (connection, prefix) -> {
            try (Statement statement = connection.createStatement()) {
                if (dialect == Dialect.DUCKDB) {
                    statement.execute("CREATE SEQUENCE IF NOT EXISTS " + prefix + "thing_rowid_seq START 1");
                    statement.execute("CREATE TABLE " + prefix + "thing (rowid BIGINT NOT NULL DEFAULT nextval('"
                        + prefix + "thing_rowid_seq'), amount INTEGER, uuid VARCHAR UNIQUE, data BLOB, yaw FLOAT)");
                } else {
                    statement.execute("CREATE TABLE " + prefix + "thing (id INTEGER PRIMARY KEY ASC, amount INTEGER,"
                        + " uuid TEXT UNIQUE, data BLOB, yaw REAL)");
                }
            } finally {
                if (dialect.schemaClosesConnection()) {
                    connection.close();
                }
            }
        };
    }

    private static JdbcRowSink sink(Dialect dialect, File file) {
        return new JdbcRowSink(dialect, connector(dialect, file), "co_", TABLES, schema(dialect),
            IncompleteMarker.status(2), file, dialect == Dialect.DUCKDB ? new DuckDBAppenderInsert() : null);
    }

    /**
     * @return the connection, but preparing a statement whose SQL matches
     *         fails, as if the migration stopped there
     */
    private static Connection failing(Connection connection, Predicate<String> sql) {
        return (Connection) Proxy.newProxyInstance(JdbcTest.class.getClassLoader(), new Class<?>[]{Connection.class},
            (proxy, method, arguments) -> {
                if (method.getName().equals("prepareStatement") && sql.test((String) arguments[0])) {
                    throw new SQLException("stopped");
                }
                try {
                    return method.invoke(connection, arguments);
                } catch (InvocationTargetException e) {
                    throw e.getCause();
                }
            });
    }

    private static final List<String> COLUMNS = List.of("amount", "uuid", "data", "yaw");

    private static Row row(long rowId, Object amount, String uuid) {
        return new Row(rowId, new Object[]{amount, uuid, new byte[]{(byte) rowId}, 1.5});
    }

    @Nested
    @DisplayName("sinks")
    class Sinks {

        @ParameterizedTest
        @EnumSource(value = Dialect.class, names = {"SQLITE", "DUCKDB"})
        @DisplayName("should name the row that breaks a constraint, and write none of its batch")
        void namesBadRow(Dialect dialect) throws SQLException {
            try (JdbcRowSink sink = sink(dialect, file("target"))) {
                sink.prepare(Map.of("thing", 10L));
                List<Row> rows = List.of(row(1, 1L, "a"), row(2, 2L, "b"), row(5, 3L, "a"), row(6, 4L, "c"));

                SQLException error = assertThrows(SQLException.class, () -> sink.write("thing", COLUMNS, rows));

                assertTrue(error.getMessage().startsWith("Row ID 5 of table thing can't be written to the target"),
                    error.getMessage());
                try (RowSource copy = sink.readBack()) {
                    assertEquals(0, copy.stats("thing").count());
                }
            }
        }

        @ParameterizedTest
        @EnumSource(value = Dialect.class, names = {"SQLITE", "DUCKDB"})
        @DisplayName("should write a batch again after a failure without duplicating rows")
        void writesAgain(Dialect dialect) throws SQLException {
            try (JdbcRowSink sink = sink(dialect, file("target"))) {
                sink.prepare(Map.of("thing", 10L));
                sink.write("thing", COLUMNS, List.of(row(1, 1L, "a"), row(2, 2L, "b")));
                assertThrows(SQLException.class, () -> sink.write("thing", COLUMNS, List.of(row(3, 3L, "a"))));

                sink.write("thing", COLUMNS, List.of(row(3, 3L, "c"), row(4, 4L, "d")));

                try (RowSource copy = sink.readBack()) {
                    assertEquals(new TableStats(4, 1, 4), copy.stats("thing"));
                }
            }
        }

        @Test
        @DisplayName("should let DuckDB convert values that its appender can't take as they are")
        void appenderFallsBack() throws SQLException {
            try (JdbcRowSink sink = sink(Dialect.DUCKDB, file("target.duckdb"))) {
                sink.prepare(Map.of());

                sink.write("thing", COLUMNS, List.of(row(1, 1L, "a"), row(2, "22", "b")));

                try (RowSource copy = sink.readBack()) {
                    List<Row> rows = copy.readRange("thing", COLUMNS, 0, 10);
                    assertEquals(22L, rows.get(1).values()[0]);
                }
                SQLException error = assertThrows(SQLException.class,
                    () -> sink.write("thing", COLUMNS, List.of(row(3, 5_000_000_000L, "c"))));
                assertTrue(error.getMessage().startsWith("Row ID 3 of table thing"), error.getMessage());
            }
        }

        @Test
        @DisplayName("should create DuckDB's sequences after the high-water marks before the schema")
        void duckDBSequences() throws SQLException {
            try (JdbcRowSink sink = sink(Dialect.DUCKDB, file("target.duckdb"))) {
                sink.prepare(Map.of("thing", 41L));
                sink.write("thing", COLUMNS, List.of(row(40, 1L, "a")));
                sink.finish(Map.of("thing", 41L));

                try (RowSource copy = sink.readBack()) {
                    assertEquals(OptionalLong.of(41), copy.highWater("thing"));
                }
            }
        }

        @Test
        @DisplayName("should not create an embedded database file before it's prepared")
        void lazyFile() throws SQLException {
            try (JdbcRowSink sink = sink(Dialect.SQLITE, file("target.db"))) {
                assertTrue(sink.nonEmptyReason().isEmpty());
            }
            assertFalse(file("target.db").exists());
        }

        @Test
        @DisplayName("should write the marker before CoreProtect's schema and keep it through the schema")
        void markerFirst() throws SQLException {
            AtomicInteger lockRows = new AtomicInteger(-1);
            SchemaCreator checking = (connection, prefix) -> {
                try (Statement statement = connection.createStatement();
                     ResultSet result = statement.executeQuery("SELECT status FROM co_database_lock WHERE rowid = 1")) {
                    lockRows.set(result.next() ? result.getInt(1) : 0);
                }
                schema(Dialect.SQLITE).create(connection, prefix);
            };
            try (JdbcRowSink sink = new JdbcRowSink(Dialect.SQLITE, connector(Dialect.SQLITE, file("t.db")), "co_",
                TABLES, checking, IncompleteMarker.lockedForever(1), file("t.db"), null)) {
                sink.prepare(Map.of());
            }
            assertEquals(1, lockRows.get());
            try (Connection connection = connector(Dialect.SQLITE, file("t.db")).open();
                 Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("SELECT status, time FROM co_database_lock")) {
                assertTrue(result.next());
                assertEquals(1, result.getInt(1));
                assertEquals(Integer.MAX_VALUE, result.getInt(2), "CoreProtect 24 would accept the lock after 15 s");
                assertFalse(result.next());
            }
        }

        @ParameterizedTest
        @EnumSource(value = Dialect.class, names = {"SQLITE", "DUCKDB"})
        @DisplayName("should create the lock table only together with its mark")
        void lockTableWithMark(Dialect dialect) throws SQLException {
            File file = file("target");
            Connector stopsBeforeMark = () -> failing(connector(dialect, file).open(),
                sql -> sql.startsWith("INSERT INTO \"co_database_lock\""));
            try (JdbcRowSink sink = new JdbcRowSink(dialect, stopsBeforeMark, "co_", TABLES, schema(dialect),
                IncompleteMarker.status(2), file, null)) {
                SQLException error = assertThrows(SQLException.class, () -> sink.prepare(Map.of()));
                assertEquals("stopped", error.getMessage());
            }

            try (Connection connection = connector(dialect, file).open()) {
                assertEquals(Set.of(), dialect.existingTables(connection), "a lock table without its mark");
            }
            if (dialect == Dialect.SQLITE) {
                // Tried again, the migration finds the target empty and marks it; a DuckDB target must be a new file
                try (JdbcRowSink sink = sink(dialect, file)) {
                    assertEquals(Optional.empty(), sink.nonEmptyReason());
                    sink.prepare(Map.of());
                }
                try (Connection connection = connector(dialect, file).open();
                     Statement statement = connection.createStatement();
                     ResultSet result = statement.executeQuery("SELECT status FROM co_database_lock")) {
                    assertTrue(result.next());
                    assertEquals(2, result.getInt(1));
                    assertFalse(result.next());
                }
            }
        }

        @Test
        @DisplayName("should check that CoreProtect created every table")
        void missingTable() {
            SchemaCreator nothing = (connection, prefix) -> connection.close();
            JdbcRowSink sink = new JdbcRowSink(Dialect.SQLITE, connector(Dialect.SQLITE, file("t.db")), "co_", TABLES,
                nothing, IncompleteMarker.status(2), file("t.db"), null);

            SQLException error = assertThrows(SQLException.class, () -> sink.prepare(Map.of()));

            assertEquals("CoreProtect didn't create table co_thing in the target", error.getMessage());
        }
    }

    @Nested
    @DisplayName("sources")
    class Sources {

        @Test
        @DisplayName("should page through DuckDB's sparse row IDs in order without an index")
        void duckDBPaging() throws SQLException {
            List<Long> rowIds = new ArrayList<>(List.of(1L, 2L, 3L, 1_000_000_000L, 1_000_000_001L,
                5_000_000_000L));
            for (long rowId = 2_000_000_000L; rowId < 2_000_003_000L; rowId += 3) {
                rowIds.add(rowId);
            }
            rowIds.sort(null);
            try (JdbcRowSink sink = sink(Dialect.DUCKDB, file("paged.duckdb"))) {
                sink.prepare(Map.of());
                List<Row> rows = new ArrayList<>();
                for (long rowId : rowIds) {
                    rows.add(row(rowId, rowId % 1000, "u" + rowId));
                }
                sink.write("thing", COLUMNS, rows);
                try (RowSource source = sink.readBack()) {
                    List<Long> read = new ArrayList<>();
                    long after = 0;
                    for (List<Row> page = source.read("thing", COLUMNS, after, 7); !page.isEmpty();
                         page = source.read("thing", COLUMNS, after, 7)) {
                        assertTrue(page.size() <= 7);
                        for (Row row : page) {
                            read.add(row.rowId());
                        }
                        after = page.get(page.size() - 1).rowId();
                    }
                    assertEquals(rowIds, read);
                }
            }
        }

        @Test
        @DisplayName("should refuse writes through a SQLite source's connection")
        void readOnlySqlite() throws SQLException {
            try (JdbcRowSink sink = sink(Dialect.SQLITE, file("source.db"))) {
                sink.prepare(Map.of());
            }
            List<Connection> opened = new ArrayList<>();
            Connector recording = () -> {
                Connection connection = Connectors.sqlite(file("source.db")).open();
                opened.add(connection);
                return connection;
            };
            try (JdbcRowSource source = new JdbcRowSource(Dialect.SQLITE, recording, true, true, "co_", TABLES)) {
                assertEquals(List.of("database_lock", "thing"), source.tables());
                assertEquals(COLUMNS, source.columns("thing"), "the id alias of the rowid isn't a column");
                try (Statement statement = opened.get(0).createStatement()) {
                    assertThrows(SQLException.class, () -> statement.execute("DELETE FROM co_thing"));
                }
            }
        }

        @Test
        @DisplayName("should report an empty table as 0 rows with row IDs 0 to 0")
        void emptyStats() throws SQLException {
            try (JdbcRowSink sink = sink(Dialect.SQLITE, file("source.db"))) {
                sink.prepare(Map.of());
                try (RowSource source = sink.readBack()) {
                    assertEquals(new TableStats(0, 0, 0), source.stats("thing"));
                    assertEquals(OptionalLong.empty(), source.highWater("thing"));
                    assertEquals(Engine.SQLITE, source.engine());
                }
            }
        }
    }

    @Nested
    @DisplayName("DuckDB high-water marks")
    class DuckDBHighWater {

        private Connector duckdb(File file) {
            Properties properties = new Properties();
            properties.setProperty("threads", "1");
            return Connectors.duckdb(file, properties);
        }

        /**
         * Rows 1 to 10 through the sequence, like CoreProtect's consumer, then
         * 11 to 15 reserved and not written, like its block writer's
         * {@code SELECT nextval(...) FROM range(?)}
         */
        private void seed(Connection connection) throws SQLException {
            try (Statement statement = connection.createStatement()) {
                statement.execute("CREATE SEQUENCE co_thing_rowid_seq START 1");
                statement.execute("CREATE TABLE co_thing (rowid INTEGER NOT NULL DEFAULT nextval('co_thing_rowid_seq'),"
                    + " amount INTEGER)");
                statement.execute("INSERT INTO co_thing (amount) SELECT range FROM range(10)");
                try (ResultSet reserved = statement.executeQuery("SELECT nextval('co_thing_rowid_seq') FROM range(5)")) {
                    while (reserved.next()) {
                        assertTrue(reserved.getLong(1) > 10);
                    }
                }
            }
        }

        @Test
        @DisplayName("should read the last row ID handed out while the file stays open, reserved or not")
        void whileOpen() throws SQLException {
            File file = file("open.duckdb");
            try (Connection open = duckdb(file).open()) {
                seed(open);
                try (JdbcRowSource source = new JdbcRowSource(Dialect.DUCKDB,
                    () -> ((org.duckdb.DuckDBConnection) open).duplicate(), true, true, "co_", List.of("thing"))) {
                    assertEquals(OptionalLong.of(15), source.highWater("thing"));
                }
            }
        }

        @Test
        @DisplayName("should read one more once DuckDB reopened the file, which is the safe direction")
        void afterReopening() throws SQLException {
            File file = file("reopened.duckdb");
            try (Connection first = duckdb(file).open()) {
                seed(first);
            }
            try (JdbcRowSource source = new JdbcRowSource(Dialect.DUCKDB, duckdb(file), true, true, "co_",
                List.of("thing"))) {
                // DuckDB keeps a sequence's next value in the file, and reports it as the last one
                assertEquals(OptionalLong.of(16), source.highWater("thing"));
            }
        }
    }

    @Test
    @DisplayName("should refuse values of types CoreProtect doesn't store")
    void refusesOddValues() throws SQLException {
        try (JdbcRowSink sink = sink(Dialect.SQLITE, file("t.db"))) {
            sink.prepare(Map.of());
            SQLException error = assertThrows(SQLDataException.class, () -> sink.write("thing", COLUMNS,
                List.of(new Row(1, new Object[]{new Object(), null, null, null}))));
            assertTrue(error.getMessage().contains("unexpected type"), error.getMessage());
        }
    }
}
