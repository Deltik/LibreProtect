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

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.extension.common.Console;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.FakeBridge.FakeSession;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Connector;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Dialect;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamChanged;
import net.deltik.mc.libreprotect.testutil.RecordingSender;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.bukkit.command.ConsoleCommandSender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLRecoverableException;
import java.sql.SQLTransientConnectionException;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class MigrationTest {

    @TempDir
    Path folder;

    private RecordingSender console;

    @BeforeEach
    void setUp() {
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(new TestLogger());
        console = new RecordingSender(ConsoleCommandSender.class);
    }

    @AfterEach
    void tearDown() {
        LibreProtectLogger.reset();
    }

    private File file(String name) {
        return folder.resolve(name).toFile();
    }

    private FakeSession session(Engine from, String sourceName, Engine to, String targetName) {
        return new FakeSession(from, file(sourceName), to, file(targetName));
    }

    private void migrate(FakeSession session, boolean fullValidation) {
        migrate(session, fullValidation, new Random(42));
    }

    private void migrate(FakeSession session, boolean fullValidation, Random random) {
        FakeBridge bridge = new FakeBridge(session);
        new Migration(bridge, session, new Console(console.sender()), session.target.engine(), fullValidation,
            System::nanoTime, random).run();
    }

    private static Map<String, List<String>> dump(Engine engine, File file) throws SQLException {
        return dump(engine, file, Transcoder.NONE);
    }

    private static Map<String, List<String>> dump(Engine engine, File file, Transcoder decode) throws SQLException {
        FakeSession reader = new FakeSession(engine, file, engine, file);
        return TestDatabases.dump(Dialect.of(engine), FakeSession.connector(reader.source), decode);
    }

    private static Connector connector(Engine engine, File file) {
        FakeSession reader = new FakeSession(engine, file, engine, file);
        return FakeSession.connector(reader.source);
    }

    private static long scalar(Connector connector, String sql) throws SQLException {
        try (Connection connection = connector.open(); Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(sql)) {
            result.next();
            return result.getLong(1);
        }
    }

    private void assertSucceeded(FakeSession session) {
        String text = console.text();
        assertTrue(text.contains("Migration complete."), text);
        assertFalse(text.contains("Migration failed"), text);
        assertEquals(1, session.activations.get(), text);
        assertEquals(1, session.pauses.get());
        assertEquals(1, session.closes.get());
    }

    private void assertFailed(FakeSession session, String reason) {
        String text = console.text();
        assertTrue(text.contains("Migration failed."), text);
        assertTrue(text.contains(reason), text);
        assertEquals(0, session.activations.get(), text);
        assertEquals(1, session.closes.get());
    }

    @Nested
    @DisplayName("round trips")
    class RoundTrips {

        @Test
        @DisplayName("should copy SQLite to SQLite with every row ID and value, whatever the column order")
        void sqliteToSqlite() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 3_000);
            byte[] sourceBefore = Files.readAllBytes(folder.resolve("source.db"));
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");

            migrate(session, false);

            assertSucceeded(session);
            Map<String, List<String>> source = dump(Engine.SQLITE, file("source.db"));
            Map<String, List<String>> target = dump(Engine.SQLITE, file("target.db"));
            assertEquals(source.keySet(), target.keySet());
            source.forEach((table, rows) -> assertEquals(rows, target.get(table), table));
            assertEquals(3_000, source.get("block").size());
            assertTrue(target.get("block").get(2_999).startsWith(TestDatabases.LARGE_BLOCK_ROWID + ":"));
            assertArrayEquals(sourceBefore, Files.readAllBytes(folder.resolve("source.db")), "the source changed");
        }

        @Test
        @DisplayName("should copy SQLite to DuckDB, converting what the engines encode differently")
        void sqliteToDuckDB() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 3_000);
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.DUCKDB, "target.duckdb");

            migrate(session, false);

            assertSucceeded(session);
            Map<String, List<String>> source = dump(Engine.SQLITE, file("source.db"));
            Map<String, List<String>> decoded = dump(Engine.DUCKDB, file("target.duckdb"),
                (table, column, value) -> FakeBridge.isMeta(table, column) && value instanceof byte[]
                    ? decodeStrict((byte[]) value) : value);
            source.forEach((table, rows) -> assertEquals(rows, decoded.get(table), table));
        }

        @Test
        @DisplayName("should copy DuckDB back to SQLite and end up with the original data")
        void duckDBToSqlite() throws Exception {
            TestDatabases.createLegacySqlite(file("original.db"), 2_000);
            migrate(session(Engine.SQLITE, "original.db", Engine.DUCKDB, "middle.duckdb"), false);
            FakeSession back = session(Engine.DUCKDB, "middle.duckdb", Engine.SQLITE, "back.db");

            migrate(back, true);

            assertSucceeded(back);
            assertEquals(dump(Engine.SQLITE, file("original.db")), dump(Engine.SQLITE, file("back.db")));
        }

        @Test
        @DisplayName("should keep DuckDB's allocator high-water marks, even ahead of the largest row ID")
        void duckDBHighWater() throws Exception {
            TestDatabases.createLegacySqlite(file("original.db"), 100);
            migrate(session(Engine.SQLITE, "original.db", Engine.DUCKDB, "first.duckdb"), false);
            Connector first = connector(Engine.DUCKDB, file("first.duckdb"));
            long maxBlock = scalar(first, "SELECT MAX(rowid) FROM co_block");
            long maxUser = scalar(first, "SELECT MAX(rowid) FROM co_user");
            // CoreProtect's DuckDB block writer reserves row IDs ahead of what it writes
            for (int i = 0; i < 3; i++) {
                scalar(first, "SELECT nextval('co_user_rowid_seq')");
            }
            long userHighWater = scalar(first, "SELECT last_value FROM duckdb_sequences()"
                + " WHERE sequence_name = 'co_user_rowid_seq'");
            assertTrue(userHighWater > maxUser);

            FakeSession session = session(Engine.DUCKDB, "first.duckdb", Engine.DUCKDB, "second.duckdb");
            migrate(session, false);

            assertSucceeded(session);
            Connector second = connector(Engine.DUCKDB, file("second.duckdb"));
            assertEquals(maxBlock + 1, scalar(second, "SELECT nextval('co_block_rowid_seq')"));
            assertEquals(userHighWater + 1, scalar(second, "SELECT nextval('co_user_rowid_seq')"));
            assertEquals(1, scalar(second, "SELECT nextval('co_art_map_rowid_seq')"), "empty table");
        }

        @Test
        @DisplayName("should mark the target unfinished until activation, and never let CoreProtect's schema unmark it")
        void incompleteMarker() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 10);
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.DUCKDB, "target.duckdb");
            AtomicBoolean checked = new AtomicBoolean();
            session.sinkWrapper = sink -> new ForwardingSink(sink) {
                @Override
                public void write(String table, List<String> columns, List<Row> rows) throws SQLException {
                    super.write(table, columns, rows);
                    if (!checked.getAndSet(true)) {
                        try (RowSource copy = readBack()) {
                            assertNotNull(copy);
                        }
                    }
                }
            };
            session.activationFailure = new MigrationException("No activation in this test");

            migrate(session, false);

            assertTrue(checked.get());
            long[] lock = TestDatabases.lock(connector(Engine.DUCKDB, file("target.duckdb")));
            assertNotNull(lock);
            assertEquals(2, lock[0], "the target isn't marked unfinished");
        }
    }

    private static byte[] decodeStrict(byte[] value) {
        assertTrue(FakeBridge.isEncoded(value), "block.meta wasn't converted for DuckDB");
        return FakeBridge.decode(value);
    }

    @Nested
    @DisplayName("sources")
    class Sources {

        @Test
        @DisplayName("should find the source's tables whatever case the catalog reports their names in")
        void tableNamesInAnotherCase() throws Exception {
            // Like MySQL with lower_case_table_names, which reports cp_* for a table-prefix of CP_
            TestDatabases.createLegacySqlite(file("source.db"), 500);
            try (Connection connection = connector(Engine.SQLITE, file("source.db")).open();
                 Statement statement = connection.createStatement()) {
                for (String table : TestDatabases.TABLES) {
                    statement.execute("ALTER TABLE co_" + table + " RENAME TO CO_" + table + "_renamed");
                    statement.execute("ALTER TABLE CO_" + table + "_renamed RENAME TO CO_" + table);
                }
            }
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.DUCKDB, "target.duckdb");

            migrate(session, false);

            assertSucceeded(session);
            Map<String, List<String>> source = dump(Engine.SQLITE, file("source.db"));
            assertEquals(500, source.get("block").size());
            assertEquals(source, dump(Engine.DUCKDB, file("target.duckdb"),
                (table, column, value) -> FakeBridge.isMeta(table, column) && value instanceof byte[]
                    ? FakeBridge.decode((byte[]) value) : value));
        }

        @Test
        @DisplayName("should refuse a source without CoreProtect's tables, such as one with another prefix")
        void noCoreProtectTables() throws Exception {
            try (Connection connection = connector(Engine.SQLITE, file("source.db")).open();
                 Statement statement = connection.createStatement()) {
                statement.execute("CREATE TABLE unrelated (x INTEGER)");
            }
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");

            migrate(session, false);

            assertFailed(session, "has no table co_version, co_user, co_world, co_block, so it isn't the CoreProtect"
                + " database it should be. Check its settings in CoreProtect's config.yml, such as table-prefix.");
            assertFalse(file("target.db").exists(), "the target was written");
        }

        @Test
        @DisplayName("should refuse a source whose CoreProtect tables are all empty")
        void emptySource() throws Exception {
            try (Connection connection = connector(Engine.SQLITE, file("source.db")).open();
                 Statement statement = connection.createStatement()) {
                for (String sql : TestDatabases.schemaStatements(Engine.SQLITE, TestDatabases.PREFIX)) {
                    statement.execute(sql);
                }
            }
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.DUCKDB, "target.duckdb");

            migrate(session, false);

            assertFailed(session, "holds no CoreProtect data, so there's nothing to migrate. Check its settings in"
                + " CoreProtect's config.yml, such as table-prefix.");
            assertFalse(file("target.duckdb").exists(), "the target was written");
        }
    }

    @Nested
    @DisplayName("values that can't be converted")
    class Unconvertible {

        private void unreadableMeta(File source, long rowId) throws SQLException {
            try (Connection connection = connector(Engine.SQLITE, source).open();
                 PreparedStatement statement = connection.prepareStatement("UPDATE co_block SET meta = ? WHERE rowid = ?")) {
                statement.setBytes(1, new byte[]{FakeBridge.UNREADABLE[0], FakeBridge.UNREADABLE[1], 7, 7});
                statement.setLong(2, rowId);
                statement.executeUpdate();
            }
        }

        @Test
        @DisplayName("should copy them unchanged, compare them as they are, and name the first few")
        void keptAndReported() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 200);
            long first = TestDatabases.blockRowId(10, 200);
            long second = TestDatabases.blockRowId(20, 200);
            unreadableMeta(file("source.db"), first);
            unreadableMeta(file("source.db"), second);
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.DUCKDB, "target.duckdb");

            migrate(session, true);

            assertSucceeded(session);
            String text = console.text();
            assertTrue(text.contains("2 values couldn't be converted for DuckDB and were copied unchanged, so"
                + " CoreProtect reads them as it did on the source: block.meta of row ID " + first), text);
            assertTrue(text.contains("block.meta of row ID " + second), text);
            try (Connection connection = connector(Engine.DUCKDB, file("target.duckdb")).open();
                 PreparedStatement statement = connection.prepareStatement("SELECT meta FROM co_block WHERE rowid = ?")) {
                statement.setLong(1, first);
                try (ResultSet result = statement.executeQuery()) {
                    assertTrue(result.next());
                    assertArrayEquals(new byte[]{FakeBridge.UNREADABLE[0], FakeBridge.UNREADABLE[1], 7, 7},
                        result.getBytes(1));
                }
            }
        }

        @Test
        @DisplayName("should fail, naming what changed, rather than keep values when CoreProtect changed under its"
            + " conversions")
        void upstreamChanged() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 20);
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.DUCKDB, "target.duckdb");
            FakeBridge bridge = new FakeBridge(session);
            bridge.conversionFailure = new UpstreamChanged("CoreProtect's BlockStatement.transcodeMetadata(byte[], an"
                + " enum with SQLITE, MYSQL) can't be reached: java.lang.NoSuchMethodException");

            new Migration(bridge, session, new Console(console.sender()), Engine.DUCKDB, false, System::nanoTime,
                new Random(42)).run();

            assertFailed(session, "Migration failed. CoreProtect doesn't work the way this LibreProtect build expects:"
                + " CoreProtect's BlockStatement.transcodeMetadata(byte[], an enum with SQLITE, MYSQL) can't be"
                + " reached");
            assertFalse(console.text().contains("couldn't be converted"), console.text());
        }

        @Test
        @DisplayName("should compare values between engines of one encoding as they are, without decoding them")
        void sameEncodingComparedAsIs() throws Exception {
            TestDatabases.createLegacySqlite(file("original.db"), 100);
            migrate(session(Engine.SQLITE, "original.db", Engine.DUCKDB, "first.duckdb"), false);
            FakeSession session = session(Engine.DUCKDB, "first.duckdb", Engine.DUCKDB, "second.duckdb");
            FakeBridge bridge = new FakeBridge(session);

            new Migration(bridge, session, new Console(console.sender()), Engine.DUCKDB, true, System::nanoTime,
                new Random(1)).run();

            assertSucceeded(session);
            assertEquals(0, bridge.canonicalCalls.get());
        }

        @Test
        @DisplayName("should treat an empty uuid as NULL only where ClickHouse is involved, in any form")
        void clickHouseUuids() throws Exception {
            FakeBridge bridge = new FakeBridge(null);
            Transcoder clickHouse = Migration.canonical(bridge, Engine.CLICKHOUSE, Engine.MYSQL);
            Transcoder relational = Migration.canonical(bridge, Engine.SQLITE, Engine.MYSQL);

            assertNull(clickHouse.apply("user", "uuid", ""));
            assertNull(clickHouse.apply("username_log", "uuid", new byte[0]));
            assertEquals("x", clickHouse.apply("user", "uuid", "x"));
            assertEquals("", clickHouse.apply("user", "user", ""));
            assertEquals("", relational.apply("user", "uuid", ""));
        }
    }

    @Test
    @DisplayName("should stop before touching anything when the switch couldn't complete")
    void preflightFails() throws Exception {
        TestDatabases.createLegacySqlite(file("source.db"), 10);
        FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");
        session.preflightFailure = new MigrationException("config.yml is not a regular file.");

        migrate(session, false);

        assertFailed(session, "config.yml is not a regular file.");
        assertEquals(0, session.pauses.get());
        assertFalse(file("target.db").exists());
    }

    @Nested
    @DisplayName("targets that aren't empty")
    class NonEmptyTargets {

        @Test
        @DisplayName("should refuse a SQLite target with CoreProtect data, without pausing or touching it")
        void sqliteWithData() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 10);
            TestDatabases.createLegacySqlite(file("target.db"), 5);
            byte[] before = Files.readAllBytes(folder.resolve("target.db"));
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");

            migrate(session, false);

            assertFailed(session, "already holds CoreProtect data");
            assertTrue(console.text().contains("has rows in table co_"), console.text());
            assertEquals(0, session.pauses.get());
            assertArrayEquals(before, Files.readAllBytes(folder.resolve("target.db")));
        }

        @Test
        @DisplayName("should refuse a target that got CoreProtect data before the pause, without touching it")
        void dataBeforePause() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 10);
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");
            // Such as CoreProtect itself, switched to the target by a reload between the checks and the pause
            session.duringPause = () -> TestDatabases.createLegacySqlite(file("target.db"), 5);

            migrate(session, false);

            assertFailed(session, "already holds CoreProtect data");
            assertEquals(1, session.pauses.get());
            try (Connection connection = connector(Engine.SQLITE, file("target.db")).open();
                 Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("SELECT COUNT(*) FROM co_block")) {
                result.next();
                assertEquals(5, result.getLong(1));
            }
        }

        @Test
        @DisplayName("should accept a SQLite target whose tables are empty, even with a lock row")
        void sqliteEmptyTables() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 10);
            try (Connection connection = connector(Engine.SQLITE, file("target.db")).open();
                 Statement statement = connection.createStatement()) {
                for (String sql : TestDatabases.schemaStatements(Engine.SQLITE, TestDatabases.PREFIX)) {
                    statement.execute(sql);
                }
                statement.execute("INSERT INTO co_database_lock (rowid, status, time) VALUES (1, 0, 0)");
            }
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");

            migrate(session, false);

            assertSucceeded(session);
        }

        @Test
        @DisplayName("should refuse a missing SQLite target with a file left over next to it")
        void sqliteLeftover() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 10);
            Files.writeString(folder.resolve("target.db-wal"), "stale");
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");

            migrate(session, false);

            assertFailed(session, "target.db-wal is left over");
            assertFalse(file("target.db").exists());
        }

        @Test
        @DisplayName("should refuse a DuckDB target that already exists, even an empty one")
        void duckDBExists() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 10);
            Files.writeString(folder.resolve("target.duckdb"), "");
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.DUCKDB, "target.duckdb");

            migrate(session, false);

            assertFailed(session, "a DuckDB target must be a new file");
            assertEquals(0, Files.size(folder.resolve("target.duckdb")));
        }
    }

    @Nested
    @DisplayName("validation")
    class Validation {

        /** A sink that changes one value of one row as it writes it */
        private void corrupt(FakeSession session, String table, long rowId, int column) {
            session.sinkWrapper = sink -> new ForwardingSink(sink) {
                @Override
                public void write(String name, List<String> columns, List<Row> rows) throws SQLException {
                    if (name.equals(table)) {
                        for (Row row : rows) {
                            if (row.rowId() == rowId) {
                                Object value = row.values()[column];
                                row.values()[column] = value instanceof Long ? (Long) value + 1 : 12345L;
                            }
                        }
                    }
                    super.write(name, columns, rows);
                }
            };
        }

        @Test
        @DisplayName("should compare every row of a small table and find a changed value")
        void fullComparisonOfSmallTable() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 3_000);
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");
            long rowId = TestDatabases.blockRowId(2_345, 3_000);
            corrupt(session, "block", rowId, 3);

            migrate(session, false);

            assertFailed(session, "Row ID " + rowId + " of table block differs in column");
            assertTrue(console.text().contains("clean") || console.text().contains("delete"), console.text());
        }

        @Test
        @DisplayName("should compare a sample of a large table that covers the copied rows it chose")
        void sampleFindsChangeInSampledRange() throws Exception {
            int blocks = 150_000;
            TestDatabases.createLegacySqlite(file("source.db"), blocks);
            SamplePlan plan = SamplePlan.forRows(blocks, new Random(7));
            SamplePlan.Range range = firstRange(plan, blocks);
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");
            corrupt(session, "block", range.toRowId(), 3);

            migrate(session, false, new Random(7));

            assertFailed(session, "Row ID " + range.toRowId() + " of table block differs");
            assertTrue(console.text().contains("about 1% of the rows of larger tables"), console.text());
        }

        @Test
        @DisplayName("should miss a change outside the sample, which --full-validation finds")
        void fullValidationFindsWhatSampleMisses() throws Exception {
            int blocks = 150_000;
            TestDatabases.createLegacySqlite(file("source.db"), blocks);
            long outside = outsideSample(SamplePlan.forRows(blocks, new Random(7)), blocks);

            FakeSession sampled = session(Engine.SQLITE, "source.db", Engine.SQLITE, "sampled.db");
            corrupt(sampled, "block", outside, 3);
            sampled.activationFailure = new MigrationException("Stop before activation");
            migrate(sampled, false, new Random(7));
            assertTrue(console.text().contains("Validation passed"), console.text());

            FakeSession full = session(Engine.SQLITE, "source.db", Engine.SQLITE, "full.db");
            corrupt(full, "block", outside, 3);
            migrate(full, true, new Random(7));
            assertFailed(full, "Row ID " + outside + " of table block differs");
            assertTrue(console.text().contains("Validating every copied row"), console.text());
        }

        @Test
        @DisplayName("should find a row the target is missing")
        void missingRow() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 500);
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");
            long dropped = TestDatabases.blockRowId(100, 500);
            session.sinkWrapper = sink -> new ForwardingSink(sink) {
                @Override
                public void write(String table, List<String> columns, List<Row> rows) throws SQLException {
                    super.write(table, columns, table.equals("block")
                        ? rows.stream().filter(row -> row.rowId() != dropped).toList() : rows);
                }
            };

            migrate(session, false);

            assertFailed(session, "Table block differs: the source has 500 rows");
        }

        @Test
        @DisplayName("should refuse a target whose allocator would reuse the source's row IDs")
        void highWater() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 50);
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.DUCKDB, "target.duckdb");
            session.sinkWrapper = sink -> new ForwardingSink(sink) {
                @Override
                public RowSource readBack() throws SQLException {
                    return new ForwardingSource(super.readBack()) {
                        @Override
                        public OptionalLong highWater(String table) throws SQLException {
                            OptionalLong real = super.highWater(table);
                            return table.equals("user") ? OptionalLong.of(real.getAsLong() - 1) : real;
                        }
                    };
                }
            };

            migrate(session, false);

            assertFailed(session, "Table user of the target would hand out row IDs from");
        }

        @Test
        @DisplayName("should notice a source that changed during the migration")
        void sourceChanged() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 50);
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");
            session.sinkWrapper = sink -> new ForwardingSink(sink) {
                @Override
                public void finish(Map<String, Long> highWater) throws SQLException {
                    super.finish(highWater);
                    try (Connection connection = connector(Engine.SQLITE, file("source.db")).open();
                         Statement statement = connection.createStatement()) {
                        statement.execute("INSERT INTO co_world (id, world) VALUES (4, 'late')");
                    }
                }
            };

            migrate(session, false);

            assertFailed(session, "Table world of the source changed during the migration");
        }
    }

    private static SamplePlan.Range firstRange(SamplePlan plan, int blocks) {
        List<Row> rows = new java.util.ArrayList<>();
        for (int i = 0; i < blocks; i++) {
            rows.add(new Row(TestDatabases.blockRowId(i, blocks), new Object[0]));
        }
        plan.observe(rows);
        return plan.ranges().get(0);
    }

    private static long outsideSample(SamplePlan plan, int blocks) {
        List<Row> rows = new java.util.ArrayList<>();
        for (int i = 0; i < blocks; i++) {
            rows.add(new Row(TestDatabases.blockRowId(i, blocks), new Object[0]));
        }
        plan.observe(rows);
        for (int i = 0; i < blocks; i++) {
            long rowId = TestDatabases.blockRowId(i, blocks);
            if (plan.ranges().stream().noneMatch(range -> range.fromRowId() <= rowId && rowId <= range.toRowId())) {
                return rowId;
            }
        }
        throw new AssertionError("every row is sampled");
    }

    @Nested
    @DisplayName("interruptions")
    class Interruptions {

        @Test
        @DisplayName("should stop between batches when the server stops, without activating")
        void stopsOnShutdown() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 20_000);
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");
            AtomicInteger batches = new AtomicInteger();
            session.sinkWrapper = sink -> new ForwardingSink(sink) {
                @Override
                public void write(String table, List<String> columns, List<Row> rows) throws SQLException {
                    super.write(table, columns, rows);
                    if (table.equals("block") && batches.incrementAndGet() == 2) {
                        session.stopReason = "the server is stopping";
                    }
                }
            };

            migrate(session, false);

            assertFailed(session, "The migration stopped because the server is stopping.");
            assertEquals(2, batches.get(), "kept copying after the stop");
            assertTrue(console.text().contains("CoreProtect keeps using the SQLite database"), console.text());
        }

        @Test
        @DisplayName("should retry a write whose commit went through but whose connection broke, without duplicates")
        void retriesLostCommit() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 3_000);
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");
            AtomicBoolean failed = new AtomicBoolean();
            session.targetConnector = connector -> () -> commitThenFailOnce(connector.open(), failed);

            migrate(session, false);

            assertSucceeded(session);
            assertTrue(failed.get());
            assertTrue(console.text().contains("Retrying after an error writing"), console.text());
            assertEquals(dump(Engine.SQLITE, file("source.db")), dump(Engine.SQLITE, file("target.db")));
        }

        @Test
        @DisplayName("should report a failed activation and leave cleaning advice")
        void activationFails() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 20);
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");
            session.activationFailure = new MigrationException("CoreProtect couldn't switch", null,
                List.of("CoreProtect switched back to the source."));

            migrate(session, false);

            String text = console.text();
            assertTrue(text.contains("Migration failed. CoreProtect couldn't switch"), text);
            assertTrue(text.contains("CoreProtect switched back to the source."), text);
            assertTrue(text.contains("move away or delete"), text);
            assertEquals(1, session.closes.get());
        }

        @Test
        @DisplayName("should pass on what the bridge advises after a failure, such as fixing config.yml")
        void failureNotes() throws Exception {
            TestDatabases.createLegacySqlite(file("source.db"), 20);
            TestDatabases.createLegacySqlite(file("target.db"), 1);
            FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");
            session.failureNotes = List.of("config.yml selects MySQL (use-mysql: true), but CoreProtect uses SQLite.");

            migrate(session, false);

            assertTrue(console.plainMessages().get(console.plainMessages().size() - 1)
                .startsWith("config.yml selects MySQL"), console.text());
        }
    }

    /**
     * A connection whose first commit of a batch goes through and then
     * reports a lost connection, like a network failure after the server
     * committed. Commits before the block table exists, such as the lock
     * table's, go through.
     */
    private static Connection commitThenFailOnce(Connection real, AtomicBoolean failed) {
        return (Connection) Proxy.newProxyInstance(MigrationTest.class.getClassLoader(), new Class<?>[]{Connection.class},
            (proxy, method, args) -> {
                if (method.getName().equals("commit") && !failed.get()) {
                    boolean blocks;
                    try (Statement statement = real.createStatement();
                         ResultSet result = statement.executeQuery("SELECT COUNT(*) FROM sqlite_master"
                             + " WHERE type = 'table' AND name = 'co_block'")) {
                        blocks = result.next() && result.getLong(1) > 0;
                    }
                    if (blocks) {
                        try (Statement statement = real.createStatement();
                             ResultSet result = statement.executeQuery("SELECT COUNT(*) FROM co_block")) {
                            result.next();
                            if (result.getLong(1) > 0) {
                                failed.set(true);
                                real.commit();
                                throw new SQLRecoverableException("Communications link failure", "08S01");
                            }
                        }
                    }
                }
                try {
                    return method.invoke(real, args);
                } catch (java.lang.reflect.InvocationTargetException e) {
                    throw e.getCause();
                }
            });
    }

    @Test
    @DisplayName("should retry a transient read error")
    void retriesTransientRead() throws Exception {
        TestDatabases.createLegacySqlite(file("source.db"), 100);
        FakeSession session = session(Engine.SQLITE, "source.db", Engine.SQLITE, "target.db");
        AtomicBoolean failed = new AtomicBoolean();
        session.sourceWrapper = source -> new ForwardingSource(source) {
            @Override
            public List<Row> read(String table, List<String> columns, long afterRowId, int limit) throws SQLException {
                if (table.equals("block") && !failed.getAndSet(true)) {
                    throw new SQLTransientConnectionException("[SQLITE_BUSY] The database file is locked");
                }
                return super.read(table, columns, afterRowId, limit);
            }
        };

        migrate(session, false);

        assertSucceeded(session);
        assertTrue(failed.get());
    }
}
