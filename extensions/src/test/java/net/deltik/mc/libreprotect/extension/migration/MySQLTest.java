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
import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.FakeBridge.FakeSession;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Connector;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Dialect;
import net.deltik.mc.libreprotect.testutil.FreezingProxy;
import net.deltik.mc.libreprotect.testutil.RecordingSender;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.bukkit.command.ConsoleCommandSender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Migrations to and from MySQL, against the MySQL container of
 * {@code scripts/lp db up}, which {@code scripts/lp build} passes as
 * {@code -Dlpit.containers}. Skipped without it.
 */
class MySQLTest {

    @TempDir
    Path folder;

    private DatabaseSettings mysql;
    private RecordingSender console;

    @BeforeEach
    void setUp() throws IOException, SQLException {
        String env = System.getProperty("lpit.containers");
        Assumptions.assumeTrue(env != null && Files.isRegularFile(Path.of(env)),
            "No database containers; start them with scripts/lp db up");
        Properties containers = new Properties();
        try (Reader in = Files.newBufferedReader(Path.of(env), StandardCharsets.UTF_8)) {
            containers.load(in);
        }
        String prefix = "unit" + ProcessHandle.current().pid() % 100_000 + "_";
        mysql = DatabaseSettings.server(Engine.MYSQL, containers.getProperty("MYSQL_HOST"),
            Integer.parseInt(containers.getProperty("MYSQL_PORT")), containers.getProperty("MYSQL_DATABASE"),
            containers.getProperty("MYSQL_USERNAME"), containers.getProperty("MYSQL_PASSWORD"), false, prefix);
        dropTables();
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(new TestLogger());
        console = new RecordingSender(ConsoleCommandSender.class);
    }

    @AfterEach
    void tearDown() throws SQLException {
        if (mysql != null) {
            dropTables();
        }
        LibreProtectLogger.reset();
    }

    private Connector connector() {
        return FakeSession.connector(mysql);
    }

    private void dropTables() throws SQLException {
        try (Connection connection = connector().open(); Statement statement = connection.createStatement()) {
            for (String table : TestDatabases.TABLES) {
                statement.execute("DROP TABLE IF EXISTS `" + mysql.prefix() + table + "`");
            }
        }
    }

    private File file(String name) {
        return folder.resolve(name).toFile();
    }

    private FakeSession toMySQL(File source) {
        return new FakeSession(DatabaseSettings.embedded(Engine.SQLITE, source), mysql);
    }

    private void migrate(FakeSession session) {
        new Migration(new FakeBridge(session), session, new Console(console.sender()), session.target.engine(), false,
            System::nanoTime, new Random(1)).run();
    }

    private long scalar(String sql) throws SQLException {
        try (Connection connection = connector().open(); Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(sql)) {
            result.next();
            return result.getLong(1);
        }
    }

    private void execute(Connector connector, String sql) throws SQLException {
        try (Connection connection = connector.open(); Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    @Test
    @DisplayName("should copy SQLite to MySQL and back, with every row ID, a row ID of 0, and the high-water marks")
    void roundTrip() throws Exception {
        TestDatabases.createLegacySqlite(file("original.db"), 3_000);
        Connector original = FakeSession.connector(DatabaseSettings.embedded(Engine.SQLITE, file("original.db")));
        // MySQL would give a row ID of 0 a new ID without NO_AUTO_VALUE_ON_ZERO
        execute(original, "INSERT INTO co_art_map (rowid, id, art) VALUES (0, 0, 'Kebab')");
        FakeSession there = toMySQL(file("original.db"));

        migrate(there);

        assertTrue(console.text().contains("Migration complete."), console.text());
        Map<String, List<String>> expected = TestDatabases.dump(Dialect.SQLITE, original, Transcoder.NONE);
        assertEquals(expected, TestDatabases.dump(Dialect.MYSQL, connector(), mysql.prefix(), Transcoder.NONE));
        assertEquals(1, scalar("SELECT COUNT(*) FROM " + mysql.prefix() + "art_map WHERE rowid = 0"));
        assertEquals(0, scalar("SELECT status FROM " + mysql.prefix() + "database_lock WHERE rowid = 1"));
        // The next row IDs continue after the source's
        execute(connector(), "INSERT INTO " + mysql.prefix() + "block (time) VALUES (1)");
        assertEquals(TestDatabases.LARGE_BLOCK_ROWID + 1, scalar("SELECT MAX(rowid) FROM " + mysql.prefix() + "block"));
        execute(connector(), "INSERT INTO " + mysql.prefix() + "user (time) VALUES (1)");
        assertEquals(10, scalar("SELECT MAX(rowid) FROM " + mysql.prefix() + "user"));

        FakeSession back = new FakeSession(mysql, DatabaseSettings.embedded(Engine.SQLITE, file("back.db")));
        migrate(back);

        assertEquals(2, console.text().split("Migration complete\\.").length - 1, console.text());
        Map<String, List<String>> returned = TestDatabases.dump(Dialect.SQLITE,
            FakeSession.connector(DatabaseSettings.embedded(Engine.SQLITE, file("back.db"))), Transcoder.NONE);
        for (String table : List.of("sign", "skull", "entity_spawn", "entity", "world")) {
            assertEquals(expected.get(table), returned.get(table), table);
        }
        assertEquals(expected.get("block").size() + 1, returned.get("block").size());
    }

    @Test
    @DisplayName("should keep MySQL's FLOAT values exact both ways, which its text protocol rounds to six digits")
    void floats() throws Exception {
        TestDatabases.createLegacySqlite(file("original.db"), 10);
        FakeSession there = toMySQL(file("original.db"));

        migrate(there);

        assertEquals(1, there.activations.get(), console.text());
        // Read back through a plain text protocol connection, which rounds
        try (Connection text = java.sql.DriverManager.getConnection("jdbc:mysql://" + mysql.host() + ":" + mysql.port()
            + "/" + mysql.database() + "?useSSL=false&allowPublicKeyRetrieval=true", mysql.username(), mysql.password());
             Statement statement = text.createStatement();
             ResultSet result = statement.executeQuery("SELECT yaw FROM " + mysql.prefix() + "entity_spawn WHERE rowid = 2")) {
            assertTrue(result.next());
            assertNotEquals((double) 123.45678f, result.getDouble(1), "the text protocol no longer rounds FLOATs");
        }
        FakeSession back = new FakeSession(mysql, DatabaseSettings.embedded(Engine.SQLITE, file("back.db")));

        migrate(back);

        assertEquals(1, back.activations.get(), console.text());
        try (Connection connection = FakeSession.connector(DatabaseSettings.embedded(Engine.SQLITE, file("back.db")))
            .open(); Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("SELECT yaw, pitch, x FROM co_entity_spawn WHERE rowid = 2")) {
            assertTrue(result.next());
            assertEquals((double) 123.45678f, result.getDouble(1));
            assertEquals((double) -12.345678f, result.getDouble(2));
            assertEquals(1234.5678901234567 * 4, result.getDouble(3));
        }
    }

    @Test
    @DisplayName("should stop within seconds when the target stops answering in the middle of the copy")
    void stopsWhileTargetHangs() throws Exception {
        TestDatabases.createLegacySqlite(file("original.db"), 20_000);
        try (FreezingProxy proxy = new FreezingProxy(mysql.host(), mysql.port())) {
            FakeSession session = new FakeSession(DatabaseSettings.embedded(Engine.SQLITE, file("original.db")),
                DatabaseSettings.server(Engine.MYSQL, "127.0.0.1", proxy.port(), mysql.database(), mysql.username(),
                    mysql.password(), false, mysql.prefix()));
            AtomicInteger batches = new AtomicInteger();
            AtomicLong stopped = new AtomicLong();
            session.sinkWrapper = sink -> new ForwardingSink(sink) {
                @Override
                public void write(String table, List<String> columns, List<Row> rows) throws SQLException {
                    if (table.equals("block") && batches.incrementAndGet() == 2) {
                        proxy.freeze();
                        Thread stopper = new Thread(() -> {
                            try {
                                Thread.sleep(1_000);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                            }
                            stopped.set(System.nanoTime());
                            session.stopReason = "the server is stopping";
                        });
                        stopper.start();
                    }
                    super.write(table, columns, rows);
                }
            };
            Thread worker = new Thread(() -> migrate(session), "LibreProtect migration");

            worker.start();
            worker.join(60_000);

            assertFalse(worker.isAlive());
            long waited = (System.nanoTime() - stopped.get()) / 1_000_000;
            assertTrue(stopped.get() != 0 && waited < 5_000, "stopped " + waited + " ms after the stop request: "
                + console.text());
            assertTrue(console.text().contains("The migration stopped because the server is stopping."), console.text());
            assertEquals(0, session.activations.get());
        }
    }

    @Test
    @DisplayName("should not repeat a statement that ran out of the connection's network timeout")
    void networkTimeoutIsFinal() throws Exception {
        try (Connection connection = connector().open(); Statement statement = connection.createStatement()) {
            // The migration's own timeout, shortened
            connection.setNetworkTimeout(Runnable::run, 500);

            SQLException timedOut = assertThrows(SQLException.class, () -> statement.executeQuery("SELECT SLEEP(5)"));

            assertEquals("08S01", timedOut.getSQLState(), "a connection failure, which is otherwise repeated");
            assertFalse(TransientErrors.isTransient(timedOut), "repeated, the statement would wait as long again");
        }
    }

    @Test
    @DisplayName("should copy batches with more values than a MySQL statement takes placeholders (65,535)")
    void largeBatches() throws Exception {
        TestDatabases.createLegacySqlite(file("original.db"), 200_000);
        FakeSession session = toMySQL(file("original.db"));
        AtomicInteger largest = new AtomicInteger();
        session.sinkWrapper = sink -> new ForwardingSink(sink) {
            @Override
            public void write(String table, List<String> columns, List<Row> rows) throws SQLException {
                if (table.equals("block")) {
                    largest.accumulateAndGet(rows.size() * columns.size(), Math::max);
                }
                super.write(table, columns, rows);
            }
        };

        migrate(session);

        assertTrue(console.text().contains("Migration complete."), console.text());
        assertTrue(largest.get() > 65_535, "the largest batch had only " + largest.get() + " values");
        assertEquals(200_000, scalar("SELECT COUNT(*) FROM " + mysql.prefix() + "block"));
    }

    @Test
    @DisplayName("should keep MySQL's allocator high-water mark ahead of the largest row ID")
    void highWaterAheadOfRows() throws Exception {
        TestDatabases.createLegacySqlite(file("original.db"), 10);
        migrate(toMySQL(file("original.db")));
        execute(connector(), "INSERT INTO " + mysql.prefix() + "world (id, world) VALUES (4, 'gone')");
        execute(connector(), "DELETE FROM " + mysql.prefix() + "world WHERE world = 'gone'");
        long highWater = scalar("SELECT MAX(rowid) FROM " + mysql.prefix() + "world") + 1;
        FakeSession out = new FakeSession(mysql, DatabaseSettings.embedded(Engine.DUCKDB, file("out.duckdb")));

        migrate(out);

        assertTrue(console.text().contains("Migration complete."), console.text());
        Connector duckdb = FakeSession.connector(DatabaseSettings.embedded(Engine.DUCKDB, file("out.duckdb")));
        try (Connection connection = duckdb.open(); Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("SELECT nextval('co_world_rowid_seq')")) {
            result.next();
            assertEquals(highWater + 1, result.getLong(1));
        }
    }

    @Test
    @DisplayName("should fail on a value that doesn't fit MySQL's column, naming its row, instead of cutting it")
    void valueTooLong() throws Exception {
        TestDatabases.createLegacySqlite(file("original.db"), 10);
        Connector original = FakeSession.connector(DatabaseSettings.embedded(Engine.SQLITE, file("original.db")));
        execute(original, "UPDATE co_sign SET line_2 = '" + "x".repeat(101) + "' WHERE rowid = 16");

        migrate(toMySQL(file("original.db")));

        String text = console.text();
        assertTrue(text.contains("Migration failed. A database error occurred: Row ID 16 of table sign can't be"
            + " written to the target: "), text);
        assertTrue(text.contains("Data too long for column 'line_2'"), text);
        assertEquals(0, scalar("SELECT COUNT(*) FROM " + mysql.prefix() + "sign"), "a partial batch was committed");
        assertTrue(text.contains("drop the tables whose names start with '" + mysql.prefix() + "'"), text);
        assertTrue(text.contains("or choose a different table-prefix in CoreProtect's config.yml."), text);
    }

    @Test
    @DisplayName("should refuse a MySQL target that has CoreProtect data under its prefix")
    void occupied() throws Exception {
        TestDatabases.createLegacySqlite(file("original.db"), 10);
        migrate(toMySQL(file("original.db")));
        console = new RecordingSender(ConsoleCommandSender.class);
        FakeSession again = toMySQL(file("original.db"));

        migrate(again);

        assertTrue(console.text().contains("The target already holds CoreProtect data: table " + mysql.prefix()),
            console.text());
        assertEquals(0, again.pauses.get());
    }
}
