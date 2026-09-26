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

/*
 * Portions of this file are copied or adapted from CoreProtect
 * <https://github.com/PlayPro/CoreProtect>:
 *
 * Copyright (c) Intelli and the CoreProtect contributors
 *
 * CoreProtect is licensed under the Artistic License 2.0 (see
 * LICENSES/Artistic-2.0.txt). As section 4(c)(ii) of that license
 * permits, LibreProtect distributes these portions under the
 * GNU General Public License, version 3 or later. See NOTICE.
 */

package net.deltik.mc.libreprotect.extension.migration;

import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Connector;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Connectors;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Dialect;
import net.deltik.mc.libreprotect.extension.migration.jdbc.JdbcRowSource;
import net.deltik.mc.libreprotect.extension.migration.jdbc.SchemaCreator;

import java.io.File;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;

/**
 * CoreProtect-shaped test databases: a subset of CoreProtect's tables with
 * the schemas upstream creates for each engine, and seeded data with row ID
 * gaps, legacy column order, binary values, NULLs and Unicode.
 */
final class TestDatabases {

    static final String PREFIX = "co_";

    /** The tables of these test databases, in CoreProtect's order */
    static final List<String> TABLES = List.of("art_map", "block", "database_lock", "entity", "entity_spawn",
        "material_map", "sign", "skull", "user", "version", "world");

    /** Tables that have a row ID sequence in DuckDB */
    private static final List<String> SEQUENCED = TABLES.stream().filter(table -> !table.equals("database_lock")).toList();

    /** A large row ID that needs 64 bits */
    static final long LARGE_BLOCK_ROWID = 5_000_000_000L;

    private TestDatabases() {
    }

    /**
     * @return upstream's schema for the engine, created the way upstream's
     *         {@code Database.createDatabaseTables} does, including its habit
     *         of closing the connection it's given on SQLite and MySQL
     */
    static SchemaCreator schema(Engine engine) {
        return (connection, prefix) -> {
            try (Statement statement = connection.createStatement()) {
                for (String sql : schemaStatements(engine, prefix)) {
                    statement.execute(sql);
                }
                if (engine == Engine.DUCKDB) {
                    statement.execute("INSERT INTO " + prefix + "database_lock (rowid, status, time) SELECT 1, 0, 0"
                        + " WHERE NOT EXISTS (SELECT 1 FROM " + prefix + "database_lock WHERE rowid = 1)");
                }
            } finally {
                if (engine != Engine.DUCKDB) {
                    connection.close();
                }
            }
        };
    }

    static List<String> schemaStatements(Engine engine, String p) {
        List<String> sql = new ArrayList<>();
        switch (engine) {
            case SQLITE:
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "art_map (id INTEGER, art TEXT)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "block (time INTEGER, user INTEGER, wid INTEGER, x INTEGER,"
                    + " y INTEGER, z INTEGER, type INTEGER, data INTEGER, meta BLOB, blockdata BLOB, action INTEGER,"
                    + " rolled_back INTEGER)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "database_lock (status INTEGER, time INTEGER)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "entity (id INTEGER PRIMARY KEY ASC, time INTEGER, data BLOB)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "material_map (id INTEGER, material TEXT)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "sign (time INTEGER, user INTEGER, wid INTEGER, x INTEGER,"
                    + " y INTEGER, z INTEGER, action INTEGER, color INTEGER, color_secondary INTEGER, data INTEGER,"
                    + " waxed INTEGER, face INTEGER, line_1 TEXT, line_2 TEXT, line_3 TEXT, line_4 TEXT, line_5 TEXT,"
                    + " line_6 TEXT, line_7 TEXT, line_8 TEXT)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "user (id INTEGER PRIMARY KEY ASC, time INTEGER, user TEXT,"
                    + " uuid TEXT)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "version (time INTEGER, version TEXT)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "world (id INTEGER, world TEXT)");
                sql.add(SQLITE_ENTITY_SPAWN.replace("%p", p));
                sql.add(SQLITE_SKULL.replace("%p", p));
                sql.add("CREATE INDEX IF NOT EXISTS block_index ON " + p + "block(wid,x,z,time)");
                sql.add("CREATE INDEX IF NOT EXISTS uuid_index ON " + p + "user(uuid)");
                break;
            case MYSQL:
                String table = " ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4";
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "art_map(rowid int NOT NULL AUTO_INCREMENT,PRIMARY KEY(rowid),"
                    + "id int,art varchar(255), INDEX(id))" + table);
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "block(rowid bigint NOT NULL AUTO_INCREMENT,PRIMARY KEY(rowid),"
                    + " time int, user int, wid int, x int, y int, z int, type int, data int, meta mediumblob,"
                    + " blockdata blob, action tinyint, rolled_back tinyint, INDEX(wid,x,z,time))" + table);
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "database_lock(rowid int NOT NULL AUTO_INCREMENT,"
                    + "PRIMARY KEY(rowid),status tinyint,time int)" + table);
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "entity(rowid int NOT NULL AUTO_INCREMENT,PRIMARY KEY(rowid),"
                    + " time int, data mediumblob)" + table);
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "material_map(rowid int NOT NULL AUTO_INCREMENT,"
                    + "PRIMARY KEY(rowid),id int,material varchar(255), INDEX(id))" + table);
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "sign(rowid int NOT NULL AUTO_INCREMENT,PRIMARY KEY(rowid),"
                    + "time int, user int, wid int, x int, y int, z int, action tinyint, color int, color_secondary int,"
                    + " data tinyint, waxed tinyint, face tinyint, line_1 varchar(100), line_2 varchar(100),"
                    + " line_3 varchar(100), line_4 varchar(100), line_5 varchar(100), line_6 varchar(100),"
                    + " line_7 varchar(100), line_8 varchar(100))" + table);
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "user(rowid int NOT NULL AUTO_INCREMENT,PRIMARY KEY(rowid),"
                    + "time int,user varchar(100),uuid varchar(64), INDEX(user), INDEX(uuid))" + table);
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "version(rowid int NOT NULL AUTO_INCREMENT,PRIMARY KEY(rowid),"
                    + "time int,version varchar(16))" + table);
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "entity_spawn(rowid int NOT NULL AUTO_INCREMENT,"
                    + "PRIMARY KEY(rowid),time int,block_rowid bigint,kill_rowid int,uuid varchar(36),wid int,"
                    + "current_wid int,origin_x double,origin_y double,origin_z double,x double,y double,z double,"
                    + "yaw float,pitch float,data mediumblob NULL,removed tinyint, UNIQUE INDEX(uuid),"
                    + " UNIQUE INDEX entity_spawn_kill_rowid_index(kill_rowid))" + table);
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "skull(rowid int NOT NULL AUTO_INCREMENT,PRIMARY KEY(rowid),"
                    + " time int, owner varchar(255), skin text)" + table);
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "world(rowid int NOT NULL AUTO_INCREMENT,PRIMARY KEY(rowid),"
                    + "id int,world varchar(255), INDEX(id))" + table);
                break;
            case DUCKDB:
                for (String sequenced : SEQUENCED) {
                    sql.add("CREATE SEQUENCE IF NOT EXISTS " + p + sequenced + "_rowid_seq START 1");
                }
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "art_map (" + rowId(p, "art_map") + ", id INTEGER, art VARCHAR)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "block (" + rowId(p, "block") + ", time INTEGER,"
                    + " \"user\" INTEGER, wid INTEGER, x INTEGER, y INTEGER, z INTEGER, type INTEGER, data INTEGER,"
                    + " meta BLOB, blockdata BLOB, action TINYINT, rolled_back TINYINT)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "database_lock (rowid INTEGER PRIMARY KEY, status TINYINT,"
                    + " time INTEGER)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "entity (" + rowId(p, "entity") + ", time INTEGER, data BLOB)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "material_map (" + rowId(p, "material_map") + ", id INTEGER,"
                    + " material VARCHAR)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "sign (" + rowId(p, "sign") + ", time INTEGER,"
                    + " \"user\" INTEGER, wid INTEGER, x INTEGER, y INTEGER, z INTEGER, action TINYINT, color INTEGER,"
                    + " color_secondary INTEGER, data TINYINT, waxed TINYINT, face TINYINT, line_1 VARCHAR,"
                    + " line_2 VARCHAR, line_3 VARCHAR, line_4 VARCHAR, line_5 VARCHAR, line_6 VARCHAR,"
                    + " line_7 VARCHAR, line_8 VARCHAR)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "user (" + rowId(p, "user") + ", time INTEGER,"
                    + " \"user\" VARCHAR, uuid VARCHAR)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "version (" + rowId(p, "version") + ", time INTEGER,"
                    + " version VARCHAR)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "world (" + rowId(p, "world") + ", id INTEGER, world VARCHAR)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "entity_spawn (" + rowId(p, "entity_spawn") + ", time INTEGER,"
                    + " block_rowid BIGINT, kill_rowid INTEGER, uuid VARCHAR UNIQUE, wid INTEGER, current_wid INTEGER,"
                    + " origin_x DOUBLE, origin_y DOUBLE, origin_z DOUBLE, x DOUBLE, y DOUBLE, z DOUBLE, yaw FLOAT,"
                    + " pitch FLOAT, data BLOB, removed TINYINT, UNIQUE(kill_rowid))");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "skull (" + rowId(p, "skull") + ", time INTEGER, owner VARCHAR,"
                    + " skin VARCHAR)");
                sql.add("CREATE TABLE IF NOT EXISTS " + p + "duckdb_spatial_index (table_id TINYINT NOT NULL,"
                    + " start_rowid BIGINT NOT NULL, end_rowid BIGINT NOT NULL, row_count INTEGER NOT NULL,"
                    + " chunks BLOB NOT NULL, entities BLOB, PRIMARY KEY(table_id,start_rowid))");
                break;
            default:
                throw new IllegalArgumentException(engine.toString());
        }
        return sql;
    }

    private static String rowId(String prefix, String table) {
        return "rowid " + (table.equals("block") ? "BIGINT" : "INTEGER") + " NOT NULL DEFAULT nextval('" + prefix
            + table + "_rowid_seq')";
    }

    /**
     * The tables as a database created by an older CoreProtect has them,
     * with columns in the order they were added.
     */
    private static List<String> legacySqliteSchema(String p) {
        return List.of(
            "CREATE TABLE " + p + "art_map (id INTEGER, art TEXT)",
            "CREATE TABLE " + p + "block (time INTEGER, user INTEGER, wid INTEGER, x INTEGER, y INTEGER, z INTEGER,"
                + " type INTEGER, data INTEGER, meta BLOB, action INTEGER, rolled_back INTEGER, blockdata BLOB)",
            "CREATE TABLE " + p + "database_lock (status INTEGER, time INTEGER)",
            "CREATE TABLE " + p + "entity (id INTEGER PRIMARY KEY ASC, time INTEGER, data BLOB)",
            "CREATE TABLE " + p + "material_map (id INTEGER, material TEXT)",
            "CREATE TABLE " + p + "sign (time INTEGER, user INTEGER, wid INTEGER, x INTEGER, y INTEGER, z INTEGER,"
                + " action INTEGER, color INTEGER, data INTEGER, line_1 TEXT, line_2 TEXT, line_3 TEXT, line_4 TEXT,"
                + " color_secondary INTEGER, waxed INTEGER, face INTEGER, line_5 TEXT, line_6 TEXT, line_7 TEXT,"
                + " line_8 TEXT)",
            "CREATE TABLE " + p + "user (id INTEGER PRIMARY KEY ASC, user TEXT, uuid TEXT, time INTEGER)",
            "CREATE TABLE " + p + "version (time INTEGER, version TEXT)",
            "CREATE TABLE " + p + "world (id INTEGER, world TEXT)",
            SQLITE_ENTITY_SPAWN.replace("%p", p),
            SQLITE_SKULL.replace("%p", p));
    }

    /** Upstream's SQLite entity_spawn (CoreProtect 25), whose yaw and pitch are floats in MySQL and DuckDB */
    private static final String SQLITE_ENTITY_SPAWN = "CREATE TABLE IF NOT EXISTS %pentity_spawn (id INTEGER PRIMARY KEY"
        + " ASC, time INTEGER, block_rowid INTEGER, kill_rowid INTEGER, uuid TEXT UNIQUE, wid INTEGER, current_wid INTEGER,"
        + " origin_x REAL, origin_y REAL, origin_z REAL, x REAL, y REAL, z REAL, yaw REAL, pitch REAL, data BLOB,"
        + " removed INTEGER)";
    private static final String SQLITE_SKULL = "CREATE TABLE IF NOT EXISTS %pskull (id INTEGER PRIMARY KEY ASC,"
        + " time INTEGER, owner TEXT, skin TEXT)";

    /**
     * Create a SQLite database like one that an older CoreProtect created
     * and a newer one kept using, with {@code blocks} block rows.
     */
    static void createLegacySqlite(File file, int blocks) throws SQLException {
        try (Connection connection = Connectors.sqlite(file).open()) {
            try (Statement statement = connection.createStatement()) {
                for (String sql : legacySqliteSchema(PREFIX)) {
                    statement.execute(sql);
                }
            }
            seed(connection, Engine.SQLITE, PREFIX, blocks);
        }
    }

    /**
     * Fill the test tables through a connection with the given schema.
     */
    static void seed(Connection connection, Engine engine, String p, int blocks) throws SQLException {
        Random random = new Random(1);
        String user = engine == Engine.DUCKDB ? "\"user\"" : "user";
        connection.setAutoCommit(false);
        try (PreparedStatement statement = connection.prepareStatement("INSERT INTO " + p + "database_lock"
            + " (rowid, status, time) VALUES (1, 1, 1700000000)")) {
            statement.executeUpdate();
        }
        String[] worlds = {"world", "world_nether", "wörld_ünïcode"};
        try (PreparedStatement statement = connection.prepareStatement("INSERT INTO " + p + "world (rowid, id, world)"
            + " VALUES (?, ?, ?)")) {
            for (int i = 0; i < worlds.length; i++) {
                statement.setLong(1, i + 1);
                statement.setInt(2, i + 1);
                statement.setString(3, worlds[i]);
                statement.addBatch();
            }
            statement.executeBatch();
        }
        Object[][] users = {
            {1L, 1600000000, "Steve", "8667ba71-b85a-4004-af54-457a9734eed7"},
            {2L, 1600000001, "Ælfred", null},
            {5L, 1600000002, "名前🙂", "0f2c1bd4-0000-4000-8000-000000000005"},
            {9L, 1600000003, "#tnt", null}};
        try (PreparedStatement statement = connection.prepareStatement("INSERT INTO " + p + "user (rowid, time, "
            + user + ", uuid) VALUES (?, ?, ?, ?)")) {
            for (Object[] row : users) {
                statement.setLong(1, (Long) row[0]);
                statement.setInt(2, (Integer) row[1]);
                statement.setString(3, (String) row[2]);
                statement.setString(4, (String) row[3]);
                statement.addBatch();
            }
            statement.executeBatch();
        }
        try (PreparedStatement statement = connection.prepareStatement("INSERT INTO " + p + "material_map"
            + " (rowid, id, material) VALUES (?, ?, ?)")) {
            for (int i = 1; i <= 50; i++) {
                statement.setLong(1, i);
                statement.setInt(2, i);
                statement.setString(3, "minecraft:stone_" + i);
                statement.addBatch();
            }
            statement.executeBatch();
        }
        try (PreparedStatement statement = connection.prepareStatement("INSERT INTO " + p + "entity (rowid, time, data)"
            + " VALUES (?, ?, ?)")) {
            long[] rowIds = {3, 7, 8};
            int[] sizes = {100, 70_000, 0};
            for (int i = 0; i < rowIds.length; i++) {
                byte[] data = new byte[sizes[i]];
                random.nextBytes(data);
                statement.setLong(1, rowIds[i]);
                statement.setInt(2, 1600000100 + i);
                statement.setBytes(3, data);
                statement.addBatch();
            }
            statement.executeBatch();
        }
        try (PreparedStatement statement = connection.prepareStatement("INSERT INTO " + p + "sign (rowid, time, "
            + user + ", wid, x, y, z, action, color, color_secondary, data, waxed, face, line_1, line_2, line_3,"
            + " line_4, line_5, line_6, line_7, line_8) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
            + " ?, ?, ?, ?)")) {
            String[] lines = {"Hello", "", null, "Ünïcødé 🙂", "日本語", "'quoted' \"double\"", "tab\there", "x"};
            for (int i = 0; i < 20; i++) {
                statement.setLong(1, 10L + i * 3);
                statement.setInt(2, 1600000200 + i);
                statement.setInt(3, 1 + i % 2);
                statement.setInt(4, 1);
                statement.setInt(5, -i * 100);
                statement.setInt(6, i % 256 - 64);
                statement.setInt(7, i * 7);
                statement.setInt(8, i % 2);
                statement.setInt(9, -16777216 + i);
                statement.setInt(10, i);
                statement.setInt(11, i % 4);
                statement.setInt(12, i % 2);
                statement.setInt(13, i % 2);
                for (int line = 0; line < 8; line++) {
                    String text = lines[(i + line) % lines.length];
                    statement.setString(14 + line, text);
                }
                statement.addBatch();
            }
            statement.executeBatch();
        }
        try (PreparedStatement statement = connection.prepareStatement("INSERT INTO " + p + "entity_spawn (rowid, time,"
            + " block_rowid, kill_rowid, uuid, wid, current_wid, origin_x, origin_y, origin_z, x, y, z, yaw, pitch, data,"
            + " removed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            for (int i = 0; i < 4; i++) {
                statement.setLong(1, 2L + i * 5);
                statement.setInt(2, 1600000300 + i);
                statement.setLong(3, i == 3 ? LARGE_BLOCK_ROWID : 1L + i);
                if (i == 1) {
                    statement.setNull(4, java.sql.Types.NULL);
                } else {
                    statement.setLong(4, 100L + i);
                }
                statement.setString(5, "00000000-0000-4000-8000-00000000000" + i);
                statement.setInt(6, 1);
                statement.setInt(7, 1 + i % 2);
                for (int column = 8; column <= 13; column++) {
                    // Coordinates are doubles with all their digits, like CoreProtect's
                    statement.setDouble(column, 1234.5678901234567 * (column - 7) + i);
                }
                // Yaw and pitch are Java floats; MySQL's text protocol would round them to six digits
                statement.setDouble(14, (double) (123.45678f + i));
                statement.setDouble(15, (double) (-12.345678f * (i + 1)));
                byte[] data = new byte[32 + i];
                random.nextBytes(data);
                statement.setBytes(16, i == 2 ? null : data);
                statement.setInt(17, i % 2);
                statement.addBatch();
            }
            statement.executeBatch();
        }
        try (PreparedStatement statement = connection.prepareStatement("INSERT INTO " + p + "skull (rowid, time, owner,"
            + " skin) VALUES (?, ?, ?, ?)")) {
            String[] owners = {"Notch", "名前🙂", ""};
            for (int i = 0; i < owners.length; i++) {
                statement.setLong(1, 1L + i * 2);
                statement.setInt(2, 1600000400 + i);
                statement.setString(3, owners[i]);
                statement.setString(4, i == 2 ? null : "eyJ0ZXh0dXJlcyI6e30=".repeat(20 * (i + 1)) + " 🙂");
                statement.addBatch();
            }
            statement.executeBatch();
        }
        try (PreparedStatement statement = connection.prepareStatement("INSERT INTO " + p + "version (rowid, time,"
            + " version) VALUES (?, ?, ?)")) {
            statement.setLong(1, 1);
            statement.setInt(2, 1500000000);
            statement.setString(3, "2.20.0");
            statement.addBatch();
            statement.setLong(1, 2);
            statement.setInt(2, 1700000000);
            statement.setString(3, "2.24.1");
            statement.addBatch();
            statement.executeBatch();
        }
        try (PreparedStatement statement = connection.prepareStatement("INSERT INTO " + p + "block (rowid, time, "
            + user + ", wid, x, y, z, type, data, meta, blockdata, action, rolled_back)"
            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            for (int i = 0; i < blocks; i++) {
                statement.setLong(1, blockRowId(i, blocks));
                statement.setInt(2, 1600001000 + i);
                statement.setInt(3, i % 3 == 0 ? 1 : 5);
                statement.setInt(4, 1 + i % 3);
                statement.setInt(5, random.nextInt(2_000_000) - 1_000_000);
                statement.setInt(6, random.nextInt(384) - 64);
                statement.setInt(7, random.nextInt(2_000_000) - 1_000_000);
                statement.setInt(8, 1 + random.nextInt(50));
                statement.setInt(9, i == 1 ? Integer.MIN_VALUE : i == 2 ? Integer.MAX_VALUE : random.nextInt(16));
                if (i % 5 == 0) {
                    byte[] meta = new byte[2 + random.nextInt(200)];
                    random.nextBytes(meta);
                    // Like the Java serialization of CoreProtect's legacy encoding
                    meta[0] = (byte) 0xAC;
                    meta[1] = (byte) 0xED;
                    statement.setBytes(10, meta);
                } else {
                    statement.setNull(10, java.sql.Types.NULL);
                }
                statement.setBytes(11, i % 2 == 0 ? new byte[]{1, 2, (byte) i} : null);
                statement.setInt(12, i % 4);
                statement.setInt(13, i % 7 == 0 ? 1 : 0);
                statement.addBatch();
                if (i % 5_000 == 4_999) {
                    statement.executeBatch();
                }
            }
            statement.executeBatch();
        }
        connection.commit();
        connection.setAutoCommit(true);
    }

    /**
     * @return the row ID of the block at a position among {@code blocks}:
     *         odd numbers, a gap of 10,000 in the middle, and a last row ID
     *         that needs 64 bits
     */
    static long blockRowId(int position, int blocks) {
        if (position == blocks - 1 && blocks > 1) {
            return LARGE_BLOCK_ROWID;
        }
        return 1L + 2L * position + (position >= blocks / 2 ? 10_000 : 0);
    }

    /**
     * @return every table's rows in row ID order, as lines like
     *         {@code 12: time=1600000000, user='Steve', meta=0a0b} with
     *         columns sorted by name, to compare databases whose column
     *         order differs
     */
    static Map<String, List<String>> dump(Dialect dialect, Connector connector, Transcoder decode)
        throws SQLException {
        return dump(dialect, connector, PREFIX, decode);
    }

    static Map<String, List<String>> dump(Dialect dialect, Connector connector, String prefix, Transcoder decode)
        throws SQLException {
        Map<String, List<String>> dump = new LinkedHashMap<>();
        try (JdbcRowSource source = new JdbcRowSource(dialect, connector, true, true, prefix, TABLES)) {
            for (String table : source.tables()) {
                if (table.equals("database_lock")) {
                    continue;
                }
                List<String> columns = new ArrayList<>(source.columns(table));
                columns.sort(null);
                List<String> lines = new ArrayList<>();
                for (Row row : source.readRange(table, columns, Long.MIN_VALUE, Long.MAX_VALUE)) {
                    StringBuilder line = new StringBuilder().append(row.rowId()).append(':');
                    for (int i = 0; i < columns.size(); i++) {
                        Object value = decode.apply(table, columns.get(i), row.values()[i]);
                        line.append(' ').append(columns.get(i)).append('=').append(render(value));
                    }
                    lines.add(line.toString());
                }
                dump.put(table, lines);
            }
        }
        return dump;
    }

    private static String render(Object value) {
        if (value == null) {
            return "NULL";
        }
        if (value instanceof byte[]) {
            return "x'" + HexFormat.of().formatHex((byte[]) value) + "'";
        }
        if (value instanceof String) {
            return "'" + value + "'";
        }
        return value.toString();
    }

    /**
     * @return the lock row's status and time: {@code [status, time]}, or
     *         {@code null} without a lock row
     */
    static long[] lock(Connector connector) throws SQLException {
        try (Connection connection = connector.open(); Statement statement = connection.createStatement();
             java.sql.ResultSet result = statement.executeQuery("SELECT status, time FROM " + PREFIX
                 + "database_lock WHERE rowid = 1")) {
            return result.next() ? new long[]{result.getLong(1), result.getLong(2)} : null;
        }
    }

    static Properties duckDBProperties(File file) {
        Properties properties = new Properties();
        properties.setProperty("default_block_size", Integer.toString(128 * 1024));
        properties.setProperty("threads", "2");
        properties.setProperty("temp_directory", file.getAbsolutePath() + ".tmp");
        properties.setProperty("enable_external_access", "false");
        properties.setProperty("autoload_known_extensions", "false");
        properties.setProperty("autoinstall_known_extensions", "false");
        return properties;
    }
}
