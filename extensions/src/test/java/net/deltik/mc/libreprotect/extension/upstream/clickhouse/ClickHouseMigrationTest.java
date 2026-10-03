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

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.extension.common.Console;
import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.MigrationBridge;
import net.deltik.mc.libreprotect.extension.migration.MigrationException;
import net.deltik.mc.libreprotect.extension.migration.MigrationSession;
import net.deltik.mc.libreprotect.extension.migration.MigrationTestAccess;
import net.deltik.mc.libreprotect.extension.migration.RowSink;
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Connector;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Dialect;
import net.deltik.mc.libreprotect.extension.migration.jdbc.JdbcRowSink;
import net.deltik.mc.libreprotect.extension.migration.jdbc.JdbcRowSource;
import net.deltik.mc.libreprotect.extension.upstream.Capabilities;
import net.deltik.mc.libreprotect.extension.upstream.Codecs;
import net.deltik.mc.libreprotect.extension.upstream.IncompleteMarks;
import net.deltik.mc.libreprotect.extension.upstream.Schema;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.testutil.CoreProtectFixture;
import net.deltik.mc.libreprotect.testutil.RecordingSender;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.bukkit.command.ConsoleCommandSender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Whole migrations through ClickHouse: the copier and validator, the real
 * ClickHouse sink and source, and CoreProtect 25's transcoding and canonical
 * comparison. SQLite → ClickHouse → SQLite, with a block table large enough
 * for sampled validation, which reads ClickHouse through readRanges on both
 * hops. Skipped without a ClickHouse container.
 *
 * <p>This drives the migration's engine-generic core with the ClickHouse
 * endpoints directly; the migration command, with its session, is tested
 * where CoreProtect's session is.
 */
class ClickHouseMigrationTest {

    /** CoreProtect 25's tables (Database.java:756) */
    private static final List<String> TABLES = List.of("art_map", "block", "chat", "command", "container",
        "entity_container", "entity_interaction", "item", "database_lock", "entity", "entity_spawn", "entity_map",
        "material_map", "blockdata_map", "session", "sign", "skull", "user", "username_log", "version", "world");

    private static final int BLOCKS = 150_000;

    @TempDir
    Path folder;

    @RegisterExtension
    final CoreProtectFixture coreProtect = new CoreProtectFixture();

    private ClickHouseMigrationAccess clickHouse;
    private RecordingSender console;
    private MigrationBridge bridge;

    @BeforeEach
    void setUp() throws Exception {
        clickHouse = ClickHouseMigrationAccess.connect();
        coreProtect.set("Config.ERROR_REPORTING", false);
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(new TestLogger());
        console = new RecordingSender(ConsoleCommandSender.class);
        bridge = new CodecsBridge(Capabilities.current().require(Codecs.CAPABILITY));
    }

    @AfterEach
    void tearDown() throws Exception {
        if (clickHouse != null) {
            clickHouse.close();
        }
        LibreProtectLogger.reset();
    }

    /**
     * What the migration needs of CoreProtect beyond its endpoints:
     * CoreProtect 25's conversions between the legacy and columnar encodings.
     */
    private static final class CodecsBridge implements MigrationBridge {
        private final Codecs codecs;

        CodecsBridge(Codecs codecs) {
            this.codecs = codecs;
        }

        @Override
        public Set<Engine> engines() {
            return Set.of(Engine.SQLITE, Engine.CLICKHOUSE);
        }

        @Override
        public Engine activeEngine() {
            throw new UnsupportedOperationException();
        }

        @Override
        public MigrationSession claim(Engine target) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Object transcode(String table, String column, Object value, Engine from, Engine to)
            throws SQLException {
            return codecs.transcode(table, column, value, from, to);
        }

        @Override
        public Object canonical(String table, String column, Object value) throws SQLException {
            return codecs.canonical(table, column, value);
        }
    }

    /** Between a SQLite file (with CoreProtect 25's own schema as a target) and ClickHouse */
    private final class Session implements MigrationSession {
        final DatabaseSettings source;
        final DatabaseSettings target;
        int activations;

        Session(DatabaseSettings source, DatabaseSettings target) {
            this.source = source;
            this.target = target;
        }

        @Override
        public Engine source() {
            return source.engine();
        }

        @Override
        public DatabaseSettings sourceSettings() {
            return source;
        }

        @Override
        public DatabaseSettings targetSettings() {
            return target;
        }

        @Override
        public List<String> pause() {
            return List.of();
        }

        @Override
        public String stopReason() {
            return null;
        }

        @Override
        public RowSource openSource() throws SQLException {
            if (source.engine() == Engine.CLICKHOUSE) {
                return clickHouse.source(source);
            }
            return new JdbcRowSource(Dialect.SQLITE, MigrationTestAccess.connector(source), true, true,
                source.prefix(), TABLES);
        }

        @Override
        public RowSink openSink(DatabaseSettings settings) throws SQLException {
            if (settings.engine() == Engine.CLICKHOUSE) {
                return clickHouse.sink(settings, folder);
            }
            try {
                Capabilities capabilities = Capabilities.current();
                return new JdbcRowSink(Dialect.SQLITE, MigrationTestAccess.connector(settings), settings.prefix(),
                    TABLES, capabilities.require(Schema.CAPABILITY).creator(Engine.SQLITE),
                    capabilities.require(IncompleteMarks.CAPABILITY).marker(), settings.file(), null);
            } catch (Missing e) {
                throw new SQLException(e.getMessage(), e);
            }
        }

        @Override
        public List<String> activate(RowSink sink, DatabaseSettings settings) throws MigrationException {
            activations++;
            try {
                sink.markComplete();
                sink.close();
            } catch (SQLException e) {
                throw new MigrationException(e.getMessage(), e);
            }
            return List.of();
        }

        @Override
        public void close() {
        }
    }

    private void migrate(Session session) {
        MigrationTestAccess.migrate(bridge, session, new Console(console.sender()), session.target.engine(),
            new Random(3));
    }

    /** TestDatabases' legacy source, with block metadata and entity data that CoreProtect's codecs can read */
    private static void seed(File file) throws Exception {
        MigrationTestAccess.createLegacySqlite(file, BLOCKS);
        UpstreamCodecs codecs = new UpstreamCodecs();
        byte[] command = codecs.serializeMetaForSqlite(new ArrayList<>(List.of("say ünïcödé 🙂")));
        List<Object> entity = new ArrayList<>(Arrays.asList(Arrays.asList(-24000, true, false), Arrays.asList(false,
            null), Arrays.asList("WHITE", 3), true, "Bessie 🐄"));
        byte[] entityData = codecs.serializeEntityForSqlite(entity, "ENTITY");
        byte[] spawnData = codecs.serializeEntityForSqlite(entity, "ENTITY_SPAWN");
        try (Connection connection = MigrationTestAccess.connector(DatabaseSettings.embedded(Engine.SQLITE, file))
            .open()) {
            update(connection, "UPDATE co_block SET meta = ? WHERE meta IS NOT NULL", command);
            update(connection, "UPDATE co_entity SET data = ?", entityData);
            update(connection, "UPDATE co_entity_spawn SET data = ? WHERE data IS NOT NULL", spawnData);
            // CoreProtect stores sign colors as Color.asRGB(), 0 to 0xFFFFFF; TestDatabases' negative ones can't exist
            try (java.sql.Statement statement = connection.createStatement()) {
                statement.executeUpdate("UPDATE co_sign SET color = 16777215 - rowid, color_secondary = rowid");
                if (ClickHouseFixture.SIGN_ROLLBACKS) {
                    // As CoreProtect's patch adds it to an older database, with some signs rolled back since
                    statement.executeUpdate("ALTER TABLE co_sign ADD COLUMN rolled_back INTEGER DEFAULT 0");
                    statement.executeUpdate("UPDATE co_sign SET rolled_back = 1 WHERE rowid % 2 = 0");
                }
            }
        }
    }

    private static void update(Connection connection, String sql, byte[] value) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setBytes(1, value);
            statement.executeUpdate();
        }
    }

    @Test
    @DisplayName("should copy SQLite to ClickHouse and back with every row and value, sampling both ways")
    void roundTrip() throws Exception {
        File original = folder.resolve("original.db").toFile();
        seed(original);
        DatabaseSettings sqlite = DatabaseSettings.embedded(Engine.SQLITE, original);
        DatabaseSettings columnar = clickHouse.newDatabase();

        Session there = new Session(sqlite, columnar);
        migrate(there);
        String text = console.text();
        assertEquals(1, there.activations, "to ClickHouse:\n" + text);
        assertTrue(text.contains("about 1% of the rows of larger tables"), text);

        File back = folder.resolve("back.db").toFile();
        Session home = new Session(columnar, DatabaseSettings.embedded(Engine.SQLITE, back));
        migrate(home);
        text = console.text();
        assertEquals(1, home.activations, "back from ClickHouse:\n" + text);

        Connector before = MigrationTestAccess.connector(sqlite);
        Connector after = MigrationTestAccess.connector(DatabaseSettings.embedded(Engine.SQLITE, back));
        Map<String, List<String>> expected = new LinkedHashMap<>(MigrationTestAccess.dump(Dialect.SQLITE, before,
            bridge));
        Map<String, List<String>> actual = new LinkedHashMap<>(MigrationTestAccess.dump(Dialect.SQLITE, after,
            bridge));
        // ClickHouse keeps only its own version row
        expected.remove("version");
        actual.remove("version");
        for (Map.Entry<String, List<String>> table : expected.entrySet()) {
            List<String> want = table.getValue();
            List<String> got = actual.get(table.getKey());
            assertNotNull(got, table.getKey());
            assertEquals(want.size(), got.size(), table.getKey() + " rows");
            for (int i = 0; i < want.size(); i++) {
                assertEquals(want.get(i), got.get(i), table.getKey());
            }
        }
    }
}
