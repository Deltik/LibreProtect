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

import net.deltik.mc.libreprotect.extension.upstream.Capabilities;
import net.deltik.mc.libreprotect.extension.upstream.Capability;
import net.deltik.mc.libreprotect.extension.upstream.Names;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Config;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Pool;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import org.junit.jupiter.api.Assumptions;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * The ClickHouse server that {@code scripts/lp db up} starts, whose endpoint
 * {@code scripts/lp build} passes to the tests as {@code -Dlpit.containers}.
 * Tests using it are skipped without one, or on a CoreProtect without
 * ClickHouse; in CI, where the environment variable {@code CI} is set, a
 * CoreProtect with ClickHouse must have a server to test with, so they fail
 * without one. Each test works under its own table prefix, whose tables and
 * views are dropped afterward.
 */
final class ClickHouseTestServer implements AutoCloseable {

    private static final String HOW_TO = "Run scripts/lp db up, then scripts/lp build --ref master.";

    private final ClickHouseApi api;
    private final Properties endpoints;
    private final Config config;
    private final Pool jdbc;
    private final List<String> prefixes = new ArrayList<>();
    private final AtomicLong batchSequence = new AtomicLong(1_000_000);

    private ClickHouseTestServer(ClickHouseApi api, Properties endpoints) {
        this.api = api;
        this.endpoints = endpoints;
        this.config = config(endpoints.getProperty("CLICKHOUSE_HOST"),
            Integer.parseInt(endpoints.getProperty("CLICKHOUSE_PORT")));
        this.jdbc = api.pool(config);
    }

    /**
     * @return CoreProtect's ClickHouse classes for writing, which read too,
     *         or skip the test on a CoreProtect without them
     */
    static ClickHouseApi writes() {
        return require(ClickHouseApi.WRITES);
    }

    /**
     * @return CoreProtect's ClickHouse classes for reading only, or skip the
     *         test on a CoreProtect without them
     */
    static ClickHouseApi reads() {
        return require(ClickHouseApi.READS);
    }

    /**
     * @return which servers this CoreProtect's ClickHouse writer takes, as a
     *         migration to ClickHouse checks, or skip the test on a
     *         CoreProtect without ClickHouse
     */
    static ClickHouseServerVersion serverVersion() {
        return require(ClickHouseServerVersion.CAPABILITY);
    }

    private static <T> T require(Capability<T> capability) {
        Choice<T> choice = Capabilities.current().get(capability);
        Assumptions.assumeTrue(choice.isAvailable(), () -> "This CoreProtect's " + choice.id() + " is "
            + choice.strategy() + ": " + choice.reason());
        return choice.orElse(null);
    }

    private Config config(String host, int port) {
        return api.config(host, port, endpoints.getProperty("CLICKHOUSE_DATABASE"),
            endpoints.getProperty("CLICKHOUSE_USERNAME"), endpoints.getProperty("CLICKHOUSE_PASSWORD"), false);
    }

    /**
     * @return the settings to reach another database of the server
     */
    Config config(String database) {
        return api.config(endpoints.getProperty("CLICKHOUSE_HOST"),
            Integer.parseInt(endpoints.getProperty("CLICKHOUSE_PORT")), database,
            endpoints.getProperty("CLICKHOUSE_USERNAME"), endpoints.getProperty("CLICKHOUSE_PASSWORD"), false);
    }

    /**
     * @return a proxy in front of the server, which can make it hang
     */
    StallingProxy stallingProxy() throws IOException {
        return new StallingProxy(endpoints.getProperty("CLICKHOUSE_HOST"),
            Integer.parseInt(endpoints.getProperty("CLICKHOUSE_PORT")));
    }

    /**
     * @return the settings to reach the server through the proxy
     */
    Config config(StallingProxy proxy) {
        return config("127.0.0.1", proxy.port());
    }

    /**
     * @return the server, or skip the test if there is none
     */
    static ClickHouseTestServer connect() throws IOException {
        return new ClickHouseTestServer(writes(), endpoints());
    }

    /**
     * @return the endpoints of the database containers, with ClickHouse's;
     *         skip the test without them, but fail it in CI
     */
    static Properties endpoints() throws IOException {
        return endpoints(System.getProperty("lpit.containers"), System.getenv("CI"));
    }

    /**
     * @param containers the file of the containers' endpoints, if any
     * @param ci         the environment variable {@code CI}, which CI sets
     */
    static Properties endpoints(String containers, String ci) throws IOException {
        Properties endpoints = new Properties();
        String missing = null;
        if (containers == null || containers.isEmpty()) {
            missing = "No database containers.";
        } else if (!Files.isRegularFile(Paths.get(containers))) {
            missing = "No database containers at " + containers + ".";
        } else {
            try (InputStream input = Files.newInputStream(Paths.get(containers))) {
                endpoints.load(input);
            }
            String host = endpoints.getProperty("CLICKHOUSE_HOST");
            if (host == null || host.isEmpty()) {
                missing = "The database containers don't include ClickHouse.";
            }
        }
        if (missing != null) {
            if (ci != null && !ci.isEmpty() && !ci.equalsIgnoreCase("false")) {
                fail(missing + " CI must test ClickHouse on a CoreProtect that has it: start the containers with"
                    + " scripts/lp db up --all.");
            }
            Assumptions.assumeTrue(false, missing + " " + HOW_TO);
        }
        return endpoints;
    }

    ClickHouseApi api() {
        return api;
    }

    Config config() {
        return config;
    }

    String database() {
        return config.database();
    }

    /**
     * @return a new table prefix, cleaned up when the server is closed
     */
    String newPrefix() {
        String prefix = "lpt" + Long.toHexString(ThreadLocalRandom.current().nextLong() & Long.MAX_VALUE) + "_";
        prefixes.add(prefix);
        return prefix;
    }

    /**
     * Skip the test unless CoreProtect's ClickHouse writer can publish to
     * this server. It sends the {@code max_insert_block_size_bytes} setting
     * with every insert, which ClickHouse 25.8 doesn't have, though some
     * CoreProtect 25 builds take 25.6 or newer. ClickHouse 26.1 is the first
     * that has it; the tests run on the 26.3 of
     * {@code integration/containers.lock}.
     */
    void assumeWriterSupported() throws SQLException {
        Assumptions.assumeTrue(queryLong("SELECT count() FROM system.settings WHERE name = 'max_insert_block_size_bytes'") > 0,
            "ClickHouse " + queryString("SELECT version()") + " rejects the max_insert_block_size_bytes setting that"
                + " CoreProtect 25's writer sends with every insert; this needs ClickHouse 26.1 or newer");
    }

    /**
     * Create CoreProtect's ClickHouse schema under the prefix, and nothing else.
     */
    void createSchema(String prefix, Path controlDirectory) throws SQLException {
        api.initialize(config, prefix, controlDirectory).close();
    }

    /**
     * Insert a row into CoreProtect's event table directly, the way
     * CoreProtect's writer lays it out, bypassing the writer.
     *
     * @param physical the event table's columns other than the batch
     *                 columns, family and row ID
     */
    void insertEvent(String prefix, String family, long rowId, Map<String, Object> physical) throws SQLException {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("batch_sequence", batchSequence.incrementAndGet());
        row.put("batch_ordinal", 0);
        row.put("family", family);
        row.put("rowid", rowId);
        row.putAll(stamps());
        row.putAll(physical);
        StringBuilder columns = new StringBuilder("batch_id");
        StringBuilder values = new StringBuilder("generateUUIDv4()");
        for (Map.Entry<String, Object> entry : row.entrySet()) {
            columns.append(", `").append(entry.getKey()).append('`');
            values.append(", ").append(literal(entry.getValue()));
        }
        execute("INSERT INTO " + api.qualified(database(), prefix + "event_data")
            + " (" + columns + ") VALUES (" + values + ")");
    }

    /**
     * Insert chat messages of 200 random printable characters each, with row
     * IDs from 1, directly as {@link #insertEvent} does. They don't
     * compress, so that streaming them takes a while.
     */
    void insertRandomChat(String prefix, int rows) throws SQLException {
        StringBuilder columns = new StringBuilder();
        StringBuilder values = new StringBuilder();
        for (Map.Entry<String, Object> stamp : stamps().entrySet()) {
            columns.append(", `").append(stamp.getKey()).append('`');
            values.append(", ").append(literal(stamp.getValue()));
        }
        execute("INSERT INTO " + table(prefix, "event_data")
            + " (batch_sequence, batch_id, batch_ordinal, family, rowid, time, user_id, wid, x, y, z,"
            + " wid_present, x_present, z_present, message" + columns + ")"
            + " SELECT 1, generateUUIDv4(), 0, 'chat', number + 1, 1700000000 + number % 1000, 1, 1,"
            + " toInt32(number % 97), 64, toInt32(number % 89), 1, 1, 1, randomPrintableASCII(200)" + values
            + " FROM numbers(" + rows + ")");
    }

    /**
     * @return what CoreProtect's writer stamps on every row of the event
     *         table besides its data: its write version, which the table
     *         requires where CoreProtect has a lookup index, or nothing
     */
    private Map<String, Object> stamps() {
        if (!api.eventColumns().contains("write_version")) {
            return Map.of();
        }
        try {
            return Map.of("write_version",
                Upstream.coreProtect().type(Names.CLICKHOUSE_SCHEMA).intConstant("VERSION").getAsInt());
        } catch (Missing e) {
            throw new AssertionError("CoreProtect's event table has a write_version, but no write version to"
                + " stamp: " + e.getMessage(), e);
        }
    }

    /**
     * @return a row of a CoreProtect located table, with the presence flags
     *         CoreProtect sets for its location
     */
    static Map<String, Object> located(long time, Long user, Integer wid, Integer x, Integer y, Integer z) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("time", time);
        row.put("user_id", user);
        row.put("wid", wid == null ? 0 : wid);
        row.put("wid_present", wid == null ? 0 : 1);
        row.put("x", x == null ? 0 : x);
        row.put("x_present", x == null ? 0 : 1);
        row.put("y", y);
        row.put("z", z == null ? 0 : z);
        row.put("z_present", z == null ? 0 : 1);
        return row;
    }

    private static String literal(Object value) {
        if (value == null) {
            return "NULL";
        }
        if (value instanceof Number) {
            return value.toString();
        }
        byte[] bytes = value instanceof byte[] ? (byte[]) value : value.toString().getBytes(StandardCharsets.UTF_8);
        StringBuilder hex = new StringBuilder("unhex('");
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.append("')").toString();
    }

    void execute(String sql) throws SQLException {
        try (Connection connection = jdbc.openConnection(); Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    long queryLong(String sql) throws SQLException {
        try (Connection connection = jdbc.openConnection(); Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return resultSet.getLong(1);
        }
    }

    String queryString(String sql) throws SQLException {
        try (Connection connection = jdbc.openConnection(); Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return resultSet.getString(1);
        }
    }

    /**
     * @return the qualified name of a table under the prefix
     */
    String table(String prefix, String table) {
        return api.qualified(database(), prefix + table);
    }

    /**
     * Drop the tables and views of every prefix this handed out.
     */
    @Override
    public void close() throws SQLException {
        try {
            for (String prefix : prefixes) {
                List<String> views = new ArrayList<>();
                List<String> tables = new ArrayList<>();
                try (Connection connection = jdbc.openConnection(); Statement statement = connection.createStatement();
                     ResultSet resultSet = statement.executeQuery("SELECT name, engine FROM system.tables WHERE database = '"
                         + database() + "' AND startsWith(name, '" + prefix + "')")) {
                    while (resultSet.next()) {
                        (resultSet.getString(2).equals("View") ? views : tables).add(resultSet.getString(1));
                    }
                }
                for (String name : views) {
                    execute("DROP VIEW IF EXISTS " + api.qualified(database(), name));
                }
                for (String name : tables) {
                    execute("DROP TABLE IF EXISTS " + api.qualified(database(), name) + " SYNC");
                }
            }
        } finally {
            jdbc.close();
        }
    }
}
