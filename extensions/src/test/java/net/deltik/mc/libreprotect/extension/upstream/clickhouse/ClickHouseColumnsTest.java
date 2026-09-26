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

import net.deltik.mc.libreprotect.extension.migration.Row;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLDataException;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ClickHouseColumnsTest {

    private ClickHouseApi api;

    @BeforeEach
    void setUp() {
        api = ClickHouseTestServer.writes();
    }

    @Nested
    @DisplayName("Column kinds")
    class Kinds {

        @ParameterizedTest(name = "{0}.{1}")
        @CsvSource({
            "block, meta", "block, blockdata", "container, metadata", "entity_container, metadata",
            "entity_interaction, metadata", "item, data", "entity, data", "entity_spawn, data"
        })
        @DisplayName("should treat the BLOB columns of the other engines as binary")
        void binary(String table, String column) {
            assertTrue(ClickHouseColumns.isBinary(table, column));
        }

        @ParameterizedTest(name = "{0}.{1}")
        @CsvSource({
            "block, data", "blockdata_map, data", "sign, data", "chat, message", "skull, skin", "user, uuid",
            "entity_spawn, uuid", "sign, line_1", "container, data", "unknown, meta"
        })
        @DisplayName("should treat other columns as text or numbers")
        void notBinary(String table, String column) {
            assertFalse(ClickHouseColumns.isBinary(table, column));
        }

        @ParameterizedTest
        @ValueSource(strings = {"rowid", "_key_time", "_key_wid", "_key_x", "_key_z"})
        @DisplayName("should not copy the row ID or the lookup keys of ClickHouse's views")
        void notCopied(String column) {
            assertFalse(ClickHouseColumns.isCopied(column));
        }

        @ParameterizedTest
        @ValueSource(strings = {"time", "user", "wid", "x", "data", "id", "key"})
        @DisplayName("should copy CoreProtect's columns")
        void copied(String column) {
            assertTrue(ClickHouseColumns.isCopied(column));
        }

        @Test
        @DisplayName("should read a missing UUID back as none only where the view shows it as empty")
        void emptyForNull() {
            assertTrue(ClickHouseColumns.isEmptyForNull("user", "uuid"));
            assertFalse(ClickHouseColumns.isEmptyForNull("username_log", "uuid"));
            assertFalse(ClickHouseColumns.isEmptyForNull("entity_spawn", "uuid"));
            assertFalse(ClickHouseColumns.isEmptyForNull("user", "user"));
        }

        @Test
        @DisplayName("should know CoreProtect's tables by name")
        void family() throws SQLException {
            assertEquals("blockdata_map", ClickHouseColumns.family(api, "blockdata_map").tableName());
            assertEquals(api.family("blockdata_map"), ClickHouseColumns.family(api, "blockdata_map"));
            SQLException e = assertThrows(SQLException.class, () -> ClickHouseColumns.family(api, "co_block"));
            assertTrue(e.getMessage().contains("co_block"), e.getMessage());
        }

        @ParameterizedTest(name = "{0}.{1} -> {2}")
        @CsvSource({
            "block, user, user_id", "user, user, user_name", "username_log, user, user_name",
            "item, data, payload", "entity, data, payload", "entity_spawn, data, entity_data",
            "blockdata_map, data, text", "sign, data, sign_data", "block, data, data", "container, data, data",
            "entity_spawn, x, current_x", "entity_spawn, z, current_z", "block, x, x", "entity_spawn, wid, wid",
            "art_map, art, name", "entity_map, entity, name", "material_map, material, name", "world, world, name",
            "skull, owner, name", "skull, skin, text", "sign, line_8, line_8", "user, uuid, uuid"
        })
        @DisplayName("should find where CoreProtect's writer stores each column")
        void physicalColumn(String table, String column, String physical) {
            assertEquals(physical, ClickHouseColumns.physicalColumn(api.family(table), column));
        }

        @Test
        @DisplayName("should map every column of every table to a column of the event table")
        void everyColumnStored() throws Exception {
            ClickHouseFixture fixture = new ClickHouseFixture();
            for (Map.Entry<String, List<String>> table : fixture.columns.entrySet()) {
                for (String column : table.getValue()) {
                    String physical = ClickHouseColumns.physicalColumn(api.family(table.getKey()), column);
                    assertTrue(api.eventColumns().contains(physical), table.getKey() + "." + column);
                }
            }
        }

        @Test
        @DisplayName("should list the identifier maps, whose rows CoreProtect keys by identifier")
        void identifierMaps() {
            assertEquals(5, ClickHouseColumns.IDENTIFIER_MAPS.size());
            assertTrue(ClickHouseColumns.IDENTIFIER_MAPS.contains("world"));
            assertFalse(ClickHouseColumns.IDENTIFIER_MAPS.contains("user"));
            for (String map : ClickHouseColumns.IDENTIFIER_MAPS) {
                assertEquals(map, api.family(map).tableName());
            }
        }
    }

    @Nested
    @DisplayName("Quoting")
    class Quoting {

        @Test
        @DisplayName("should quote column names in backquotes")
        void quote() throws SQLException {
            assertEquals("`user`", ClickHouseColumns.quote("user"));
            assertEquals("`line_8`", ClickHouseColumns.quote("line_8"));
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "8line", "user`", "a b", "x;DROP", "ü"})
        @DisplayName("should refuse anything but a plain identifier")
        void refuse(String identifier) {
            assertThrows(SQLException.class, () -> ClickHouseColumns.quote(identifier));
        }
    }

    @Nested
    @DisplayName("Normalization")
    class Normalization {

        @Test
        @DisplayName("should turn every whole number type the driver returns into Long")
        void wholeNumbers() throws SQLException {
            assertEquals(4_000_000_000L, ClickHouseColumns.normalize(4_000_000_000L));
            assertEquals(-3L, ClickHouseColumns.normalize(-3));
            assertEquals(255L, ClickHouseColumns.normalize((short) 255));
            assertEquals(7L, ClickHouseColumns.normalize((byte) 7));
            assertEquals(Long.MAX_VALUE, ClickHouseColumns.normalize(BigInteger.valueOf(Long.MAX_VALUE)));
            assertEquals(1L, ClickHouseColumns.normalize(Boolean.TRUE));
        }

        @Test
        @DisplayName("should refuse a UInt64 beyond the signed 64-bit range")
        void tooLarge() {
            assertThrows(SQLDataException.class,
                () -> ClickHouseColumns.normalize(BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE)));
        }

        @Test
        @DisplayName("should widen Float32 to the Double other engines return for the same float")
        void floats() throws SQLException {
            assertEquals((double) 0.1f, ClickHouseColumns.normalize(0.1f));
            assertEquals(0.2, ClickHouseColumns.normalize(0.2));
        }

        @Test
        @DisplayName("should pass text, binary data and NULL through")
        void passThrough() throws SQLException {
            byte[] bytes = {0, 1};
            assertSame(bytes, ClickHouseColumns.normalize(bytes));
            assertEquals("Stéve ☃", ClickHouseColumns.normalize("Stéve ☃"));
            assertNull(ClickHouseColumns.normalize(null));
        }

        @Test
        @DisplayName("should refuse values of other types")
        void other() {
            assertThrows(SQLDataException.class, () -> ClickHouseColumns.normalize(new java.util.Date()));
        }
    }

    @Nested
    @DisplayName("Binary unwrapping")
    class Unwrapping {

        @Test
        @DisplayName("should keep binary data from string columns exactly, even when it starts with a zero byte")
        void string() throws SQLException {
            byte[] bytes = {0, -1, 65};
            assertSame(bytes, ClickHouseColumns.unwrapBinary(bytes, Types.VARCHAR, "meta"));
            byte[] empty = {};
            assertSame(empty, ClickHouseColumns.unwrapBinary(empty, Types.VARCHAR, "meta"));
            assertNull(ClickHouseColumns.unwrapBinary(null, Types.VARCHAR, "meta"));
        }

        @Test
        @DisplayName("should strip the presence byte from array columns, as CoreProtect does")
        void array() throws SQLException {
            assertArrayEquals(new byte[]{1, 2}, ClickHouseColumns.unwrapBinary(new byte[]{0, 1, 2}, Types.ARRAY, "m"));
            assertArrayEquals(new byte[]{}, ClickHouseColumns.unwrapBinary(new byte[]{0}, Types.ARRAY, "m"));
            assertNull(ClickHouseColumns.unwrapBinary(new byte[]{}, Types.ARRAY, "m"));
            assertNull(ClickHouseColumns.unwrapBinary(null, Types.ARRAY, "m"));
        }

        @Test
        @DisplayName("should refuse an array value without the presence byte")
        void badMarker() {
            SQLException e = assertThrows(SQLException.class,
                () -> ClickHouseColumns.unwrapBinary(new byte[]{1, 2}, Types.ARRAY, "metadata"));
            assertTrue(e.getMessage().contains("metadata"), e.getMessage());
        }
    }

    @Nested
    @DisplayName("Reading rows")
    class Reading {

        @Test
        @DisplayName("should read binary columns as bytes, other columns as normalized objects")
        void kinds() throws SQLException {
            byte[] meta = {0, 5};
            ResultSet resultSet = resultSet(new int[]{Types.BIGINT, Types.INTEGER, Types.VARCHAR, Types.VARCHAR},
                BigInteger.valueOf(42), 7, meta, "text");
            ClickHouseColumns.RowReader reader = new ClickHouseColumns.RowReader("block",
                Arrays.asList("x", "meta", "message"), resultSet.getMetaData());

            Row row = reader.read(resultSet);

            assertEquals(42, row.rowId());
            assertEquals(7L, row.values()[0]);
            assertArrayEquals(meta, (byte[]) row.values()[1]);
            assertEquals("text", row.values()[2]);
        }

        @Test
        @DisplayName("should read the user view's empty UUID as none")
        void userUuid() throws SQLException {
            ResultSet resultSet = resultSet(new int[]{Types.BIGINT, Types.VARCHAR, Types.VARCHAR}, 3L, "#fire", "");
            ClickHouseColumns.RowReader reader = new ClickHouseColumns.RowReader("user",
                Arrays.asList("user", "uuid"), resultSet.getMetaData());

            assertNull(reader.read(resultSet).values()[1]);
        }

        @Test
        @DisplayName("should keep an empty UUID elsewhere")
        void otherUuid() throws SQLException {
            ResultSet resultSet = resultSet(new int[]{Types.BIGINT, Types.VARCHAR}, 3L, "");
            ClickHouseColumns.RowReader reader = new ClickHouseColumns.RowReader("username_log",
                List.of("uuid"), resultSet.getMetaData());

            assertEquals("", reader.read(resultSet).values()[0]);
        }

        @Test
        @DisplayName("should refuse a result with other columns than asked for")
        void columnCount() {
            ResultSet resultSet = resultSet(new int[]{Types.BIGINT, Types.VARCHAR}, 3L, "");
            assertThrows(SQLException.class, () -> new ClickHouseColumns.RowReader("user",
                Arrays.asList("user", "uuid"), resultSet.getMetaData()));
        }

        /**
         * A result set positioned on one row, with a row ID first
         */
        private ResultSet resultSet(int[] types, Object... values) {
            ResultSetMetaData metaData = (ResultSetMetaData) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{ResultSetMetaData.class}, (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getColumnCount":
                            return values.length;
                        case "getColumnType":
                            return types[(Integer) args[0] - 1];
                        default:
                            throw new UnsupportedOperationException(method.getName());
                    }
                });
            return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{ResultSet.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getMetaData":
                            return metaData;
                        case "getLong":
                            return ((Number) values[(Integer) args[0] - 1]).longValue();
                        case "wasNull":
                            return false;
                        case "getBytes":
                            return (byte[]) values[(Integer) args[0] - 1];
                        case "getObject":
                            return values[(Integer) args[0] - 1];
                        default:
                            throw new UnsupportedOperationException(method.getName());
                    }
                });
        }
    }
}
