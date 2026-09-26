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

package net.deltik.mc.libreprotect.extension.upstream.clickhouse;

import net.deltik.mc.libreprotect.extension.migration.Row;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Family;

import java.math.BigInteger;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLDataException;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * How CoreProtect's ClickHouse views line up with the column values that
 * migrations copy between engines.
 *
 * <p>Every CoreProtect table is a view over one event table in ClickHouse,
 * with the relational column names. Values read from a view are normalized
 * as {@link Row} describes. ClickHouse keeps text and binary data in the same
 * {@code String} type, so the binary columns are listed here.
 *
 * <p>What this knows of CoreProtect's views is LibreProtect's contract with
 * them, which the capability report's {@code relies} lines watch: the
 * views' columns ({@code ClickHouseSchema.createStatements} and
 * {@code binary}), and the presence byte of binary data
 * ({@code DatabaseUtils.getBytes}). Where the writer stores a view's column
 * is CoreProtect's own mapping ({@code ClickHouseEventBatch.compatibilityColumn}).
 */
final class ClickHouseColumns {

    /** The row ID column of every view */
    static final String ROW_ID = "rowid";

    /** Views add these to look rows up, such as by location; they aren't CoreProtect columns */
    static final String KEY_COLUMN_PREFIX = "_key_";

    /**
     * The tables whose rows map an identifier to a name, which CoreProtect
     * keys by that identifier, in the order CoreProtect declares them
     */
    static final Set<String> IDENTIFIER_MAPS = Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
        "art_map", "entity_map", "material_map", "blockdata_map", "world")));

    private static final Map<String, Set<String>> BINARY_COLUMNS = binaryColumns();

    /** Event table columns that CoreProtect's writer stores with a presence flag, so NULL is kept */
    private static final Set<String> LOCATED = Collections.unmodifiableSet(new HashSet<>(Arrays.asList("wid", "x", "z")));

    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*");

    private ClickHouseColumns() {
    }

    private static Map<String, Set<String>> binaryColumns() {
        Map<String, Set<String>> columns = new HashMap<>();
        columns.put("block", new HashSet<>(Arrays.asList("meta", "blockdata")));
        columns.put("container", Collections.singleton("metadata"));
        columns.put("entity_container", Collections.singleton("metadata"));
        columns.put("entity_interaction", Collections.singleton("metadata"));
        columns.put("item", Collections.singleton("data"));
        columns.put("entity", Collections.singleton("data"));
        columns.put("entity_spawn", Collections.singleton("data"));
        return Collections.unmodifiableMap(columns);
    }

    /**
     * @return whether the column holds binary data, which is a BLOB on the other engines
     */
    static boolean isBinary(String table, String column) {
        return BINARY_COLUMNS.getOrDefault(table, Collections.emptySet()).contains(column);
    }

    /**
     * @return whether a view column is one that migrations copy: not the row ID
     *         and not one of the lookup keys that only ClickHouse's views have
     */
    static boolean isCopied(String column) {
        return !column.equals(ROW_ID) && !column.startsWith(KEY_COLUMN_PREFIX);
    }

    /**
     * @return whether a missing UUID reads back as an empty string: the
     *         {@code user} view shows {@code ''} where the other engines have NULL
     */
    static boolean isEmptyForNull(String table, String column) {
        return table.equals("user") && column.equals("uuid");
    }

    /**
     * @return the CoreProtect table's event family
     * @throws SQLException if CoreProtect has no such table
     */
    static Family family(ClickHouseApi api, String table) throws SQLException {
        try {
            return api.family(table);
        } catch (IllegalArgumentException e) {
            throw new SQLException("CoreProtect has no table named '" + table + "'", e);
        }
    }

    /**
     * @return the identifier in backquotes, for SQL
     * @throws SQLException if it isn't a plain identifier, which every CoreProtect column is
     */
    static String quote(String identifier) throws SQLException {
        if (identifier == null || !IDENTIFIER.matcher(identifier).matches()) {
            throw new SQLException("Not a CoreProtect column name: " + identifier);
        }
        return "`" + identifier + "`";
    }

    /**
     * @return the column of CoreProtect's event table that a view column is
     *         stored in, as CoreProtect's writer maps it for compatibility rows
     */
    static String physicalColumn(Family family, String column) {
        return family.api().compatibilityColumn(family, column);
    }

    /**
     * Refuse a value that ClickHouse can't hold as it is: CoreProtect's
     * writer would store a missing time as 0, and wrap or truncate numbers
     * that don't fit, rather than fail. The same rule as for MySQL targets,
     * where a value that doesn't fit its column fails the migration.
     *
     * @throws SQLDataException naming the table, column and row ID
     */
    static void requireFits(Family family, String table, String column, Object value, long rowId)
        throws SQLDataException {
        String physical = physicalColumn(family, column);
        String type = family.api().eventColumnType(physical);
        if (type == null) {
            // CoreProtect's writer names the column it doesn't know
            return;
        }
        boolean nullable = type.startsWith("Nullable(") && type.endsWith(")");
        String base = nullable ? type.substring("Nullable(".length(), type.length() - 1) : type;
        String problem = misfit(base, value);
        if (value == null && !nullable && !LOCATED.contains(physical)) {
            problem = "is missing, which ClickHouse requires";
        }
        if (problem != null) {
            throw new SQLDataException("Can't write " + table + " row " + rowId + " to ClickHouse: its " + column
                + (value == null ? " " : " (" + show(value) + ") ") + problem);
        }
    }

    /**
     * @return why a value doesn't fit the ClickHouse type, or {@code null} if it does or is NULL
     */
    private static String misfit(String type, Object value) {
        if (value == null) {
            return null;
        }
        switch (type) {
            case "UInt8":
                return wholeNumberMisfit(type, value, 0, 0xffL);
            case "UInt32":
                return wholeNumberMisfit(type, value, 0, 0xffff_ffffL);
            case "UInt64":
                return wholeNumberMisfit(type, value, 0, Long.MAX_VALUE);
            case "Int32":
                return wholeNumberMisfit(type, value, Integer.MIN_VALUE, Integer.MAX_VALUE);
            case "Int64":
                return wholeNumberMisfit(type, value, Long.MIN_VALUE, Long.MAX_VALUE);
            case "Float32":
                if (!(value instanceof Long || value instanceof Double)) {
                    return "isn't a number";
                }
                double number = ((Number) value).doubleValue();
                return Double.isFinite(number) && Float.isInfinite((float) number)
                    ? "is out of range for ClickHouse's Float32" : null;
            case "Float64":
                return value instanceof Long || value instanceof Double ? null : "isn't a number";
            case "String":
                return value instanceof String || value instanceof byte[] ? null : "isn't text or binary data";
            default:
                return null;
        }
    }

    private static String wholeNumberMisfit(String type, Object value, long minimum, long maximum) {
        long number;
        if (value instanceof Long) {
            number = (Long) value;
        } else if (value instanceof Double) {
            double decimal = (Double) value;
            if (decimal != Math.rint(decimal) || decimal < -0x1p63 || decimal >= 0x1p63) {
                return "isn't a whole number, as ClickHouse's " + type + " requires";
            }
            number = (long) decimal;
        } else {
            return "isn't a number, as ClickHouse's " + type + " requires";
        }
        if (number < minimum || number > maximum) {
            return "is out of range for ClickHouse's " + type;
        }
        return null;
    }

    private static String show(Object value) {
        if (value instanceof byte[]) {
            return ((byte[]) value).length + " bytes of binary data";
        }
        if (value instanceof String) {
            String text = (String) value;
            return "'" + (text.length() > 40 ? text.substring(0, 40) + "..." : text) + "'";
        }
        return String.valueOf(value);
    }

    /**
     * Normalize a value from the ClickHouse driver as {@link Row} describes:
     * whole numbers of every width become {@link Long}, {@code Float32}
     * becomes the same {@link Double} the other engines return for it.
     */
    static Object normalize(Object value) throws SQLException {
        if (value == null || value instanceof Long || value instanceof Double
            || value instanceof String || value instanceof byte[]) {
            return value;
        }
        if (value instanceof Integer || value instanceof Short || value instanceof Byte) {
            return ((Number) value).longValue();
        }
        if (value instanceof BigInteger) {
            try {
                return ((BigInteger) value).longValueExact();
            } catch (ArithmeticException e) {
                throw new SQLDataException("ClickHouse value " + value + " doesn't fit a signed 64-bit integer", e);
            }
        }
        if (value instanceof Float) {
            return ((Float) value).doubleValue();
        }
        if (value instanceof Boolean) {
            return ((Boolean) value) ? 1L : 0L;
        }
        throw new SQLDataException("Unexpected ClickHouse value of type " + value.getClass().getName());
    }

    /**
     * Unwrap binary data the way CoreProtect's {@code DatabaseUtils.getBytes}
     * does for its active ClickHouse database, which a migration can't rely
     * on because the database it reads isn't the active one: when the driver
     * reports the column as an array, the value starts with a zero byte that
     * marks it present.
     *
     * @param columnType the column's type from {@link ResultSetMetaData#getColumnType}
     */
    static byte[] unwrapBinary(byte[] value, int columnType, String column) throws SQLException {
        if (columnType != Types.ARRAY || value == null) {
            return value;
        }
        if (value.length == 0) {
            return null;
        }
        if (value[0] != 0) {
            throw new SQLDataException("Invalid ClickHouse binary presence marker for column " + column);
        }
        return Arrays.copyOfRange(value, 1, value.length);
    }

    /**
     * Reads rows of one table from a result set whose first column is the row
     * ID, followed by the requested columns.
     */
    static final class RowReader {
        private final String table;
        private final String[] columns;
        private final int[] columnTypes;
        private final boolean[] binary;
        private final boolean[] emptyForNull;

        RowReader(String table, List<String> columns, ResultSetMetaData metaData) throws SQLException {
            this.table = table;
            this.columns = columns.toArray(new String[0]);
            columnTypes = new int[this.columns.length];
            binary = new boolean[this.columns.length];
            emptyForNull = new boolean[this.columns.length];
            if (metaData.getColumnCount() != this.columns.length + 1) {
                throw new SQLException("Expected " + (this.columns.length + 1) + " columns from ClickHouse table "
                    + table + ", got " + metaData.getColumnCount());
            }
            for (int index = 0; index < this.columns.length; index++) {
                columnTypes[index] = metaData.getColumnType(index + 2);
                binary[index] = isBinary(table, this.columns[index]);
                emptyForNull[index] = isEmptyForNull(table, this.columns[index]);
            }
        }

        /**
         * @return the current row of the result set
         */
        Row read(ResultSet resultSet) throws SQLException {
            long rowId = resultSet.getLong(1);
            if (resultSet.wasNull()) {
                throw new SQLDataException("ClickHouse table " + table + " has a row without a row ID");
            }
            Object[] values = new Object[columns.length];
            for (int index = 0; index < columns.length; index++) {
                int column = index + 2;
                Object value;
                if (binary[index]) {
                    value = unwrapBinary(resultSet.getBytes(column), columnTypes[index], columns[index]);
                } else {
                    value = normalize(resultSet.getObject(column));
                }
                if (emptyForNull[index] && "".equals(value)) {
                    value = null;
                }
                values[index] = value;
            }
            return new Row(rowId, values);
        }
    }
}
