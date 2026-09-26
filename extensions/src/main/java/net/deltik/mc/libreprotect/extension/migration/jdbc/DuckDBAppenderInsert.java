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
import net.deltik.mc.libreprotect.extension.upstream.Names;
import net.deltik.mc.libreprotect.extension.upstream.reflect.InstanceMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamChanged;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;

import java.lang.invoke.MethodHandle;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Inserts rows into DuckDB through its appender, which is dozens of times
 * faster than its JDBC statements. The appender takes every column of the
 * table, in order, each with exactly its type, so values that would need a
 * conversion go through SQL instead.
 *
 * <p>DuckDB's JDBC driver comes from CoreProtect's plugin libraries, in
 * whatever version CoreProtect asks for, so the appender is found by name on
 * the class of DuckDB's connection at hand, unwrapped from a connection that
 * wraps it, whatever its methods return, since newer drivers return the
 * appender for chaining calls. Without it, rows go through SQL, after one
 * note on the console.
 */
public final class DuckDBAppenderInsert implements BulkInsert {

    private enum Type {
        BIGINT, INTEGER, SMALLINT, TINYINT, DOUBLE, FLOAT, VARCHAR, BLOB
    }

    private static final class Column {
        final String name;
        final Type type;

        Column(String name, Type type) {
            this.name = name;
            this.type = type;
        }
    }

    private static final String DRIVER = "DuckDB's JDBC driver";

    private final Upstream driver;
    /** The columns of each table, or {@code null} for tables with a type the appender isn't used for */
    private final Map<String, List<Column>> layouts = new HashMap<>();
    /** The appender of each connection class, or empty where there is none */
    private final Map<Class<?>, Optional<Api>> apis = new HashMap<>();
    /** DuckDB's connection class, to unwrap connections with; empty if the driver has none */
    private Optional<Class<?>> connectionClass;

    public DuckDBAppenderInsert() {
        this(Upstream.coreProtect());
    }

    /**
     * @param driver where DuckDB's driver is, which tests can hide parts of
     */
    public DuckDBAppenderInsert(Upstream driver) {
        this.driver = driver.library(DRIVER);
    }

    /**
     * Check that DuckDB's driver has the appender this uses.
     *
     * @param driver where DuckDB's driver is
     * @param connectionClass the class of DuckDB's connections
     * @throws Missing what the driver lacks
     */
    public static void requireAppender(Upstream driver, Class<?> connectionClass) throws Missing {
        new Api(driver.library(DRIVER), connectionClass);
    }

    @Override
    public boolean insert(Connection connection, String table, List<String> columns, List<Row> rows)
        throws SQLException {
        Object duckDB = unwrap(connection);
        Api api = api(duckDB.getClass());
        if (api == null) {
            return false;
        }
        if (!layouts.containsKey(table)) {
            layouts.put(table, layout(connection, api.schema.get(), table));
        }
        List<Column> layout = layouts.get(table);
        if (layout == null) {
            return false;
        }
        // Where each table column's value comes from: the row ID, a value index, or nowhere (NULL)
        int[] sources = new int[layout.size()];
        int found = 0;
        for (int i = 0; i < layout.size(); i++) {
            String name = layout.get(i).name;
            sources[i] = name.equalsIgnoreCase(Dialect.ROWID) ? -1 : indexOf(columns, name);
            if (sources[i] >= 0) {
                found++;
            }
        }
        if (found != columns.size()) {
            return false;
        }
        for (Row row : rows) {
            for (int i = 0; i < layout.size(); i++) {
                if (!fits(layout.get(i).type, value(row, sources[i]))) {
                    return false;
                }
            }
        }
        try {
            Object appender = (Object) api.createAppender.invokeExact(duckDB, api.schema.get(), table);
            try {
                for (Row row : rows) {
                    api.beginRow.invokeExact(appender);
                    for (int i = 0; i < layout.size(); i++) {
                        append(api, appender, layout.get(i).type, value(row, sources[i]));
                    }
                    api.endRow.invokeExact(appender);
                }
                // Only flush reports a failure, such as a UNIQUE violation; close drops the rows without a word
                api.flush.invokeExact(appender);
            } catch (Throwable e) {
                try {
                    api.close.invokeExact(appender);
                } catch (Throwable closing) {
                    e.addSuppressed(closing);
                }
                throw e;
            }
            api.close.invokeExact(appender);
        } catch (SQLException | RuntimeException | Error e) {
            throw e;
        } catch (Throwable e) {
            throw new SQLException("DuckDB's appender failed: " + e, e);
        }
        return true;
    }

    /**
     * @return DuckDB's own connection behind a connection that wraps one, as
     *         JDBC's {@code unwrap} gives it, or the connection itself
     */
    private Object unwrap(Connection connection) throws SQLException {
        if (connectionClass == null) {
            try {
                connectionClass = Optional.of(driver.type(Names.DUCKDB_CONNECTION).type());
            } catch (Missing e) {
                connectionClass = Optional.empty();
            }
        }
        if (connectionClass.isPresent() && !connectionClass.get().isInstance(connection)
            && connection.isWrapperFor(connectionClass.get())) {
            return connection.unwrap(connectionClass.get());
        }
        return connection;
    }

    /**
     * @return the appender of a connection class, or {@code null} if it has
     *         none, which is noted on the console once
     */
    private Api api(Class<?> connectionClass) {
        Optional<Api> api = apis.get(connectionClass);
        if (api == null) {
            try {
                api = Optional.of(new Api(driver, connectionClass));
            } catch (Missing | UpstreamChanged e) {
                api = Optional.empty();
                LibreProtectLogger.info("DuckDB's appender can't be used (" + e.getMessage() + "), so the"
                    + " migration writes DuckDB with SQL, which is slower.");
            }
            apis.put(connectionClass, api);
        }
        return api.orElse(null);
    }

    private static List<Column> layout(Connection connection, String schema, String table) throws SQLException {
        List<Column> layout = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("SELECT column_name, data_type"
            + " FROM information_schema.columns WHERE table_catalog = current_database()"
            + " AND table_schema = ? AND table_name = ? ORDER BY ordinal_position")) {
            statement.setString(1, schema);
            statement.setString(2, table);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    Type type;
                    try {
                        type = Type.valueOf(result.getString(2).toUpperCase(Locale.ROOT));
                    } catch (IllegalArgumentException e) {
                        return null;
                    }
                    layout.add(new Column(result.getString(1), type));
                }
            }
        }
        return layout.isEmpty() ? null : layout;
    }

    private static int indexOf(List<String> columns, String name) {
        for (int i = 0; i < columns.size(); i++) {
            if (columns.get(i).equalsIgnoreCase(name)) {
                return i;
            }
        }
        return -2;
    }

    private static Object value(Row row, int source) {
        return source == -1 ? (Object) row.rowId() : source >= 0 ? row.values()[source] : null;
    }

    private static boolean fits(Type type, Object value) {
        if (value == null) {
            return true;
        }
        switch (type) {
            case BIGINT:
                return value instanceof Long;
            case INTEGER:
                return value instanceof Long && (Long) value == ((Long) value).intValue();
            case SMALLINT:
                return value instanceof Long && (Long) value == ((Long) value).shortValue();
            case TINYINT:
                return value instanceof Long && (Long) value == ((Long) value).byteValue();
            case DOUBLE:
                return value instanceof Double;
            case FLOAT:
                if (!(value instanceof Double)) {
                    return false;
                }
                double number = (Double) value;
                return (float) number == number || Double.isNaN(number);
            case VARCHAR:
                return value instanceof String;
            case BLOB:
                return value instanceof byte[];
            default:
                return false;
        }
    }

    private static void append(Api api, Object appender, Type type, Object value) throws Throwable {
        if (value == null) {
            api.appendNull.invokeExact(appender);
            return;
        }
        switch (type) {
            case BIGINT:
                api.appendLong.invokeExact(appender, (long) (Long) value);
                break;
            case INTEGER:
                api.appendInt.invokeExact(appender, (int) (long) (Long) value);
                break;
            case SMALLINT:
                api.appendShort.invokeExact(appender, (short) (long) (Long) value);
                break;
            case TINYINT:
                api.appendByte.invokeExact(appender, (byte) (long) (Long) value);
                break;
            case DOUBLE:
                api.appendDouble.invokeExact(appender, (double) (Double) value);
                break;
            case FLOAT:
                api.appendFloat.invokeExact(appender, (float) (double) (Double) value);
                break;
            case VARCHAR:
                api.appendString.invokeExact(appender, (String) value);
                break;
            default:
                api.appendBytes.invokeExact(appender, (byte[]) value);
                break;
        }
    }

    /**
     * DuckDB's appender API, found on a connection class and bound once.
     * Each handle takes the connection or appender as an {@code Object}, and
     * drops what the method returns.
     */
    private static final class Api {
        final MethodHandle createAppender;
        final Supplier<String> schema;
        final MethodHandle beginRow;
        final MethodHandle endRow;
        final MethodHandle appendNull;
        final MethodHandle appendLong;
        final MethodHandle appendInt;
        final MethodHandle appendShort;
        final MethodHandle appendByte;
        final MethodHandle appendDouble;
        final MethodHandle appendFloat;
        final MethodHandle appendString;
        final MethodHandle appendBytes;
        final MethodHandle flush;
        final MethodHandle close;

        Api(Upstream driver, Class<?> connectionClass) throws Missing {
            UpstreamClass connection = driver.type(connectionClass);
            InstanceMethod<Object, RuntimeException> create = connection.method("createAppender", Object.class,
                String.class, String.class);
            // DuckDB's name for the schema that tables are created in
            schema = connection.stringConstant("DEFAULT_SCHEMA", "main");
            UpstreamClass appender = driver.type(create.returnType());
            createAppender = create.exact();
            beginRow = appender.methodIgnoringResult("beginRow").exact();
            endRow = appender.methodIgnoringResult("endRow").exact();
            appendNull = appender.methodIgnoringResult("appendNull").exact();
            appendLong = appender.methodIgnoringResult("append", long.class).exact();
            appendInt = appender.methodIgnoringResult("append", int.class).exact();
            appendShort = appender.methodIgnoringResult("append", short.class).exact();
            appendByte = appender.methodIgnoringResult("append", byte.class).exact();
            appendDouble = appender.methodIgnoringResult("append", double.class).exact();
            appendFloat = appender.methodIgnoringResult("append", float.class).exact();
            appendString = appender.methodIgnoringResult("append", String.class).exact();
            appendBytes = appender.methodIgnoringResult("append", byte[].class).exact();
            flush = appender.methodIgnoringResult("flush").exact();
            close = appender.methodIgnoringResult("close").exact();
        }
    }
}
