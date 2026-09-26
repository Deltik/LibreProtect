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

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.SQLDataException;
import java.sql.SQLException;
import java.util.Arrays;

/**
 * Column values in the engine-neutral form that {@link Row} describes, and
 * comparing them across engines.
 */
public final class Values {

    private Values() {
    }

    /**
     * @return a value read through JDBC in {@link Row}'s normalized form:
     *         {@link Long}, {@link Double}, {@link String}, {@code byte[]} or
     *         {@code null}
     * @throws SQLDataException for values that CoreProtect never stores, such
     *                          as dates, which a migration shouldn't guess at
     */
    public static Object normalize(Object value) throws SQLException {
        if (value == null || value instanceof Long || value instanceof Double || value instanceof String
            || value instanceof byte[]) {
            return value;
        }
        if (value instanceof Integer || value instanceof Short || value instanceof Byte) {
            return ((Number) value).longValue();
        }
        if (value instanceof Float) {
            return ((Float) value).doubleValue();
        }
        if (value instanceof Boolean) {
            return (Boolean) value ? 1L : 0L;
        }
        if (value instanceof BigInteger) {
            try {
                return ((BigInteger) value).longValueExact();
            } catch (ArithmeticException e) {
                throw new SQLDataException("Integer " + value + " doesn't fit in 64 bits", e);
            }
        }
        if (value instanceof BigDecimal) {
            BigDecimal decimal = (BigDecimal) value;
            try {
                if (decimal.stripTrailingZeros().scale() <= 0) {
                    return decimal.longValueExact();
                }
                return decimal.doubleValue();
            } catch (ArithmeticException e) {
                throw new SQLDataException("Number " + value + " doesn't fit in 64 bits", e);
            }
        }
        if (value instanceof Blob) {
            Blob blob = (Blob) value;
            long length = blob.length();
            if (length > Integer.MAX_VALUE) {
                throw new SQLDataException("Binary value of " + length + " bytes is too large");
            }
            return blob.getBytes(1, (int) length);
        }
        if (value instanceof Clob) {
            Clob clob = (Clob) value;
            long length = clob.length();
            if (length > Integer.MAX_VALUE) {
                throw new SQLDataException("Text value of " + length + " characters is too large");
            }
            return clob.getSubString(1, (int) length);
        }
        throw new SQLDataException("Unexpected value of type " + value.getClass().getName());
    }

    /**
     * Whether two normalized values hold the same data. Engines differ in
     * how they type a value, so text and binary are the same if the text's
     * UTF-8 encoding is the binary, and whole and fractional numbers are the
     * same if they're numerically equal.
     */
    public static boolean same(Object a, Object b) {
        if (a == null || b == null) {
            return a == b;
        }
        if (a instanceof byte[] && b instanceof byte[]) {
            return Arrays.equals((byte[]) a, (byte[]) b);
        }
        if (a instanceof String && b instanceof byte[]) {
            return Arrays.equals(((String) a).getBytes(StandardCharsets.UTF_8), (byte[]) b);
        }
        if (a instanceof byte[] && b instanceof String) {
            return same(b, a);
        }
        if (a instanceof Long && b instanceof Long) {
            return a.equals(b);
        }
        if (a instanceof Number && b instanceof Number) {
            if (a instanceof Long || b instanceof Long) {
                long whole = ((Number) (a instanceof Long ? a : b)).longValue();
                double fraction = ((Number) (a instanceof Long ? b : a)).doubleValue();
                return !Double.isNaN(fraction) && !Double.isInfinite(fraction)
                    && new BigDecimal(fraction).compareTo(BigDecimal.valueOf(whole)) == 0;
            }
            double x = ((Number) a).doubleValue();
            double y = ((Number) b).doubleValue();
            return x == y || (Double.isNaN(x) && Double.isNaN(y));
        }
        return a.equals(b);
    }

    /**
     * @return a short description of a value for messages
     */
    static String describe(Object value) {
        if (value == null) {
            return "NULL";
        }
        if (value instanceof byte[]) {
            return ((byte[]) value).length + " bytes";
        }
        if (value instanceof String) {
            String text = (String) value;
            return "'" + (text.length() > 40 ? text.substring(0, 40) + "…" : text) + "'";
        }
        return String.valueOf(value);
    }
}
