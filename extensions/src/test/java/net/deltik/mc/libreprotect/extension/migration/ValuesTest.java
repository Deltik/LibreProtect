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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.sql.SQLDataException;
import java.sql.Timestamp;

import static org.junit.jupiter.api.Assertions.*;

class ValuesTest {

    @Test
    @DisplayName("should normalize what JDBC drivers return to Long, Double, String, byte[] or null")
    void normalizes() throws Exception {
        assertEquals(7L, Values.normalize(7));
        assertEquals(7L, Values.normalize((short) 7));
        assertEquals(-7L, Values.normalize((byte) -7));
        assertEquals(1L, Values.normalize(Boolean.TRUE));
        assertEquals(Long.MAX_VALUE, Values.normalize(BigInteger.valueOf(Long.MAX_VALUE)));
        assertEquals(12L, Values.normalize(new BigDecimal("12.000")));
        assertEquals(1.5, Values.normalize(new BigDecimal("1.5")));
        assertEquals(1.5, Values.normalize(1.5f));
        assertEquals((double) 0.1f, Values.normalize(0.1f));
        assertEquals("text", Values.normalize("text"));
        assertNull(Values.normalize(null));
    }

    @Test
    @DisplayName("should refuse values that CoreProtect never stores, or that don't fit")
    void refuses() {
        assertThrows(SQLDataException.class, () -> Values.normalize(new Timestamp(0)));
        assertThrows(SQLDataException.class, () -> Values.normalize(BigInteger.ONE.shiftLeft(64)));
    }

    @Test
    @DisplayName("should compare values across the engines' typing")
    void compares() {
        assertTrue(Values.same(null, null));
        assertFalse(Values.same(null, 0L));
        assertFalse(Values.same("", null));
        assertTrue(Values.same(5L, 5L));
        assertFalse(Values.same(5L, 6L));
        assertTrue(Values.same(5L, 5.0));
        assertFalse(Values.same(5L, 5.5));
        assertTrue(Values.same(Double.NaN, Double.NaN));
        assertTrue(Values.same(0.0, -0.0));
        assertFalse(Values.same(0.1, (double) 0.1f));
        assertTrue(Values.same(new byte[]{1, 2}, new byte[]{1, 2}));
        assertFalse(Values.same(new byte[]{1, 2}, new byte[]{1, 3}));
        assertTrue(Values.same("名前🙂", "名前🙂".getBytes(StandardCharsets.UTF_8)));
        assertTrue(Values.same("名前🙂".getBytes(StandardCharsets.UTF_8), "名前🙂"));
        assertFalse(Values.same("5", 5L));
        assertTrue(Values.same(Long.MAX_VALUE, Long.MAX_VALUE));
        assertFalse(Values.same(Long.MAX_VALUE, (double) Long.MAX_VALUE));
    }
}
