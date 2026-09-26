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

import java.util.Arrays;

/**
 * One row of a CoreProtect table: its row ID and its other column values, in
 * the order of the column list it was read with.
 *
 * <p>Values are normalized across engines: whole numbers are {@link Long},
 * other numbers {@link Double}, text is {@link String}, binary data is
 * {@code byte[]}, and SQL NULL is {@code null}. Binary data is in the
 * encoding of the engine it was read from; the copier converts it for the
 * target (see {@link MigrationBridge#transcode}).
 */
public final class Row {

    private final long rowId;
    private final Object[] values;

    public Row(long rowId, Object[] values) {
        this.rowId = rowId;
        this.values = values;
    }

    public long rowId() {
        return rowId;
    }

    /**
     * @return the column values; the array is shared, not copied
     */
    public Object[] values() {
        return values;
    }

    @Override
    public String toString() {
        return "Row{" + rowId + ", " + Arrays.deepToString(values) + "}";
    }
}
