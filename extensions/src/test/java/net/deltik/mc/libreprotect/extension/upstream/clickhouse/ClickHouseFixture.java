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
import net.deltik.mc.libreprotect.extension.migration.TableStats;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Rows of every CoreProtect table except {@code database_lock}, as a
 * relational source hands them to the ClickHouse sink (with binary data,
 * NULLs, unicode, row ID gaps and legacy encodings), and as they read back
 * from ClickHouse.
 */
final class ClickHouseFixture {

    static final String CORE_VERSION = "2.24.1";
    static final long BLOCK_HIGH_WATER = 5_000_000_100L;
    static final long CHAT_HIGH_WATER = 900;
    static final long USER_HIGH_WATER = 50;

    /**
     * Whether CoreProtect rolls signs back, which put {@code rolled_back} on
     * its sign table as on block's
     */
    static final boolean SIGN_ROLLBACKS =
        Upstream.coreProtect().has("net.coreprotect.model.rollback.RollbackUpdateTargets#SIGN");

    /** Each table's columns, in the view's order */
    final Map<String, List<String>> columns = new LinkedHashMap<>();
    /** What the source hands over */
    final Map<String, List<Row>> written = new LinkedHashMap<>();
    /** What reads back; ClickHouse keeps its own version row, so not {@code version} */
    final Map<String, List<Row>> expected = new LinkedHashMap<>();
    /** The source's high-water marks */
    final Map<String, Long> highWater = new LinkedHashMap<>();

    ClickHouseFixture() throws Exception {
        UpstreamCodecs codecs = new UpstreamCodecs();
        byte[] legacyMeta = javaSerialized(new ArrayList<>(Arrays.asList("minecraft:chest", 3,
            new ArrayList<>(Arrays.asList("a", "b")))));
        byte[] encodedMeta = codecs.encodeMeta(new ArrayList<>(Arrays.asList("minecraft:sign", 1)));
        byte[] rawMeta = {0, -1, 65};
        byte[] legacyEntity = javaSerialized(new ArrayList<>(Arrays.asList("minecraft:zombie", 20, 1.5)));
        byte[] encodedEntity = codecs.encodeEntity("ENTITY", List.of("minecraft:cow", 7));
        byte[] encodedSpawn = codecs.encodeEntity("ENTITY_SPAWN", List.of("minecraft:pig"));
        byte[] legacySpawn = javaSerialized(new ArrayList<>(Arrays.asList("minecraft:sheep", "WHITE")));
        String longText = "Ünïcødé ☃ 😀 \"quoted\" 'single' \\ ".repeat(400);

        table("art_map", List.of("id", "art"),
            row(1, 1L, "Kebab"),
            row(3, 2L, "Ünïcødé"));
        table("block", List.of("time", "user", "wid", "x", "y", "z", "type", "data", "meta", "blockdata", "action",
                "rolled_back"),
            row(2, 1_700_000_000L, 3L, 1L, -5L, 64L, 7L, 12L, -9L, rawMeta, "1,2".getBytes(), 1L, 0L),
            row(3, 1_700_000_001L, 3L, 1L, -5L, null, 7L, 12L, 0L, null, new byte[0], 0L, 1L),
            row(10, 1_700_000_002L, 4L, 2L, 100L, -64L, -100L, 54L, 1L, legacyMeta, null, 1L, 0L),
            row(4_000_000_000L, 1_600_000_000L, 5L, 1L, 0L, 0L, 0L, 54L, 2L, encodedMeta, null, 0L, 0L));
        expect("block", 10, 8, codecs.forClickHouse("block", legacyMeta));
        expect("block", 4_000_000_000L, 8, codecs.forClickHouse("block", encodedMeta));
        table("chat", List.of("time", "user", "wid", "x", "y", "z", "message"),
            row(1, 1_700_000_000L, 1L, 1L, 0L, 64L, 0L, "hello"),
            row(7, 1_700_000_001L, 2L, 1L, 0L, 64L, 0L, longText),
            row(800, 1_700_000_002L, 2L, 1L, 0L, 64L, 0L, ""));
        table("command", List.of("time", "user", "wid", "x", "y", "z", "message"),
            row(4, 1_700_000_000L, 1L, null, null, null, null, "/co i"));
        table("container", List.of("time", "user", "wid", "x", "y", "z", "type", "data", "amount", "metadata",
                "action", "rolled_back"),
            row(1, 1_700_000_000L, 1L, 1L, 0L, 64L, 0L, 99L, 0L, 64L, new byte[]{1, 2, 3}, 0L, 0L),
            row(2, 1_700_000_000L, 1L, 1L, 0L, 64L, 0L, 99L, 0L, 1L, null, 1L, 1L));
        table("entity_container", List.of("time", "user", "entity_spawn_rowid", "wid", "x", "y", "z", "type",
                "data", "amount", "metadata", "action", "rolled_back"),
            row(5, 1_700_000_000L, 1L, 2L, 1L, 0L, 64L, 0L, 99L, 0L, 1L, new byte[]{0}, 0L, 0L));
        table("entity_interaction", List.of("time", "user", "entity_spawn_rowid", "wid", "x", "y", "z", "type",
                "action", "metadata", "rolled_back"),
            row(6, 1_700_000_000L, 1L, 2L, 1L, 0L, 64L, 0L, 7L, 1L, null, 0L));
        table("item", List.of("time", "user", "wid", "x", "y", "z", "type", "data", "amount", "action",
                "rolled_back"),
            row(3, 1_700_000_000L, 1L, 1L, 0L, 64L, 0L, 99L, new byte[]{9, 8}, 2L, 2L, 0L));
        table("entity", List.of("time", "data"),
            row(1, 1_700_000_000L, encodedEntity),
            row(2, 1_700_000_001L, legacyEntity),
            row(3, 1_700_000_002L, null));
        expect("entity", 2, 1, codecs.forClickHouse("entity", legacyEntity));
        table("entity_spawn", List.of("time", "block_rowid", "kill_rowid", "uuid", "wid", "current_wid",
                "origin_x", "origin_y", "origin_z", "x", "y", "z", "yaw", "pitch", "data", "removed"),
            row(2, 1_700_000_000L, 10L, null, "5a1e6f7c-8d9e-4f00-9a1b-2c3d4e5f6071", 1L, 1L, 1.5, 64.0, -3.5,
                1.25, 65.0, -3.75, 90.5, -12.25, encodedSpawn, 0L),
            row(4, 1_700_000_001L, null, 1L, "6b2f7a8d-9eaf-4011-8b2c-3d4e5f607182", 2L, 1L, -0.5, 0.0, 0.25,
                -0.5, 0.0, 0.25, 0.0, 0.0, legacySpawn, 1L),
            row(5, 1_700_000_002L, null, null, "7c3a8b9e-af00-4122-9c3d-4e5f60718293", 1L, 2L, 0.0, 0.0, 0.0,
                0.0, 0.0, 0.0, 0.0, 0.0, null, 0L));
        expect("entity_spawn", 4, 14, codecs.forClickHouse("entity_spawn", legacySpawn));
        table("entity_map", List.of("id", "entity"),
            row(1, 1L, "minecraft:zombie"));
        // A row ID that ran ahead of its identifier, as MySQL's can
        table("material_map", List.of("id", "material"),
            row(1, 1L, "minecraft:stone"),
            row(7, 2L, "minecraft:dirt"));
        table("blockdata_map", List.of("id", "data"),
            row(1, 1L, "minecraft:oak_log[axis=y]"));
        table("session", List.of("time", "user", "wid", "x", "y", "z", "action"),
            row(1, 1_700_000_000L, 1L, 1L, 0L, 64L, 0L, 1L));
        table("sign", List.of("time", "user", "wid", "x", "y", "z", "action", "color", "color_secondary", "data",
                "waxed", "face", "line_1", "line_2", "line_3", "line_4", "line_5", "line_6", "line_7", "line_8"),
            row(3, 1_700_000_000L, 1L, 1L, 0L, 64L, 0L, 1L, 16_777_215L, 0L, 1L, 0L, 1L, "Line ☃", "", null,
                "4", "5", "6", "7", longText.substring(0, 16)),
            row(4, 1_700_000_001L, 2L, 1L, 0L, 64L, 0L, 1L, 0L, 0L, 0L, 0L, 1L, "Rolled back", null, null, null,
                "", "", "", ""));
        if (SIGN_ROLLBACKS) {
            column("sign", "rolled_back", 0L, 1L);
        }
        table("skull", List.of("time", "owner", "skin"),
            row(1, 1_700_000_000L, "Notch", longText),
            row(2, 1_700_000_000L, null, null));
        table("user", List.of("time", "user", "uuid"),
            row(1, 1_600_000_000L, "Notch", "069a79f4-44e9-4726-a5be-fca90e38aaf5"),
            row(2, 1_600_000_001L, "#fire", null),
            row(3, 1_600_000_002L, "Stéve", ""));
        expect("user", 3, 2, null);
        table("username_log", List.of("time", "uuid", "user"),
            row(1, 1_600_000_000L, "069a79f4-44e9-4726-a5be-fca90e38aaf5", "Notch"),
            row(2, 1_600_000_001L, "", "Nobody"));
        expect("username_log", 2, 1, null);
        table("version", List.of("time", "version"),
            row(1, 1_500_000_000L, "2.20.0"),
            row(2, 1_600_000_000L, "2.24.1"));
        expected.remove("version");
        table("world", List.of("id", "world"),
            row(1, 1L, "world"),
            row(2, 2L, "world_nether"));

        for (Map.Entry<String, List<Row>> entry : written.entrySet()) {
            highWater.put(entry.getKey(), stats(entry.getValue()).maxRowId());
        }
        highWater.put("block", BLOCK_HIGH_WATER);
        highWater.put("chat", CHAT_HIGH_WATER);
        highWater.put("user", USER_HIGH_WATER);
        highWater.put("version", 30L);
    }

    static TableStats stats(List<Row> rows) {
        long min = Long.MAX_VALUE;
        long max = 0;
        for (Row row : rows) {
            min = Math.min(min, row.rowId());
            max = Math.max(max, row.rowId());
        }
        return rows.isEmpty() ? new TableStats(0, 0, 0) : new TableStats(rows.size(), min, max);
    }

    private void table(String table, List<String> tableColumns, Row... rows) {
        columns.put(table, tableColumns);
        written.put(table, List.of(rows));
        List<Row> copies = new ArrayList<>();
        for (Row row : rows) {
            copies.add(new Row(row.rowId(), row.values().clone()));
        }
        expected.put(table, copies);
    }

    /**
     * Add a column to a table, with a value for each of its rows in turn
     */
    private void column(String table, String column, Object... values) {
        List<String> tableColumns = new ArrayList<>(columns.get(table));
        tableColumns.add(column);
        columns.put(table, tableColumns);
        written.put(table, withColumn(written.get(table), values));
        expected.put(table, withColumn(expected.get(table), values));
    }

    private static List<Row> withColumn(List<Row> rows, Object... values) {
        if (rows.size() != values.length) {
            throw new IllegalArgumentException(rows.size() + " rows but " + values.length + " values");
        }
        List<Row> extended = new ArrayList<>();
        for (int index = 0; index < rows.size(); index++) {
            Row row = rows.get(index);
            Object[] rowValues = Arrays.copyOf(row.values(), row.values().length + 1);
            rowValues[rowValues.length - 1] = values[index];
            extended.add(new Row(row.rowId(), rowValues));
        }
        return extended;
    }

    /**
     * Expect a different value to read back than was written
     */
    private void expect(String table, long rowId, int column, Object value) {
        for (Row row : expected.get(table)) {
            if (row.rowId() == rowId) {
                row.values()[column] = value;
                return;
            }
        }
        throw new IllegalArgumentException("No " + table + " row " + rowId);
    }

    private static Row row(long rowId, Object... values) {
        return new Row(rowId, values);
    }

    static byte[] javaSerialized(Object value) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream output = new ObjectOutputStream(bytes)) {
            output.writeObject(value);
        }
        return bytes.toByteArray();
    }
}
