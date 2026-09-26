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

package net.deltik.mc.libreprotect.extension.upstream;

import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Shape;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamChanged;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamEnum;
import net.deltik.mc.libreprotect.testutil.AssumeCapability;
import net.deltik.mc.libreprotect.testutil.CoreProtectFixture;
import org.bukkit.DyeColor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.sql.SQLDataException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Conversions between the legacy encoding of SQLite and MySQL and the
 * canonical one of DuckDB and ClickHouse, with upstream's own codecs and
 * serialization; only on a CoreProtect with columnar engines.
 */
class CodecsTest {

    @RegisterExtension
    final CoreProtectFixture coreProtect = new CoreProtectFixture();

    private Codecs codecs;
    /** Upstream's serialization and codecs, which the tests check the conversions with */
    private UpstreamEnum types;
    private UpstreamEnum kinds;
    private StaticMethod<byte[], RuntimeException> serializeData;
    private StaticMethod<byte[], RuntimeException> serializeMetadata;
    private StaticMethod<Object, RuntimeException> decodeData;
    private StaticMethod<byte[], Exception> dataFromLegacy;
    private StaticMethod<Boolean, RuntimeException> metaIsEncoded;
    private StaticMethod<Object, RuntimeException> decodeMeta;
    private StaticMethod<Object, Exception> decodeLegacyMeta;

    @BeforeEach
    void upstream() throws Exception {
        AssumeCapability.strategy("migrate-db.transcoding", "statement-codecs");
        codecs = Capabilities.current().require(Codecs.CAPABILITY);
        coreProtect.set("Config.ERROR_REPORTING", false);
        Upstream upstream = Upstream.coreProtect();
        types = upstream.type(Names.DATABASE_TYPE).asEnum();
        kinds = upstream.type(Names.ENTITY_DATA_CODEC + "$Kind").asEnum();
        Shape type = Shape.enumWith("SQLITE");
        Shape kind = Shape.enumWith("ENTITY");
        serializeData = upstream.type(Names.ENTITY_STATEMENT).staticMethodShaped("serializeData", byte[].class,
            Shape.exactly(List.class), kind, type);
        serializeMetadata = upstream.type(Names.BLOCK_STATEMENT).staticMethodShaped("serializeMetadata",
            byte[].class, Shape.exactly(List.class), type);
        UpstreamClass entityCodec = upstream.type(Names.ENTITY_DATA_CODEC);
        decodeData = entityCodec.staticMethodShaped("decode", Object.class, kind, Shape.exactly(byte[].class));
        dataFromLegacy = entityCodec.staticMethodShaped("fromLegacy", byte[].class, kind,
            Shape.exactly(byte[].class)).throwing(Exception.class);
        UpstreamClass metaCodec = upstream.type(Names.BLOCK_META_CODEC);
        metaIsEncoded = metaCodec.staticMethod("isEncoded", boolean.class, byte[].class);
        decodeMeta = metaCodec.staticMethod("decode", Object.class, byte[].class);
        decodeLegacyMeta = metaCodec.staticMethod("decodeLegacy", Object.class, byte[].class)
            .throwing(Exception.class);
    }

    /** Entity data the way CoreProtect's entity kill logger builds it: age, tame, info, name, attributes, details */
    private static List<Object> entityData() {
        List<Object> attributes = new ArrayList<>();
        attributes.add(Arrays.asList("minecraft:generic.max_health", 10.0, new ArrayList<>()));
        attributes.add(Arrays.asList("minecraft:generic.movement_speed", 0.25, new ArrayList<>()));
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("variant", "temperate");
        details.put("saddled", false);
        List<Object> data = new ArrayList<>();
        data.add(Arrays.asList(-24000, true, false));
        data.add(Arrays.asList(false, null));
        data.add(Arrays.asList("WHITE", 3));
        data.add(true);
        data.add("Bessie éè 🐄");
        data.add(attributes);
        data.add(Arrays.asList(details, 7L, 1.5f, (short) 2, (byte) 1));
        return data;
    }

    /** Block metadata the way CoreProtect's block utilities build it: a command, or a banner's patterns */
    private static List<Object> blockMeta(boolean banner) {
        List<Object> meta = new ArrayList<>();
        if (banner) {
            meta.add(DyeColor.RED);
            Map<String, Object> pattern = new LinkedHashMap<>();
            pattern.put("color", "BLUE");
            pattern.put("pattern", "cr");
            meta.add(pattern);
        } else {
            meta.add("say Hello from a command block, ünïcödé 🙂");
        }
        return meta;
    }

    @Nested
    @DisplayName("entity data")
    class EntityData {

        @ParameterizedTest
        @ValueSource(strings = {"ENTITY", "ENTITY_SPAWN"})
        @DisplayName("should convert legacy data for columnar engines and back, keeping its content")
        void roundTrip(String kindName) throws Exception {
            Enum<?> kind = kinds.constant(kindName);
            String table = kindName.toLowerCase();
            byte[] legacy = serializeData.call(entityData(), kind, types.constant("SQLITE"));
            assertNotNull(legacy);
            assertFalse(codecs.isEncoded(legacy));

            byte[] columnar = (byte[]) codecs.transcode(table, "data", legacy, Engine.SQLITE, Engine.DUCKDB);
            byte[] back = (byte[]) codecs.transcode(table, "data", columnar, Engine.DUCKDB, Engine.MYSQL);

            assertTrue(codecs.isEncoded(columnar));
            assertFalse(codecs.isEncoded(back));
            assertEquals(decodeData.call(kind, columnar), decodeData.call(kind, dataFromLegacy.call(kind, back)));
            assertArrayEquals((byte[]) codecs.canonical(table, "data", legacy),
                (byte[]) codecs.canonical(table, "data", back));
            assertArrayEquals(columnar, (byte[]) codecs.canonical(table, "data", columnar));
        }
    }

    @Nested
    @DisplayName("block metadata")
    class BlockMeta {

        @ParameterizedTest(name = "banner {0}")
        @ValueSource(booleans = {false, true})
        @DisplayName("should convert legacy metadata for columnar engines and back, keeping its content")
        void roundTrip(boolean banner) throws Exception {
            byte[] legacy = serializeMetadata.call(blockMeta(banner), types.constant("MYSQL"));
            assertNotNull(legacy);
            assertFalse(metaIsEncoded.call((Object) legacy));

            byte[] columnar = (byte[]) codecs.transcode("block", "meta", legacy, Engine.MYSQL, Engine.CLICKHOUSE);
            byte[] back = (byte[]) codecs.transcode("block", "meta", columnar, Engine.CLICKHOUSE, Engine.SQLITE);

            assertTrue(metaIsEncoded.call((Object) columnar));
            assertFalse(metaIsEncoded.call((Object) back));
            assertEquals(decodeMeta.call((Object) columnar), decodeLegacyMeta.call((Object) back));
            assertArrayEquals((byte[]) codecs.canonical("block", "meta", legacy),
                (byte[]) codecs.canonical("block", "meta", back));
        }
    }

    @Test
    @DisplayName("should pass values through between engines of one encoding, and columns without an encoding")
    void passThrough() throws Exception {
        byte[] legacy = serializeData.call(entityData(), kinds.constant("ENTITY"), types.constant("SQLITE"));

        assertSame(legacy, codecs.transcode("entity", "data", legacy, Engine.SQLITE, Engine.MYSQL));
        assertSame(legacy, codecs.transcode("entity", "data", legacy, Engine.DUCKDB, Engine.CLICKHOUSE));
        assertSame(legacy, codecs.transcode("container", "metadata", legacy, Engine.SQLITE, Engine.DUCKDB));
        assertSame(legacy, codecs.canonical("item", "data", legacy));
        assertNull(codecs.transcode("entity", "data", null, Engine.SQLITE, Engine.DUCKDB));
        assertTrue(Codecs.isEncodedColumn("entity_spawn", "DATA"));
        assertFalse(Codecs.isEncodedColumn("item", "data"));
    }

    @Test
    @DisplayName("should refuse, with a reason, data that upstream's codec can't read")
    void unreadable() {
        byte[] garbage = {(byte) 0xAC, (byte) 0xED, 0, 5, 1, 2, 3};

        SQLDataException error = assertThrows(SQLDataException.class,
            () -> codecs.transcode("entity", "data", garbage, Engine.SQLITE, Engine.DUCKDB));

        assertTrue(error.getMessage().startsWith("CoreProtect can't convert entity.data for DuckDB"), error.getMessage());
        assertThrows(SQLDataException.class, () -> codecs.canonical("block", "meta", garbage));
    }

    @Nested
    @DisplayName("a conversion")
    class Converting {

        @Test
        @DisplayName("should blame the value for what CoreProtect's conversion throws")
        void refused() {
            IllegalArgumentException refusal = new IllegalArgumentException("Unknown entity data version 9");

            SQLDataException error = assertThrows(SQLDataException.class,
                () -> Codecs.converting("entity", "data", Engine.CLICKHOUSE, () -> {
                    throw refusal;
                }));

            assertEquals("CoreProtect can't convert entity.data for ClickHouse: " + refusal, error.getMessage());
            assertSame(refusal, error.getCause());
        }

        @Test
        @DisplayName("should let a change of CoreProtect through as it is, naming what changed, not blame the value")
        void upstreamChanged() {
            // As when a conversion's handle can't be made the first time a migration converts a value
            UpstreamChanged changed = new UpstreamChanged("CoreProtect's BlockStatement.transcodeMetadata(byte[], an"
                + " enum with SQLITE, MYSQL) can't be reached: java.lang.NoSuchMethodException");

            assertSame(changed, assertThrows(UpstreamChanged.class,
                () -> Codecs.converting("block", "meta", Engine.DUCKDB, () -> {
                    throw changed;
                })));
        }
    }
}
