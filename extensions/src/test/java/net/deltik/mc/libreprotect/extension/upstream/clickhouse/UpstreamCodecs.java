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

import net.deltik.mc.libreprotect.extension.upstream.Names;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Shape;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamEnum;

import java.util.List;
import java.util.Locale;

/**
 * CoreProtect 25's own encodings of block metadata and entity data, called
 * directly, not through LibreProtect's {@code Codecs}, for the values that
 * tests write and expect: its serialization for SQLite and MySQL, its
 * columnar codecs, and its conversion for ClickHouse.
 */
final class UpstreamCodecs {

    private final UpstreamEnum types;
    private final UpstreamEnum kinds;
    private final StaticMethod<byte[], RuntimeException> encodeMeta;
    private final StaticMethod<byte[], RuntimeException> encodeEntity;
    private final StaticMethod<Object, RuntimeException> decodeEntity;
    private final StaticMethod<Boolean, RuntimeException> isEncoded;
    private final StaticMethod<byte[], RuntimeException> serializeMeta;
    private final StaticMethod<byte[], RuntimeException> serializeEntity;
    private final StaticMethod<byte[], Exception> transcodeMetadata;
    private final StaticMethod<byte[], Exception> transcodeData;

    UpstreamCodecs() throws Missing {
        Upstream upstream = Upstream.coreProtect();
        types = upstream.type(Names.DATABASE_TYPE).asEnum();
        kinds = upstream.type(Names.ENTITY_DATA_CODEC + "$Kind").asEnum();
        Shape kind = Shape.enumWith("ENTITY", "ENTITY_SPAWN");
        Shape type = Shape.enumWith("SQLITE", "MYSQL");
        encodeMeta = upstream.type(Names.BLOCK_META_CODEC).staticMethod("encode", byte[].class, List.class);
        encodeEntity = upstream.type(Names.ENTITY_DATA_CODEC).staticMethodShaped("encode", byte[].class, kind,
            Shape.exactly(List.class));
        decodeEntity = upstream.type(Names.ENTITY_DATA_CODEC).staticMethodShaped("decode", Object.class, kind,
            Shape.exactly(byte[].class));
        isEncoded = upstream.type(Names.ENTITY_DATA_CODEC).staticMethod("isEncoded", boolean.class, byte[].class);
        serializeMeta = upstream.type(Names.BLOCK_STATEMENT).staticMethodShaped("serializeMetadata", byte[].class,
            Shape.exactly(List.class), type);
        serializeEntity = upstream.type(Names.ENTITY_STATEMENT).staticMethodShaped("serializeData", byte[].class,
            Shape.exactly(List.class), kind, type);
        transcodeMetadata = upstream.type(Names.BLOCK_STATEMENT).staticMethodShaped("transcodeMetadata",
            byte[].class, Shape.exactly(byte[].class), type).throwing(Exception.class);
        transcodeData = upstream.type(Names.ENTITY_STATEMENT).staticMethodShaped("transcodeData", byte[].class,
            Shape.exactly(byte[].class), kind, type).throwing(Exception.class);
    }

    /**
     * @return block metadata in CoreProtect's columnar encoding ({@code BlockMetaCodec.encode})
     */
    byte[] encodeMeta(List<?> meta) {
        return encodeMeta.call(meta);
    }

    /**
     * @param kind {@code ENTITY} or {@code ENTITY_SPAWN}
     * @return entity data in CoreProtect's columnar encoding ({@code EntityDataCodec.encode})
     */
    byte[] encodeEntity(String kind, List<?> data) {
        return encodeEntity.call(kinds.constant(kind), data);
    }

    /**
     * @return entity data from CoreProtect's columnar encoding ({@code EntityDataCodec.decode})
     */
    Object decodeEntity(String kind, byte[] data) {
        return decodeEntity.call(kinds.constant(kind), data);
    }

    /**
     * @return whether entity data is in CoreProtect's columnar encoding ({@code EntityDataCodec.isEncoded})
     */
    boolean isEncoded(byte[] entityData) {
        return isEncoded.call((Object) entityData);
    }

    /**
     * @return block metadata as CoreProtect stores it in SQLite ({@code BlockStatement.serializeMetadata})
     */
    byte[] serializeMetaForSqlite(List<?> meta) {
        return serializeMeta.call(meta, types.constant("SQLITE"));
    }

    /**
     * @return entity data as CoreProtect stores it in SQLite ({@code EntityStatement.serializeData})
     */
    byte[] serializeEntityForSqlite(List<?> data, String kind) {
        return serializeEntity.call(data, kinds.constant(kind), types.constant("SQLITE"));
    }

    /**
     * @param table {@code block} for block metadata, or {@code entity} or
     *              {@code entity_spawn} for entity data
     * @return a value as CoreProtect converts it for ClickHouse
     *         ({@code BlockStatement.transcodeMetadata},
     *         {@code EntityStatement.transcodeData})
     */
    byte[] forClickHouse(String table, byte[] value) throws Exception {
        Object clickHouse = types.constant("CLICKHOUSE");
        if (table.equals("block")) {
            return transcodeMetadata.call(value, clickHouse);
        }
        return transcodeData.call(value, kinds.constant(table.toUpperCase(Locale.ROOT)), clickHouse);
    }
}
