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
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Shape;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamChanged;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamEnum;

import java.sql.SQLDataException;
import java.sql.SQLException;

/**
 * CoreProtect's conversions of entity data and block metadata between the
 * legacy encoding of SQLite and MySQL and the columnar one of DuckDB and
 * ClickHouse. CoreProtect without a columnar engine has one encoding, so
 * this capability is absent there, and values pass through.
 *
 * <p>Which columns are encoded is LibreProtect's contract, not something
 * CoreProtect lists: {@code block.meta}, {@code entity.data} and
 * {@code entity_spawn.data}. The canonical encoding, for comparing values
 * across engines, is the columnar one.
 *
 * <p>The report's {@code relies} lines follow a conversion from
 * {@code transcodeMetadata} and {@code transcodeData} into each codec's
 * methods that choose and convert the encoding. The binary readers and
 * writers under those are the encodings themselves, which the round-trip
 * tests check instead.
 */
public final class Codecs {

    public static final Capability<Codecs> CAPABILITY = Capability.of("migrate-db.transcoding",
        Choice.way("statement-codecs", "CoreProtect's conversions between its legacy and columnar encodings",
            Codecs::new));

    /** A parameter of CoreProtect's engine enum */
    private static final Shape ENGINE = Shape.enumWith("SQLITE", "MYSQL");

    private final StaticMethod<byte[], Exception> transcodeMetadata;
    private final StaticMethod<byte[], Exception> transcodeData;
    private final StaticMethod<Boolean, RuntimeException> isEncoded;
    private final UpstreamEnum engines;
    private final UpstreamEnum kinds;
    private final Engine canonical;

    private Codecs(Upstream upstream) throws Missing {
        // Only CoreProtect's multi-engine layer has columnar engines
        Designs.MULTI_ENGINE.requireIn(upstream);
        // Only migrations convert, and every migration needs the protocol
        MigrationProtocol.CAPABILITY.probe(upstream).require();
        transcodeMetadata = upstream.type(Names.BLOCK_STATEMENT).staticMethodShaped("transcodeMetadata",
            byte[].class, Shape.exactly(byte[].class), ENGINE).throwing(Exception.class);
        engines = upstream.type(transcodeMetadata.parameterType(1)).asEnum();
        transcodeData = upstream.type(Names.ENTITY_STATEMENT).staticMethodShaped("transcodeData", byte[].class,
            Shape.exactly(byte[].class), Shape.enumWith("ENTITY", "ENTITY_SPAWN"), ENGINE)
            .throwing(Exception.class);
        kinds = upstream.type(transcodeData.parameterType(1)).asEnum();
        if (transcodeData.parameterType(2) != engines.type()) {
            throw new Missing(upstream.name() + "'s " + transcodeData + " and " + transcodeMetadata
                + " take different engine types");
        }
        isEncoded = upstream.type(Names.ENTITY_DATA_CODEC).staticMethod("isEncoded", boolean.class, byte[].class);
        canonical = canonical(engines);
        if (canonical == null) {
            throw new Missing(upstream.name() + "'s engine types " + engines.names() + " have no columnar one");
        }
        relyOnConversions(upstream);
    }

    /**
     * Record the methods each conversion goes through, down to where each
     * codec encodes and decodes: the transformer fingerprints a method with
     * its private helpers, not its other callees.
     */
    private void relyOnConversions(Upstream upstream) throws Missing {
        upstream.relyOn("converts block metadata in either encoding to the columnar one for a columnar engine type,"
            + " and to the legacy one otherwise", transcodeMetadata);
        upstream.relyOn("converts entity data of a kind in either encoding to the columnar one for a columnar engine"
            + " type, and to the legacy one otherwise", transcodeData);
        upstream.relyOn("counts exactly ClickHouse and DuckDB as columnar, as LibreProtect does", engines.name(),
            "isColumnar()Z", "isClickHouse()Z", "isDuckDB()Z");
        upstream.relyOn("tells block metadata's columnar encoding from the legacy one, and converts between them",
            Names.BLOCK_META_CODEC, "isEncoded([B)Z", "canonicalize([B)[B", "fromLegacy([B)[B", "toLegacy([B)[B",
            "encode(Ljava/util/List;)[B");
        String kind = Names.descriptor(kinds.name());
        upstream.relyOn("tells entity data's columnar encoding from the legacy one, and converts between them",
            Names.ENTITY_DATA_CODEC, "isEncoded([B)Z", "canonicalize(" + kind + "[B)[B",
            "fromLegacy(" + kind + "[B)[B", "toLegacy(" + kind + "[B)[B", "encode(" + kind + "Ljava/util/List;)[B");
        upstream.relyOn("tells entity data's kinds apart by their codes", kinds.name(), "fromCode(I)" + kind);
        upstream.relyOn("reads and writes the legacy encoding of both", Names.LEGACY_METADATA_CODEC,
            "decode([B)Ljava/util/List;", "encode(Ljava/util/List;)[B");
    }

    /**
     * @return DuckDB if upstream has it, else another columnar engine, or
     *         {@code null} if it has none
     */
    private static Engine canonical(UpstreamEnum engines) {
        Engine found = null;
        for (String name : engines.names()) {
            Engine engine = Engine.fromUpstreamName(name).orElse(null);
            if (engine != null && engine.isColumnar() && (found == null || engine == Engine.DUCKDB)) {
                found = engine;
            }
        }
        return found;
    }

    /**
     * @return whether a column holds values that CoreProtect encodes
     *         differently for columnar engines
     */
    public static boolean isEncodedColumn(String table, String column) {
        return kind(table, column) != null;
    }

    /**
     * Convert a value from one engine's encoding to another's; values of
     * other columns, and between engines of one encoding, pass through.
     *
     * @param table the unprefixed table the value belongs to
     * @throws SQLException if CoreProtect can't convert the value
     */
    public Object transcode(String table, String column, Object value, Engine from, Engine to) throws SQLException {
        if (from.isColumnar() == to.isColumnar() || !(value instanceof byte[])) {
            return value;
        }
        return convert(table, column, (byte[]) value, to);
    }

    /**
     * @return the value in the canonical encoding, for comparing it with
     *         one from an engine that encodes it differently
     * @throws SQLException if CoreProtect can't decode the value
     */
    public Object canonical(String table, String column, Object value) throws SQLException {
        if (!(value instanceof byte[])) {
            return value;
        }
        return convert(table, column, (byte[]) value, canonical);
    }

    /**
     * @return whether entity data is in the columnar encoding
     */
    public boolean isEncoded(byte[] data) {
        return isEncoded.call((Object) data);
    }

    private Object convert(String table, String column, byte[] value, Engine engine) throws SQLException {
        String kind = kind(table, column);
        if (kind == null) {
            return value;
        }
        if (kind.isEmpty()) {
            return converting(table, column, engine, () -> transcodeMetadata.call(value,
                engines.constant(engine.name())));
        }
        return converting(table, column, engine, () -> transcodeData.call(value, kinds.constant(kind),
            engines.constant(engine.name())));
    }

    /** One of CoreProtect's conversions of a value */
    @FunctionalInterface
    interface Conversion {
        byte[] convert() throws Exception;
    }

    /**
     * Run one of CoreProtect's conversions of a value of the column.
     *
     * @param engine the engine whose encoding the value is converted to
     * @throws SQLDataException if CoreProtect refuses the value
     * @throws UpstreamChanged  as it is, if CoreProtect changed under the
     *                          conversion, which is no fault of the value's:
     *                          it names what changed, and the migration
     *                          fails instead of blaming the value or
     *                          keeping it unconverted
     */
    static byte[] converting(String table, String column, Engine engine, Conversion conversion)
        throws SQLDataException {
        try {
            return conversion.convert();
        } catch (UpstreamChanged e) {
            throw e;
        } catch (Exception e) {
            throw new SQLDataException("CoreProtect can't convert " + table + "." + column + " for "
                + engine.displayName() + ": " + e, e);
        }
    }

    /**
     * @return the entity data kind of an encoded column, an empty string for
     *         block metadata, or {@code null} for a column without an encoding
     */
    private static String kind(String table, String column) {
        if (table.equals("block") && column.equalsIgnoreCase("meta")) {
            return "";
        }
        if (table.equals("entity") && column.equalsIgnoreCase("data")) {
            return "ENTITY";
        }
        if (table.equals("entity_spawn") && column.equalsIgnoreCase("data")) {
            return "ENTITY_SPAWN";
        }
        return null;
    }
}
