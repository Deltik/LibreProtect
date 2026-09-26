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

import net.deltik.mc.libreprotect.extension.upstream.Capability;
import net.deltik.mc.libreprotect.extension.upstream.Codecs;
import net.deltik.mc.libreprotect.extension.upstream.ConfigLock;
import net.deltik.mc.libreprotect.extension.upstream.Designs;
import net.deltik.mc.libreprotect.extension.upstream.Flags;
import net.deltik.mc.libreprotect.extension.upstream.Names;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Creator;
import net.deltik.mc.libreprotect.extension.upstream.reflect.InstanceMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamChanged;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamEnum;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodType;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

/**
 * CoreProtect 25's ClickHouse storage, reached only by name: the surface
 * that upstream built for its own {@code /co migrate-db}, such as
 * {@code ClickHouseJdbcConfig.forMigrationReads},
 * {@code ClickHouseEventBatch.addCompatibilityRow} and
 * {@code ClickHouseDatabase.preserveCompatibilityHighWaterMarks}. Each
 * wrapper mirrors one upstream type and holds one of its objects. Every
 * member is found when the capability is probed, and bound as an exact
 * method handle on first use, so that a row costs one direct call.
 *
 * <p>Two capabilities: {@link #READS}, for a migration from ClickHouse, and
 * {@link #WRITES}, for one to it, which also reads the target back. Only a
 * CoreProtect without the multi-engine layer lacks ClickHouse, so that alone
 * makes both absent, as on 24.1, however CoreProtect names its ClickHouse
 * classes. A member that upstream renamed or reshaped leaves only the
 * capabilities that use it unavailable, naming it: a writer that changed
 * leaves reads alone.
 *
 * <p>Some of what LibreProtect relies on can't be probed: the columns of
 * CoreProtect's views, how its writer retries, the lock that makes it the
 * single writer of an installation, and where CoreProtect has a lookup index
 * ({@link Designs#CLICKHOUSE_LOOKUP_INDEX}), that its writer indexes each row
 * that its lookups by player read through it. The {@code relies} lines of the
 * capability report name the upstream methods that define each, so that
 * the build sees when they change.
 */
public final class ClickHouseApi {

    public static final Capability<ClickHouseApi> READS = Capability.of("clickhouse.reads",
        Choice.way("migration-reads", "CoreProtect's ClickHouse views, read over LibreProtect's own connections",
            upstream -> new ClickHouseApi(upstream, false)));

    public static final Capability<ClickHouseApi> WRITES = Capability.of("clickhouse.writes",
        Choice.way("compatibility-rows", "CoreProtect's ClickHouse writer, with its own mapping of CoreProtect's"
            + " columns", upstream -> new ClickHouseApi(upstream, true)));

    /** What {@code ClickHouseSchema.BATCH_RECEIPT_FAMILY} was when LibreProtect last looked */
    static final String BATCH_RECEIPT_FAMILY = "_batch_receipt";

    private static final String VIEWS = "creates a view of the event table per CoreProtect table, named after the"
        + " table, with rowid and the table's own column names; the keys that views add for lookups, such as"
        + " location keys, have names that start with _key_, and the user view shows a missing UUID as ''";

    private final Class<?> familyType;
    private final Bound newConfig;
    private final Bound configDatabase;
    private final Bound forMigrationReads;
    private final Bound newPool;
    private final Bound openConnection;
    private final Bound closePool;
    private final UpstreamEnum families;
    private final Bound tableName;
    private final Bound fromTableName;
    private final Bound qualified;
    private final Bound readRemote;
    private final Bound compatibilityRowId;
    /** What only a writer has, or {@code null} for reads */
    private final Writer writer;
    private volatile Map<Object, Family> byConstant;

    private ClickHouseApi(Upstream upstream, boolean writes) throws Missing {
        Designs.MULTI_ENGINE.requireIn(upstream);
        UpstreamClass config = upstream.type(Names.CLICKHOUSE_JDBC_CONFIG);
        Class<?> configType = config.type();
        newConfig = bind(config.constructor(String.class, int.class, String.class, String.class, String.class,
            boolean.class), String.class, int.class, String.class, String.class, String.class, boolean.class);
        configDatabase = bind(config.method("getDatabase", String.class), String.class);
        forMigrationReads = bind(config.method("forMigrationReads", configType), Object.class);
        upstream.relyOn("reads without a socket timeout, and has the server send rows as it finds them, for streaming"
            + " a whole table", Names.CLICKHOUSE_JDBC_CONFIG,
            "forMigrationReads()" + Names.descriptor(Names.CLICKHOUSE_JDBC_CONFIG));

        UpstreamClass jdbc = upstream.type(Names.CLICKHOUSE_JDBC);
        newPool = bind(jdbc.constructor(configType), Object.class);
        openConnection = bind(jdbc.method("openConnection", Connection.class), Connection.class);
        closePool = bind(jdbc.method("close", void.class), void.class);
        upstream.relyOn("closes its connection pools, which aborts the connections in use", Names.CLICKHOUSE_JDBC,
            "close()V");

        UpstreamClass family = upstream.type(Names.CLICKHOUSE_FAMILY);
        familyType = family.type();
        families = family.asEnum();
        tableName = bind(family.method("getTableName", String.class), String.class);
        fromTableName = bind(family.staticMethod("fromTableName", familyType, String.class), Object.class,
            String.class);

        qualified = bind(upstream.type(Names.CLICKHOUSE_IDENTIFIERS).staticMethod("qualified", String.class,
            String.class, String.class), String.class, String.class, String.class);

        UpstreamClass marks = upstream.type(Names.CLICKHOUSE_HIGH_WATER_MARKS);
        StaticMethod<?, ?> remote = upstream.type(Names.CLICKHOUSE_STARTUP_RECONCILER).staticMethod("readRemote",
            marks.type(), Connection.class, String.class, String.class);
        upstream.relyOn("reads the largest row ID that ClickHouse recorded for each table, purged rows included,"
            + " which CoreProtect continues after", remote);
        readRemote = bind(remote, Object.class, Connection.class, String.class, String.class);
        compatibilityRowId = bind(marks.method("getCompatibilityRowId", long.class, familyType), long.class,
            Object.class);

        upstream.relyOn(VIEWS, Names.CLICKHOUSE_SCHEMA, "createStatements(Ljava/lang/String;Ljava/lang/String;)"
            + "Ljava/util/List;");
        upstream.relyOn("shows each binary column in its view as it is stored, which LibreProtect reads as binary"
            + " data", Names.CLICKHOUSE_SCHEMA, "binary(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
        upstream.relyOn("strips the zero byte that marks binary data present where the driver reports a ClickHouse"
            + " column as an array, as LibreProtect does for a database that isn't the active one",
            Names.DATABASE_UTILS, "getBytes(Ljava/sql/ResultSet;Ljava/lang/String;)[B");

        writer = writes ? new Writer(upstream, configType, familyType) : null;
    }

    /**
     * @return whether this is {@link #WRITES}, which can write ClickHouse,
     *         rather than {@link #READS}
     */
    public boolean canWrite() {
        return writer != null;
    }

    /**
     * @throws IllegalArgumentException for settings that CoreProtect refuses,
     *                                  such as an empty username
     */
    public Config config(String host, int port, String database, String username, String password, boolean tls) {
        try {
            return new Config(this, (Object) newConfig.get().invokeExact(host, port, database, username, password,
                tls));
        } catch (Throwable e) {
            throw newConfig.unexpected(e);
        }
    }

    /**
     * @return CoreProtect's connection pools for a ClickHouse database, which
     *         connect on demand
     */
    public Pool pool(Config config) {
        try {
            return new Pool(this, (Object) newPool.get().invokeExact(config.config));
        } catch (Throwable e) {
            throw newPool.unexpected(e);
        }
    }

    /**
     * @return CoreProtect's ClickHouse tables, as its event families, in
     *         the order CoreProtect declares them
     */
    public List<Family> families() {
        return new ArrayList<>(byConstant().values());
    }

    /**
     * @return the event family of a CoreProtect table, by its unprefixed name
     * @throws IllegalArgumentException if CoreProtect has no such table
     */
    public Family family(String table) {
        Object constant;
        try {
            constant = (Object) fromTableName.get().invokeExact(table);
        } catch (Throwable e) {
            throw fromTableName.unexpected(e);
        }
        Family family = byConstant().get(constant);
        if (family == null) {
            throw new IllegalArgumentException("CoreProtect has no ClickHouse family " + constant);
        }
        return family;
    }

    private Map<Object, Family> byConstant() {
        Map<Object, Family> map = byConstant;
        if (map == null) {
            synchronized (this) {
                map = byConstant;
                if (map == null) {
                    Map<Object, Family> built = new LinkedHashMap<>();
                    for (String name : families.names()) {
                        Object constant = families.constant(name);
                        String table;
                        try {
                            table = (String) tableName.get().invokeExact(constant);
                        } catch (Throwable e) {
                            throw tableName.unexpected(e);
                        }
                        built.put(constant, new Family(this, constant, table));
                    }
                    map = Collections.unmodifiableMap(built);
                    byConstant = map;
                }
            }
        }
        return map;
    }

    /**
     * @return a table's name in backquotes, qualified with its database, as
     *         CoreProtect writes it in SQL
     * @throws IllegalArgumentException if either isn't a plain identifier
     */
    public String qualified(String database, String table) {
        try {
            return (String) qualified.get().invokeExact(database, table);
        } catch (Throwable e) {
            throw qualified.unexpected(e);
        }
    }

    /**
     * @return the row ID high-water marks that CoreProtect would start from
     *         on this database
     */
    public HighWaterMarks readHighWaterMarks(Connection connection, String database, String prefix)
        throws SQLException {
        try {
            return new HighWaterMarks(this, (Object) readRemote.get().invokeExact(connection, database, prefix));
        } catch (SQLException e) {
            throw e;
        } catch (Throwable e) {
            throw readRemote.unexpected(e);
        }
    }

    /**
     * Open a ClickHouse database as CoreProtect does: create its schema, and
     * register as the single ClickHouse writer of the control directory.
     *
     * @throws IllegalArgumentException for a prefix that isn't a plain identifier
     */
    public Target initialize(Config config, String prefix, Path controlDirectory) throws SQLException {
        Writer writer = writer();
        try {
            return new Target(this, (Object) writer.initialize.get().invokeExact(config.config, prefix,
                controlDirectory));
        } catch (SQLException e) {
            throw e;
        } catch (Throwable e) {
            throw writer.initialize.unexpected(e);
        }
    }

    /**
     * @return the columns of CoreProtect's event table
     */
    public List<String> eventColumns() {
        return writer().eventColumns().columns;
    }

    /**
     * @return the ClickHouse type of a column of CoreProtect's event table,
     *         such as {@code Nullable(UInt32)}, or {@code null} if it has none
     */
    public String eventColumnType(String column) {
        return writer().eventColumns().types.get(column);
    }

    /**
     * @return the column of CoreProtect's event table that its writer stores
     *         a table's column in, by CoreProtect's own mapping, which it
     *         keeps private: with it, LibreProtect refuses a value that the
     *         writer would wrap, truncate or store as zero
     */
    public String compatibilityColumn(Family family, String column) {
        Writer writer = writer();
        try {
            return (String) writer.compatibilityColumn.get().invokeExact(family.family, column);
        } catch (Throwable e) {
            throw writer.compatibilityColumn.unexpected(e);
        }
    }

    /**
     * @return the family of the rows that record which batches CoreProtect
     *         published, which aren't CoreProtect data, and of the rows of
     *         its lookup index where it has one, which are (see
     *         {@link #lookupIndexedFamily})
     */
    public String batchReceiptFamily() {
        return writer().batchReceiptFamily.get();
    }

    /**
     * @return CoreProtect's SQL expression of the table whose data a row of
     *         the event table is, over that table's columns: its family,
     *         except for a row of CoreProtect's lookup index, which is data
     *         of the table that it indexes, since CoreProtect's lookups read
     *         it as such; empty where CoreProtect has no lookup index
     */
    public Optional<String> lookupIndexedFamily() {
        StaticMethod<String, RuntimeException> expression = writer().logicalFamily;
        return expression.exists() ? Optional.of(expression.call()) : Optional.empty();
    }

    /**
     * @param eventTable the event table's qualified name, as
     *                   {@link #qualified} gives it
     * @return CoreProtect's SQL subquery of whether its lookups read the
     *         lookup index of the event table, 1 if they do, and anything
     *         else while a purge or schema upgrade that didn't complete
     *         keeps it closed; empty where CoreProtect has no lookup index
     */
    public Optional<String> lookupIndexOpen(String eventTable) {
        StaticMethod<String, RuntimeException> subquery = writer().lookupIndexReady;
        return subquery.exists() ? Optional.of(subquery.call(eventTable)) : Optional.empty();
    }

    /**
     * @return CoreProtect's internal database version, as ClickHouse records
     *         it, such as {@code 2.24.1}
     */
    public String coreVersion() {
        Writer writer = writer();
        Integer[] version;
        try {
            version = (Integer[]) writer.internalVersion.get().invokeExact();
        } catch (Throwable e) {
            throw writer.internalVersion.unexpected(e);
        }
        return version[0] + "." + version[1] + "." + version[2];
    }

    /**
     * @return CoreProtect's data folder, where it registers the ClickHouse
     *         writer of this installation
     */
    public Path controlDirectory() {
        return Paths.get((String) writer().path.get());
    }

    /**
     * @return the status of a {@code database_lock} row that marks an
     *         unfinished migration
     */
    public int incompleteStatus() {
        return writer().incompleteStatus.getAsInt();
    }

    /**
     * @return the status of a {@code database_lock} row that no server holds
     */
    public int inactiveStatus() {
        return writer().inactiveStatus.getAsInt();
    }

    /**
     * @param table an identifier map, such as {@code material_map}
     * @throws IllegalArgumentException for another table
     */
    public IdentifierCache identifierCache(String table) {
        IdentifierCache cache = writer().identifierCaches.get(table);
        if (cache == null) {
            throw new IllegalArgumentException("Not an identifier map: " + table);
        }
        return cache;
    }

    /**
     * @return the lock that CoreProtect assigns identifiers under
     */
    public ConfigLock configLock() {
        return writer().configLock;
    }

    /**
     * @return CoreProtect's conversions of entity data, for data in the
     *         legacy encoding, which its writer refuses
     */
    public Codecs codecs() {
        return writer().codecs;
    }

    /**
     * @return CoreProtect's lifecycle flags, which say when its shutdown begins
     */
    public Flags flags() {
        return writer().flags;
    }

    private Writer writer() {
        if (writer == null) {
            throw new IllegalStateException("This is " + READS.id() + ", which can't write ClickHouse");
        }
        return writer;
    }

    /**
     * What only writing needs, found when {@link #WRITES} is probed, with the
     * capabilities it needs besides: CoreProtect's conversions of entity data
     * ({@code migrate-db.transcoding}), its lock on identifiers
     * ({@code config.lock}) and its shutdown signals ({@code lifecycle.flags}).
     */
    private static final class Writer {
        final Bound initialize;
        final Bound newWriteBatch;
        final Bound publish;
        final Bound preserveMarks;
        final Bound ensureCoreData;
        final Bound openConnection;
        final Bound close;
        final Bound events;
        final Bound closeBatch;
        final Bound addCompatibilityRow;
        final Bound addDatabaseLockVersion;
        final Bound eventCount;
        final Bound compatibilityColumn;
        final StaticField eventColumnList;
        final StaticField eventColumnTypeList;
        final Supplier<String> batchReceiptFamily;
        /** Absent where CoreProtect has no lookup index, as are the others of it */
        final StaticMethod<String, RuntimeException> logicalFamily;
        final StaticMethod<String, RuntimeException> lookupIndexReady;
        final Bound internalVersion;
        final StaticField path;
        final IntSupplier incompleteStatus;
        final IntSupplier inactiveStatus;
        final Map<String, IdentifierCache> identifierCaches;
        final ConfigLock configLock;
        final Codecs codecs;
        final Flags flags;
        private volatile EventColumns eventColumns;

        Writer(Upstream upstream, Class<?> configType, Class<?> familyType) throws Missing {
            UpstreamClass database = upstream.type(Names.CLICKHOUSE_DATABASE);
            Class<?> databaseType = database.type();
            UpstreamClass writeBatch = upstream.type(Names.CLICKHOUSE_WRITE_BATCH);
            UpstreamClass eventBatch = upstream.type(Names.CLICKHOUSE_EVENT_BATCH);

            StaticMethod<?, ?> open = database.staticMethod("initialize", databaseType, configType, String.class,
                Path.class);
            upstream.relyOn("creates CoreProtect's ClickHouse schema, after checking the server's version and"
                + " database engine, and registers the database as the single writer of the control directory",
                open);
            initialize = bind(open, Object.class, Object.class, String.class, Path.class);
            newWriteBatch = bind(database.method("newWriteBatch", writeBatch.type()), Object.class);
            publish = bind(database.method("publish", Object.class, writeBatch.type()), Object.class, Object.class);
            preserveMarks = bind(database.method("preserveCompatibilityHighWaterMarks", void.class, Map.class),
                void.class, Map.class);
            ensureCoreData = bind(database.method("ensureCoreData", void.class, String.class), void.class,
                String.class);
            openConnection = bind(database.method("openConnection", Connection.class), Connection.class);
            close = bind(database.method("close", void.class), void.class);
            events = bind(writeBatch.method("events", eventBatch.type()), Object.class);
            closeBatch = bind(writeBatch.method("close", void.class), void.class);
            addCompatibilityRow = bind(eventBatch.method("addCompatibilityRow", void.class, familyType, long.class,
                Map.class), void.class, Object.class, long.class, Map.class);
            addDatabaseLockVersion = bind(eventBatch.method("addDatabaseLockVersion", long.class, long.class,
                int.class, int.class), long.class, long.class, int.class, int.class);
            eventCount = bind(eventBatch.method("size", int.class), int.class);
            // Private, and what the checks of values rest on, so a change of it stops writing
            compatibilityColumn = bind(eventBatch.staticMethod("compatibilityColumn", String.class, familyType,
                String.class), String.class, Object.class, String.class);

            UpstreamClass schema = upstream.type(Names.CLICKHOUSE_SCHEMA);
            eventColumnList = schema.staticField("EVENT_COLUMNS", List.class);
            eventColumnTypeList = schema.staticField("EVENT_COLUMN_TYPES", List.class);
            batchReceiptFamily = schema.stringConstant("BATCH_RECEIPT_FAMILY", BATCH_RECEIPT_FAMILY);
            UpstreamClass lookupIndex = upstream.typeIfPresent(Names.CLICKHOUSE_LOOKUP_INDEX);
            logicalFamily = lookupIndex.staticMethodSince(Designs.CLICKHOUSE_LOOKUP_INDEX, "logicalFamily",
                String.class);
            lookupIndexReady = lookupIndex.staticMethodSince(Designs.CLICKHOUSE_LOOKUP_INDEX, "ready", String.class,
                String.class);
            if (logicalFamily.exists()) {
                upstream.relyOn("gives the family of each row of the event table, or for a row of the lookup index,"
                    + " the family of the table that it indexes, as CoreProtect's lookups read it, which is how a"
                    + " sink tells CoreProtect data from batch receipts", logicalFamily);
            }
            if (lookupIndexReady.exists()) {
                upstream.relyOn("is 1 while CoreProtect's lookups read the lookup index, and 0 while any"
                    + " installation's purge or schema upgrade that didn't complete keeps it closed, which a sink"
                    + " counts as CoreProtect data", lookupIndexReady);
            }
            internalVersion = bind(upstream.type(Names.VERSION_UTILS).staticMethod("getInternalPluginVersion",
                Integer[].class), Integer[].class);

            UpstreamClass handler = upstream.type(Names.CONFIG_HANDLER);
            path = handler.staticField("path", String.class);
            identifierCaches = identifierCaches(handler);

            UpstreamClass databases = upstream.type(Names.DATABASE);
            incompleteStatus = databases.intConstant("DATABASE_LOCK_MIGRATION_INCOMPLETE");
            inactiveStatus = databases.intConstant("DATABASE_LOCK_INACTIVE");

            configLock = require(upstream, ConfigLock.CAPABILITY);
            codecs = require(upstream, Codecs.CAPABILITY);
            flags = require(upstream, Flags.CAPABILITY);
            relyOnWriter(upstream);
        }

        /**
         * The caches of the identifier maps, by table: what CoreProtect has
         * assigned, and the counter it assigns the next one above
         */
        private static Map<String, IdentifierCache> identifierCaches(UpstreamClass handler) throws Missing {
            String[][] caches = {
                {"art_map", "artId", "artReversed"},
                {"blockdata_map", "blockdataId", "blockdataReversed"},
                {"entity_map", "entityId", "entitiesReversed"},
                {"material_map", "materialId", "materialsReversed"},
                {"world", "worldId", "worldsReversed"}};
            Map<String, IdentifierCache> byTable = new HashMap<>();
            for (String[] cache : caches) {
                byTable.put(cache[0], new IdentifierCache(handler.writableStaticField(cache[1], int.class),
                    handler.staticField(cache[2], Map.class)));
            }
            return Collections.unmodifiableMap(byTable);
        }

        /**
         * The behavior of CoreProtect's writer that LibreProtect's sink
         * relies on, by the methods that hold it
         */
        private static void relyOnWriter(Upstream upstream) throws Missing {
            String batch = Names.descriptor(Names.CLICKHOUSE_WRITE_BATCH);
            String identity = Names.descriptor(Names.CLICKHOUSE_BATCH_IDENTITY);
            String family = Names.descriptor(Names.CLICKHOUSE_FAMILY);
            upstream.relyOn("refuses a second writer registration in the same control directory while one holds its"
                + " file lock", Names.CLICKHOUSE_WRITER_REGISTRATION, "acquire()V");
            upstream.relyOn("releases the file lock, so that another writer can register",
                Names.CLICKHOUSE_WRITER_REGISTRATION, "close()V");
            upstream.relyOn("releases the writer registration and closes the database's connections",
                Names.CLICKHOUSE_DATABASE, "close()V");
            upstream.relyOn("publishes each partition of a batch once, so a batch published again after a failure"
                + " isn't stored twice; retries a refused partition for as long as shouldContinueRecovery holds",
                Names.CLICKHOUSE_BATCH_PUBLISHER,
                "publish(" + batch + ")" + Names.descriptor(Names.CLICKHOUSE_BATCH_RECEIPT));
            upstream.relyOn("records row ID high-water marks in retention_high_water, where readRemote finds them"
                + " after a restart; retries a refused insert for as long as shouldContinueRecovery holds",
                Names.CLICKHOUSE_HIGH_WATER_PUBLISHER, "publish(" + identity + "Ljava/util/Map;)V");
            upstream.relyOn("keeps retrying for as long as the server runs, which PublishDeadline bounds",
                Names.CLICKHOUSE_BATCH_PUBLISHER, "shouldContinueRecovery()Z");
            upstream.relyOn("stops waiting between attempts when the thread is interrupted, which is how"
                + " PublishDeadline stops a publication", Names.CLICKHOUSE_BATCH_PUBLISHER,
                "pauseBeforeRetry(ILjava/lang/String;)V");
            upstream.relyOn("gives an insert CoreProtect's 5-minute socket timeout, so one in flight ends by itself",
                Names.CLICKHOUSE_NATIVE_CLIENT, "<init>(" + Names.descriptor(Names.CLICKHOUSE_JDBC_CONFIG) + ")V");
            upstream.relyOn("sends each insert with a deduplication token of its batch, so ClickHouse ignores one"
                + " repeated after a failure", Names.CLICKHOUSE_NATIVE_CLIENT, "insert(Ljava/lang/String;"
                + "Ljava/util/List;Ljava/io/InputStream;" + identity + "Ljava/lang/String;)V");
            upstream.relyOn("defines the columns of the event table, among them family and rowid, and of"
                + " identity_reservation, among them sequence", Names.CLICKHOUSE_SCHEMA, "<clinit>()V");
            upstream.relyOn("stores a row under its own row ID, each column where compatibilityColumn maps it,"
                + " converting block metadata itself and refusing entity data in the legacy encoding; where"
                + " CoreProtect has a lookup index, it also stamps the row with CoreProtect's write version, refusing"
                + " one of the caller's, and indexes the row for CoreProtect's lookups",
                Names.CLICKHOUSE_EVENT_BATCH, "addCompatibilityRow(" + family + "JLjava/util/Map;)V");
            upstream.relyOnSince(Designs.CLICKHOUSE_LOOKUP_INDEX, "adds an index row, under the batch receipt family,"
                + " beside each row of the tables that CoreProtect's lookups by player read through the index, so"
                + " that those lookups find the rows that a migration copied too", Names.CLICKHOUSE_LOOKUP_INDEX,
                "append(Lnet/coreprotect/database/clickhouse/ClickHouseRowBinaryBuffer;" + family + "IZ)Z");
            upstream.relyOnSince(Designs.CLICKHOUSE_LOOKUP_INDEX, "numbers the tables that the lookup index indexes,"
                + " and no other, so that only rows of those tables get index rows", Names.CLICKHOUSE_LOOKUP_INDEX,
                "familyCode(Ljava/lang/String;)I");
            upstream.relyOnSince(Designs.CLICKHOUSE_LOOKUP_INDEX, "has CoreProtect's lookups by player read a table's"
                + " rows from its index rows alone while the index is open, and from the events while it's closed,"
                + " so that they find what a migration copied, and index rows without events too",
                Names.CLICKHOUSE_LOOKUP_INDEX, "source(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
                    + "Ljava/lang/String;JJZ)Ljava/lang/String;");
            upstream.relyOn("records row ID high-water marks, which CoreProtect's row IDs continue after, now and after"
                + " a restart", Names.CLICKHOUSE_DATABASE, "preserveCompatibilityHighWaterMarks(Ljava/util/Map;)V");
            String reservation = Names.descriptor(Names.CLICKHOUSE_IDENTITY_RESERVATION);
            upstream.relyOn("starts each table's row IDs after its high-water mark when a database opens, and after"
                + " every row ID observed since, such as a mark or a copied row's", Names.CLICKHOUSE_IDENTITY_ALLOCATOR,
                "<init>(Ljava/util/UUID;" + reservation + Names.descriptor(Names.CLICKHOUSE_HIGH_WATER_MARKS) + ")V",
                "nextRowId(" + family + ")J", "observeRowId(" + family + "J)V");
            upstream.relyOn("reserves the next row IDs of a table above every one observed",
                Names.CLICKHOUSE_IDENTITY_RESERVATION, "next(Ljava/lang/String;)J", "next(Ljava/lang/String;J)J",
                "observe(Ljava/lang/String;J)V");
            upstream.relyOn("writes the version row, and a database lock row if there is none, both with row ID 1",
                Names.CLICKHOUSE_DATABASE, "ensureCoreData(Ljava/lang/String;)V");
            upstream.relyOn("claims identifiers in identity_reservation under sequences starting with canonical:",
                Names.CLICKHOUSE_DATABASE,
                "nextIdentifierId(Lnet/coreprotect/database/ConsumerWriteBatch$ReferenceKind;Ljava/lang/String;I)I",
                "canonicalUserId(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;)I");
            upstream.relyOn("names the event table event_data and the claims table identity_reservation, after the"
                + " table prefix", Names.CLICKHOUSE_SCHEMA + "$Names", "<init>(Ljava/lang/String;Ljava/lang/String;)V");
            // How CoreProtect takes a prepared database over is migrate-db.target.clickhouse's (see EngineSide)
            String database = Names.descriptor(Names.CLICKHOUSE_DATABASE);
            upstream.relyOn("registers the active database's writer in CoreProtect's data folder, where a sink"
                + " registers too, so that only one of them writes", Names.CLICKHOUSE_DATABASE,
                "initialize(" + Names.descriptor(Names.CLICKHOUSE_JDBC_CONFIG) + "Ljava/lang/String;)" + database);
            upstream.relyOn("assigns a new identifier above the largest assigned, under the lock on ConfigHandler",
                Names.CONFIG_HANDLER, "resolveIdentifierId(Lnet/coreprotect/config/ConfigHandler$CacheType;"
                    + "Ljava/lang/String;Z)I");
            upstream.relyOn("records an assigned identifier among the assigned ones and raises the counter to it",
                Names.CONFIG_HANDLER + "$IdentifierStore", "store(ILjava/lang/String;)Z");
            upstream.relyOn("keeps each identifier map's counter and assigned identifiers in artId and artReversed,"
                + " blockdataId and blockdataReversed, entityId and entitiesReversed, materialId and materialsReversed,"
                + " and worldId and worldsReversed", Names.CONFIG_HANDLER, "identifierStores()Ljava/util/Map;");
        }

        EventColumns eventColumns() {
            EventColumns columns = eventColumns;
            if (columns == null) {
                columns = new EventColumns(eventColumnList.get(), eventColumnTypeList.get());
                eventColumns = columns;
            }
            return columns;
        }
    }

    /**
     * The columns of CoreProtect's event table, with their types, read once.
     */
    private static final class EventColumns {
        final List<String> columns;
        final Map<String, String> types;

        EventColumns(Object columns, Object types) {
            List<String> names = new ArrayList<>();
            Map<String, String> byName = new HashMap<>();
            List<?> nameList = (List<?>) columns;
            List<?> typeList = (List<?>) types;
            if (nameList.size() != typeList.size()) {
                throw new UpstreamChanged("CoreProtect's ClickHouse event table has " + nameList.size()
                    + " columns, but " + typeList.size() + " column types");
            }
            for (int index = 0; index < nameList.size(); index++) {
                String name = (String) nameList.get(index);
                names.add(name);
                byName.put(name, (String) typeList.get(index));
            }
            this.columns = Collections.unmodifiableList(names);
            this.types = Collections.unmodifiableMap(byName);
        }
    }

    private static <T> T require(Upstream upstream, Capability<T> capability) throws Missing {
        return capability.probe(upstream).require();
    }

    private static Bound bind(Creator creator, Class<?>... parameters) {
        return new Bound(creator::exact, creator.toString(), Object.class, parameters);
    }

    private static Bound bind(StaticMethod<?, ?> method, Class<?> returns, Class<?>... parameters) {
        return new Bound(method::exact, method.toString(), returns, parameters);
    }

    /**
     * @param parameters the method's parameters after its target
     */
    private static Bound bind(InstanceMethod<?, ?> method, Class<?> returns, Class<?>... parameters) {
        return new Bound(method::exact, method.toString(), MethodType.methodType(returns, parameters)
            .insertParameterTypes(0, Object.class));
    }

    /**
     * A member's exact handle, adapted on first use to the types that the
     * facade calls it with, in which upstream's own classes are
     * {@code Object}, and kept: a call is one {@code invokeExact}.
     */
    private static final class Bound {
        private final Supplier<MethodHandle> exact;
        private final String what;
        private final MethodType type;
        private volatile MethodHandle handle;

        Bound(Supplier<MethodHandle> exact, String what, Class<?> returns, Class<?>... parameters) {
            this(exact, what, MethodType.methodType(returns, parameters));
        }

        Bound(Supplier<MethodHandle> exact, String what, MethodType type) {
            this.exact = exact;
            this.what = what;
            this.type = type;
        }

        MethodHandle get() {
            MethodHandle bound = handle;
            if (bound == null) {
                bound = exact.get().asType(type);
                handle = bound;
            }
            return bound;
        }

        /**
         * @return an unchecked exception or error to throw for something the
         *         member threw that the caller didn't let through: itself,
         *         or {@link UpstreamChanged} for a checked exception, which
         *         upstream doesn't declare
         */
        RuntimeException unexpected(Throwable thrown) {
            if (thrown instanceof RuntimeException) {
                return (RuntimeException) thrown;
            }
            if (thrown instanceof Error) {
                throw (Error) thrown;
            }
            return new UpstreamChanged(what + " failed with an unexpected " + thrown, thrown);
        }
    }

    /**
     * A {@code ClickHouseJdbcConfig}: where a ClickHouse database is, and how
     * CoreProtect connects to it.
     */
    public static final class Config {
        private final ClickHouseApi api;
        private final Object config;

        private Config(ClickHouseApi api, Object config) {
            this.api = api;
            this.config = config;
        }

        public String database() {
            try {
                return (String) api.configDatabase.get().invokeExact(config);
            } catch (Throwable e) {
                throw api.configDatabase.unexpected(e);
            }
        }

        /**
         * @return the same settings for streaming a whole table: without a
         *         socket timeout, since nothing arrives while the server
         *         sorts, and with rows sent as the server finds them
         */
        public Config forMigrationReads() {
            try {
                return new Config(api, (Object) api.forMigrationReads.get().invokeExact(config));
            } catch (Throwable e) {
                throw api.forMigrationReads.unexpected(e);
            }
        }

        public Object upstream() {
            return config;
        }
    }

    /**
     * A {@code ClickHouseJdbc}: CoreProtect's pools of connections to a
     * ClickHouse database.
     */
    public static final class Pool implements AutoCloseable {
        private final ClickHouseApi api;
        private final Object pool;

        private Pool(ClickHouseApi api, Object pool) {
            this.api = api;
            this.pool = pool;
        }

        public Connection openConnection() throws SQLException {
            try {
                return (Connection) api.openConnection.get().invokeExact(pool);
            } catch (SQLException e) {
                throw e;
            } catch (Throwable e) {
                throw api.openConnection.unexpected(e);
            }
        }

        /**
         * Close the pools, which aborts the connections in use.
         */
        @Override
        public void close() {
            try {
                api.closePool.get().invokeExact(pool);
            } catch (Throwable e) {
                throw api.closePool.unexpected(e);
            }
        }

        /**
         * @return CoreProtect's {@code ClickHouseJdbc}
         */
        public Object upstream() {
            return pool;
        }
    }

    /**
     * A {@code ClickHouseFamily}: one of CoreProtect's tables, whose rows
     * ClickHouse keeps in one event table, by family.
     */
    public static final class Family {
        private final ClickHouseApi api;
        private final Object family;
        private final String tableName;

        private Family(ClickHouseApi api, Object family, String tableName) {
            this.api = api;
            this.family = family;
            this.tableName = tableName;
        }

        /**
         * @return the unprefixed name of the CoreProtect table, such as {@code block}
         */
        public String tableName() {
            return tableName;
        }

        ClickHouseApi api() {
            return api;
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Family && ((Family) other).family == family;
        }

        @Override
        public int hashCode() {
            return System.identityHashCode(family);
        }

        @Override
        public String toString() {
            return tableName;
        }
    }

    /**
     * A {@code ClickHouseHighWaterMarks}: the largest row ID that ClickHouse
     * recorded for each table.
     */
    public static final class HighWaterMarks {
        private final ClickHouseApi api;
        private final Object marks;

        private HighWaterMarks(ClickHouseApi api, Object marks) {
            this.api = api;
            this.marks = marks;
        }

        /**
         * @return the table's high-water mark, or 0 if it has none
         */
        public long compatibilityRowId(Family family) {
            try {
                return (long) api.compatibilityRowId.get().invokeExact(marks, family.family);
            } catch (Throwable e) {
                throw api.compatibilityRowId.unexpected(e);
            }
        }
    }

    /**
     * A {@code ClickHouseDatabase}: a ClickHouse database that CoreProtect
     * writes, as the single writer of its installation until it's closed.
     */
    public static final class Target implements AutoCloseable {
        private final ClickHouseApi api;
        private final Writer writer;
        private final Object database;

        private Target(ClickHouseApi api, Object database) {
            this.api = api;
            this.writer = api.writer();
            this.database = database;
        }

        public WriteBatch newWriteBatch() throws SQLException {
            try {
                return new WriteBatch(api, (Object) writer.newWriteBatch.get().invokeExact(database));
            } catch (SQLException e) {
                throw e;
            } catch (Throwable e) {
                throw writer.newWriteBatch.unexpected(e);
            }
        }

        /**
         * Publish a batch, or the rest of it after a failure.
         */
        public void publish(WriteBatch batch) throws SQLException {
            try {
                Object ignored = (Object) writer.publish.get().invokeExact(database, batch.batch);
            } catch (SQLException e) {
                throw e;
            } catch (Throwable e) {
                throw writer.publish.unexpected(e);
            }
        }

        /**
         * @param marks row ID high-water marks by table, which CoreProtect's
         *              row IDs continue after
         */
        @SuppressWarnings({"unchecked", "rawtypes"})
        public void preserveCompatibilityHighWaterMarks(Map<Family, Long> marks) throws SQLException {
            Map<Object, Long> byFamily = new EnumMap(api.familyType);
            for (Map.Entry<Family, Long> mark : marks.entrySet()) {
                byFamily.put(mark.getKey().family, mark.getValue());
            }
            try {
                writer.preserveMarks.get().invokeExact(database, (Map) byFamily);
            } catch (SQLException e) {
                throw e;
            } catch (Throwable e) {
                throw writer.preserveMarks.unexpected(e);
            }
        }

        /**
         * Write CoreProtect's version row, and a database lock row if there is none.
         */
        public void ensureCoreData(String coreVersion) throws SQLException {
            try {
                writer.ensureCoreData.get().invokeExact(database, coreVersion);
            } catch (SQLException e) {
                throw e;
            } catch (Throwable e) {
                throw writer.ensureCoreData.unexpected(e);
            }
        }

        public Connection openConnection() throws SQLException {
            try {
                return (Connection) writer.openConnection.get().invokeExact(database);
            } catch (SQLException e) {
                throw e;
            } catch (Throwable e) {
                throw writer.openConnection.unexpected(e);
            }
        }

        /**
         * Close the database and release its writer registration; nothing
         * the second time.
         */
        @Override
        public void close() throws SQLException {
            try {
                writer.close.get().invokeExact(database);
            } catch (SQLException e) {
                throw e;
            } catch (Throwable e) {
                throw writer.close.unexpected(e);
            }
        }

        /**
         * @return CoreProtect's {@code ClickHouseDatabase}
         */
        public Object upstream() {
            return database;
        }
    }

    /**
     * A {@code ClickHouseWriteBatch}: rows to publish together.
     */
    public static final class WriteBatch implements AutoCloseable {
        private final ClickHouseApi api;
        private final Object batch;

        private WriteBatch(ClickHouseApi api, Object batch) {
            this.api = api;
            this.batch = batch;
        }

        /**
         * @throws IllegalStateException if the batch is closed
         */
        public Events events() {
            Writer writer = api.writer;
            try {
                return new Events(writer, (Object) writer.events.get().invokeExact(batch));
            } catch (Throwable e) {
                throw writer.events.unexpected(e);
            }
        }

        @Override
        public void close() {
            Writer writer = api.writer;
            try {
                writer.closeBatch.get().invokeExact(batch);
            } catch (Throwable e) {
                throw writer.closeBatch.unexpected(e);
            }
        }
    }

    /**
     * A {@code ClickHouseEventBatch}: the event rows of a batch.
     */
    public static final class Events {
        private final Writer writer;
        private final Object events;

        private Events(Writer writer, Object events) {
            this.writer = writer;
            this.events = events;
        }

        /**
         * Add a row of a CoreProtect table with its own row ID.
         *
         * @param values the row's values by column; CoreProtect stores each
         *               where {@link ClickHouseApi#compatibilityColumn} says
         * @throws IllegalArgumentException for a value CoreProtect refuses
         */
        @SuppressWarnings("rawtypes")
        public void addCompatibilityRow(Family family, long rowId, Map<String, ?> values) throws SQLException {
            try {
                writer.addCompatibilityRow.get().invokeExact(events, family.family, rowId, (Map) values);
            } catch (SQLException e) {
                throw e;
            } catch (Throwable e) {
                throw writer.addCompatibilityRow.unexpected(e);
            }
        }

        /**
         * Add a version of the {@code database_lock} row.
         */
        public long addDatabaseLockVersion(long rowId, int time, int status) throws SQLException {
            try {
                return (long) writer.addDatabaseLockVersion.get().invokeExact(events, rowId, time, status);
            } catch (SQLException e) {
                throw e;
            } catch (Throwable e) {
                throw writer.addDatabaseLockVersion.unexpected(e);
            }
        }

        /**
         * @return how many events the batch has
         */
        public int size() {
            try {
                return (int) writer.eventCount.get().invokeExact(events);
            } catch (Throwable e) {
                throw writer.eventCount.unexpected(e);
            }
        }

        /**
         * @return CoreProtect's {@code ClickHouseEventBatch}
         */
        public Object upstream() {
            return events;
        }
    }

    /**
     * CoreProtect's cache of one identifier map's identifiers, in
     * {@code ConfigHandler}: those it assigned, by identifier, and the
     * counter it assigns the next one above. Change them only with
     * {@link #configLock()} held.
     */
    public static final class IdentifierCache {
        private final StaticField counter;
        private final StaticField assigned;

        private IdentifierCache(StaticField counter, StaticField assigned) {
            this.counter = counter;
            this.assigned = assigned;
        }

        public int counter() {
            return counter.getInt();
        }

        public void setCounter(int value) {
            counter.setInt(value);
        }

        /**
         * @return the assigned identifiers and their values, as CoreProtect
         *         keeps them now
         */
        @SuppressWarnings("unchecked")
        public Map<Integer, String> assigned() {
            return (Map<Integer, String>) assigned.get();
        }
    }
}
