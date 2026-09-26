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

/**
 * The binary names of the upstream classes that LibreProtect's extensions
 * use, in one place. They are strings on purpose: the extensions reach
 * CoreProtect only by reflection, so that the build's check that they never
 * link to it directly holds, and a missing class is a {@code Missing} with a
 * reason rather than a {@code NoClassDefFoundError}.
 */
public final class Names {

    public static final String CORE_PROTECT = "net.coreprotect.CoreProtect";
    public static final String PURGE_COMMAND = "net.coreprotect.command.PurgeCommand";
    public static final String RELOAD_COMMAND = "net.coreprotect.command.ReloadCommand";
    public static final String LOOKUP_COMMAND = "net.coreprotect.command.LookupCommand";
    public static final String ROLLBACK_RESTORE_COMMAND = "net.coreprotect.command.RollbackRestoreCommand";
    public static final String CONFIG = "net.coreprotect.config.Config";
    public static final String CONFIG_FILE = "net.coreprotect.config.ConfigFile";
    public static final String CONFIG_HANDLER = "net.coreprotect.config.ConfigHandler";
    public static final String DATABASE_CONFIG_WRITER = "net.coreprotect.config.DatabaseConfigWriter";
    public static final String CONSUMER = "net.coreprotect.consumer.Consumer";
    public static final String OPERATION_START_RESULT = "net.coreprotect.consumer.Consumer$OperationStartResult";
    public static final String PROCESS = "net.coreprotect.consumer.process.Process";
    public static final String DATABASE = "net.coreprotect.database.Database";
    /** CoreProtect's enum of database engines, which replaced {@code use-mysql} */
    public static final String DATABASE_TYPE = "net.coreprotect.database.DatabaseType";
    public static final String DUCKDB_DATABASE = "net.coreprotect.database.DuckDBDatabase";
    public static final String DUCKDB_RECOVERY = "net.coreprotect.database.DuckDBRecovery";
    public static final String PURGE_POLICY = "net.coreprotect.database.PurgePolicy";
    public static final String CLICKHOUSE_BATCH_IDENTITY =
        "net.coreprotect.database.clickhouse.ClickHouseBatchIdentity";
    public static final String CLICKHOUSE_BATCH_PUBLISHER =
        "net.coreprotect.database.clickhouse.ClickHouseBatchPublisher";
    public static final String CLICKHOUSE_BATCH_RECEIPT = "net.coreprotect.database.clickhouse.ClickHouseBatchReceipt";
    public static final String CLICKHOUSE_DATABASE = "net.coreprotect.database.clickhouse.ClickHouseDatabase";
    public static final String CLICKHOUSE_EVENT_BATCH = "net.coreprotect.database.clickhouse.ClickHouseEventBatch";
    public static final String CLICKHOUSE_FAMILY = "net.coreprotect.database.clickhouse.ClickHouseFamily";
    public static final String CLICKHOUSE_HIGH_WATER_PUBLISHER =
        "net.coreprotect.database.clickhouse.ClickHouseHighWaterPublisher";
    public static final String CLICKHOUSE_HIGH_WATER_MARKS =
        "net.coreprotect.database.clickhouse.ClickHouseHighWaterMarks";
    public static final String CLICKHOUSE_IDENTIFIERS = "net.coreprotect.database.clickhouse.ClickHouseIdentifiers";
    public static final String CLICKHOUSE_IDENTITY_ALLOCATOR =
        "net.coreprotect.database.clickhouse.ClickHouseIdentityAllocator";
    public static final String CLICKHOUSE_IDENTITY_RESERVATION =
        "net.coreprotect.database.clickhouse.ClickHouseIdentityReservation";
    public static final String CLICKHOUSE_JDBC = "net.coreprotect.database.clickhouse.ClickHouseJdbc";
    public static final String CLICKHOUSE_JDBC_CONFIG = "net.coreprotect.database.clickhouse.ClickHouseJdbcConfig";
    public static final String CLICKHOUSE_LOOKUP = "net.coreprotect.database.clickhouse.ClickHouseLookup";
    public static final String CLICKHOUSE_LOOKUP_INDEX = "net.coreprotect.database.clickhouse.ClickHouseLookupIndex";
    public static final String CLICKHOUSE_NATIVE_CLIENT = "net.coreprotect.database.clickhouse.ClickHouseNativeClient";
    public static final String CLICKHOUSE_RETENTION = "net.coreprotect.database.clickhouse.ClickHouseRetention";
    public static final String CLICKHOUSE_SCHEMA = "net.coreprotect.database.clickhouse.ClickHouseSchema";
    public static final String CLICKHOUSE_STARTUP_RECONCILER =
        "net.coreprotect.database.clickhouse.ClickHouseStartupReconciler";
    public static final String CLICKHOUSE_WRITE_BATCH = "net.coreprotect.database.clickhouse.ClickHouseWriteBatch";
    public static final String CLICKHOUSE_WRITER_REGISTRATION =
        "net.coreprotect.database.clickhouse.ClickHouseWriterRegistration";
    public static final String BLOCK_STATEMENT = "net.coreprotect.database.statement.BlockStatement";
    public static final String ENTITY_STATEMENT = "net.coreprotect.database.statement.EntityStatement";
    public static final String PLUGIN_INITIALIZATION = "net.coreprotect.services.PluginInitializationService";
    public static final String SHUTDOWN_SERVICE = "net.coreprotect.services.ShutdownService";
    public static final String SCHEDULER = "net.coreprotect.thread.Scheduler";
    public static final String DATABASE_UTILS = "net.coreprotect.utility.DatabaseUtils";
    public static final String ENTITY_SPAWN_TRACKING = "net.coreprotect.utility.EntitySpawnTracking";
    public static final String VERSION_UTILS = "net.coreprotect.utility.VersionUtils";
    public static final String BLOCK_META_CODEC = "net.coreprotect.utility.serialize.BlockMetaCodec";
    public static final String ENTITY_DATA_CODEC = "net.coreprotect.utility.serialize.EntityDataCodec";
    public static final String LEGACY_METADATA_CODEC = "net.coreprotect.utility.serialize.LegacyMetadataCodec";

    /** DuckDB's JDBC connection, from the driver that CoreProtect's plugin libraries bring along */
    public static final String DUCKDB_CONNECTION = "org.duckdb.DuckDBConnection";

    private Names() {
    }

    /**
     * @return the type descriptor of a class, for method descriptors, such as
     *         {@code Lnet/coreprotect/CoreProtect;}
     */
    public static String descriptor(String className) {
        return "L" + className.replace('.', '/') + ";";
    }
}
