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

import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.ConfigValueWriter;
import net.deltik.mc.libreprotect.extension.migration.MigrationException;
import net.deltik.mc.libreprotect.extension.upstream.reflect.InstanceField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.InstanceMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Shape;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamEnum;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;

/**
 * The selection of CoreProtect with engine types, such as CoreProtect 25:
 * {@code database-type} names one, and CoreProtect keeps it in
 * {@code ConfigHandler.databaseType}. Its docs have every engine's settings
 * loaded before a migration starts, so the target's settings are the ones
 * CoreProtect has loaded. {@code Config.MYSQL}, which CoreProtect derives
 * from the engine type, and the table prefixes change with it, under
 * CoreProtect's lock (see {@link ConfigLock}). config.yml changes only once
 * CoreProtect uses the target, through CoreProtect's own writer.
 */
final class DatabaseTypeSelection implements Selection {

    /** Embedded databases always use this prefix */
    private static final String EMBEDDED_PREFIX = "co_";

    private final UpstreamEnum types;
    private final StaticField databaseType;
    private final InstanceMethod<Boolean, RuntimeException> isMySQL;
    private final StaticMethod<?, RuntimeException> global;
    private final InstanceField configuredType;
    private final InstanceField mySQL;
    private final InstanceField globalPrefix;
    private final InstanceField databaseLock;
    private final StaticField path;
    private final StaticField prefix;
    private final StaticField prefixConfig;
    private final StaticField configFile;
    private final StaticMethod<Void, RuntimeException> loadDatabase;
    private final StaticMethod<Void, IOException> persistDatabaseType;
    private final ConfigLock lock;

    private DatabaseTypeSelection(Upstream upstream) throws Missing {
        UpstreamClass handler = upstream.type(Names.CONFIG_HANDLER);
        // Selecting a database and switching back set databaseType, DATABASE_TYPE, MYSQL, PREFIX and prefix
        databaseType = handler.writableStaticField("databaseType", Enum.class);
        UpstreamClass type = upstream.type(databaseType.type());
        types = type.asEnum();
        isMySQL = type.method("isMySQL", boolean.class);
        UpstreamClass config = upstream.type(Names.CONFIG);
        global = config.staticMethod("getGlobal", config.type());
        configuredType = config.writableField("DATABASE_TYPE", String.class);
        mySQL = config.writableField("MYSQL", boolean.class);
        globalPrefix = config.writableField("PREFIX", String.class);
        databaseLock = config.field("DATABASE_LOCK", boolean.class);
        path = handler.staticField("path", String.class);
        prefix = handler.writableStaticField("prefix", String.class);
        prefixConfig = handler.staticField("prefixConfig", String.class);
        configFile = upstream.type(Names.CONFIG_FILE).staticField("CONFIG", String.class);
        loadDatabase = handler.staticMethod("loadDatabase", void.class);
        persistDatabaseType = upstream.type(Names.DATABASE_CONFIG_WRITER).staticMethod("persistDatabaseType",
            void.class, type.type()).throwing(IOException.class);
        lock = MigrationProtocol.need(upstream, ConfigLock.CAPABILITY);

        upstream.relyOn("loads the database that databaseType and the loaded settings select, keeping the caches of"
            + " identifiers, and throws if it can't", loadDatabase);
        upstream.relyOn("closes the database in use first, and refuses one with the unfinished migration's status"
            + " unless a migration activates it", checkedLoad(handler));
        upstream.relyOn("closes the connections of every engine, so that the next database can be loaded",
            Names.DATABASE, "closeConnection()V");
        upstream.relyOn("loads every engine's settings whichever database-type selects, keeps the configured"
            + " table-prefix in prefixConfig, and co_ for embedded engines", Names.CONFIG_HANDLER, "loadConfig()V");
        upstream.relyOn("atomically sets database-type in config.yml, and use-mysql where it's set",
            persistDatabaseType);
    }

    static DatabaseTypeSelection probe(Upstream upstream) throws Missing {
        return new DatabaseTypeSelection(upstream);
    }

    /**
     * @param handler CoreProtect's {@code ConfigHandler}
     * @return the private {@code loadDatabase} that both
     *         {@code loadDatabase()} and a migration's activation of
     *         ClickHouse go through, which checks the unfinished migration's
     *         status. It's known by its name and its shape: a database, then
     *         whether a migration activates it. Its first parameter is
     *         ClickHouse's class, which only migrations from or to
     *         ClickHouse use, so a rename of that class doesn't turn off the
     *         migrations between the other engines.
     */
    static StaticMethod<Void, RuntimeException> checkedLoad(UpstreamClass handler) throws Missing {
        return handler.staticMethodShaped("loadDatabase", void.class, Shape.anyObject(), Shape.exactly(boolean.class));
    }

    @Override
    public DatabaseSettings loadedTargetSettings(Engine source, Engine target,
                                                 Function<String, DatabaseSettings> loaded) {
        return targetSettings(source, target, loaded);
    }

    /**
     * Embedded targets use {@code co_}. An external target uses the
     * configured table-prefix when the source is embedded, and otherwise the
     * source's prefix, which is the same one.
     */
    @Override
    public DatabaseSettings targetSettings(Engine source, Engine target, Function<String, DatabaseSettings> loaded) {
        return loaded.apply(target.isEmbedded() ? EMBEDDED_PREFIX
            : (String) (source.isEmbedded() ? prefixConfig.get() : prefix.get()));
    }

    @Override
    public String targetSettingsChanged(Engine target) {
        return "CoreProtect's " + target.displayName() + " settings changed after the migration began, such as on"
            + " /co reload";
    }

    @Override
    public String activePrefix() {
        return (String) prefix.get();
    }

    @Override
    public boolean databaseLockEnabled() {
        return databaseLock.getBoolean(global.call());
    }

    /**
     * config.yml's {@code database-type} changes at the switch, through
     * CoreProtect's writer, which needs a regular file it can replace
     * atomically with a copy that has the same owner.
     */
    @Override
    public void preflight() throws MigrationException {
        File file = configFile();
        try {
            ConfigValueWriter.checkReplaceable(file.toPath(), true);
        } catch (IOException e) {
            throw new MigrationException("CoreProtect couldn't select the target in " + file + " after the copy: "
                + e.getMessage() + ".", e);
        }
    }

    @Override
    public List<String> whileCopying(Engine source, Engine target) {
        return Collections.emptyList();
    }

    @Override
    public Selected current() {
        Object[] values = new Object[5];
        lock.run(() -> {
            Object config = global.call();
            values[0] = databaseType.get();
            values[1] = configuredType.get(config);
            values[2] = mySQL.getBoolean(config);
            values[3] = globalPrefix.get(config);
            values[4] = prefix.get();
        });
        return () -> apply(values[0], (String) values[1], (Boolean) values[2], (String) values[3], (String) values[4]);
    }

    /**
     * Select the target as CoreProtect would after loading config.yml with
     * the target's {@code database-type}.
     */
    @Override
    public void select(Engine target, DatabaseSettings settings) {
        Enum<?> type = types.constant(target.name());
        apply(type, type.name().toLowerCase(Locale.ROOT), isMySQL.call(type), settings.prefix(), settings.prefix());
    }

    private void apply(Object type, String configured, boolean mySQLSelected, String configuredPrefix,
                       String activePrefix) {
        lock.run(() -> {
            Object config = global.call();
            databaseType.set(type);
            configuredType.set(config, configured);
            mySQL.setBoolean(config, mySQLSelected);
            globalPrefix.set(config, configuredPrefix);
            prefix.set(activePrefix);
        });
    }

    @Override
    public void load() {
        loadDatabase.call();
    }

    @Override
    public String persist(Engine target) throws IOException {
        persistDatabaseType.call(types.constant(target.name()));
        return "config.yml now selects " + target.displayName() + " (database-type: " + target.configName()
            + ", and use-mysql: " + (target == Engine.MYSQL) + " where it's set).";
    }

    @Override
    public List<String> afterFailure() {
        return Collections.emptyList();
    }

    @Override
    public String markedAgain() {
        return "The target is marked as an unfinished migration again, so CoreProtect refuses to use it.";
    }

    private File configFile() {
        return new File((String) path.get(), (String) configFile.get());
    }
}
