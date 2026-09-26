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
import net.deltik.mc.libreprotect.extension.upstream.reflect.Creator;
import net.deltik.mc.libreprotect.extension.upstream.reflect.InstanceField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.InstanceMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

/**
 * The selection of CoreProtect with only SQLite and MySQL, such as
 * CoreProtect 24: {@code use-mysql} picks one, and CoreProtect keeps it in
 * {@code Config.MYSQL}.
 *
 * <p>CoreProtect 24 reads config.yml's database settings only at startup and
 * on {@code /co reload}. Its migration docs have the target configured in
 * config.yml while the server runs on the source, so the target's settings
 * are read from the file directly, with CoreProtect's own parser. While the
 * copy runs, config.yml selects the source, so a restart in between keeps
 * using it; the target is selected at the switch, in memory like CoreProtect
 * loads its settings, then in config.yml once CoreProtect uses it.
 */
final class UseMySQLSelection implements Selection {

    private final StaticMethod<?, RuntimeException> global;
    private final Creator newConfig;
    private final InstanceMethod<Void, IOException> load;
    private final InstanceField mySQL;
    private final InstanceField globalPrefix;
    private final InstanceField mySQLHost;
    private final InstanceField mySQLPort;
    private final InstanceField mySQLDatabase;
    private final InstanceField mySQLUsername;
    private final InstanceField mySQLPassword;
    private final InstanceField tls;
    private final InstanceField poolSize;
    private final InstanceField databaseLock;
    private final StaticField path;
    private final StaticField host;
    private final StaticField port;
    private final StaticField database;
    private final StaticField username;
    private final StaticField password;
    private final StaticField maximumPoolSize;
    private final StaticField prefix;
    private final StaticField prefixConfig;
    private final StaticField configFile;
    private final StaticMethod<Void, RuntimeException> loadDatabase;

    private UseMySQLSelection(Upstream upstream) throws Missing {
        UpstreamClass config = upstream.type(Names.CONFIG);
        global = config.staticMethod("getGlobal", config.type());
        newConfig = config.constructor();
        load = config.method("load", void.class, InputStream.class).throwing(IOException.class);
        // Selecting a database and switching back set these
        mySQL = config.writableField("MYSQL", boolean.class);
        globalPrefix = config.writableField("PREFIX", String.class);
        mySQLHost = config.writableField("MYSQL_HOST", String.class);
        mySQLPort = config.writableField("MYSQL_PORT", int.class);
        mySQLDatabase = config.writableField("MYSQL_DATABASE", String.class);
        mySQLUsername = config.writableField("MYSQL_USERNAME", String.class);
        mySQLPassword = config.writableField("MYSQL_PASSWORD", String.class);
        tls = config.writableField("ENABLE_SSL", boolean.class);
        poolSize = config.writableField("MAXIMUM_POOL_SIZE", int.class);
        databaseLock = config.field("DATABASE_LOCK", boolean.class);
        UpstreamClass handler = upstream.type(Names.CONFIG_HANDLER);
        path = handler.staticField("path", String.class);
        host = handler.writableStaticField("host", String.class);
        port = handler.writableStaticField("port", int.class);
        database = handler.writableStaticField("database", String.class);
        username = handler.writableStaticField("username", String.class);
        password = handler.writableStaticField("password", String.class);
        maximumPoolSize = handler.writableStaticField("maximumPoolSize", int.class);
        prefix = handler.writableStaticField("prefix", String.class);
        prefixConfig = handler.writableStaticField("prefixConfig", String.class);
        configFile = upstream.type(Names.CONFIG_FILE).staticField("CONFIG", String.class);
        loadDatabase = handler.staticMethod("loadDatabase", void.class);

        upstream.relyOn("reloads the database that Config.MYSQL and ConfigHandler's connection settings select,"
            + " keeping the caches of identifiers; throws when MySQL's pool can't connect, and reports other"
            + " failures instead of throwing them", loadDatabase);
        upstream.relyOn("clears Config.MYSQL, falling back to SQLite, when MySQL's pool connected but its tables"
            + " can't be created", Names.DATABASE, "createDatabaseTables(Ljava/lang/String;ZLjava/sql/Connection;ZZ)V");
        upstream.relyOn("closes MySQL's pool, so that the next database can be loaded", Names.DATABASE,
            "closeConnection()V");
        upstream.relyOn("reads config.yml's settings the way CoreProtect reads them when it starts", Names.CONFIG,
            "load(Ljava/io/InputStream;)V");
        upstream.relyOn("parses config.yml's lines into settings", Names.CONFIG_FILE,
            "load(Ljava/io/InputStream;Ljava/util/Map;Z)V");
        upstream.relyOn("copies config.yml's MySQL settings into ConfigHandler whichever database use-mysql selects,"
            + " and keeps the configured table-prefix in prefixConfig for SQLite", Names.CONFIG_HANDLER,
            "loadConfig()V");
    }

    static UseMySQLSelection probe(Upstream upstream) throws Missing {
        return new UseMySQLSelection(upstream);
    }

    /**
     * @return {@code null}: CoreProtect 24's migration docs edit the
     *         target's settings in config.yml without loading them
     */
    @Override
    public DatabaseSettings loadedTargetSettings(Engine source, Engine target,
                                                 Function<String, DatabaseSettings> loaded) {
        return null;
    }

    /**
     * A MySQL target's settings come from config.yml as it is now; SQLite's
     * file is CoreProtect's.
     */
    @Override
    public DatabaseSettings targetSettings(Engine source, Engine target, Function<String, DatabaseSettings> loaded)
        throws MigrationException {
        if (target != Engine.MYSQL) {
            return loaded.apply("co_");
        }
        Object config = readConfig();
        return DatabaseSettings.server(Engine.MYSQL, (String) mySQLHost.get(config), mySQLPort.getInt(config),
            (String) mySQLDatabase.get(config), (String) mySQLUsername.get(config),
            (String) mySQLPassword.get(config), tls.getBoolean(config), (String) globalPrefix.get(config));
    }

    @Override
    public String targetSettingsChanged(Engine target) {
        return "config.yml's " + target.displayName() + " settings changed after the migration began";
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
     * config.yml's {@code use-mysql} changes during the migration, so the
     * file has to be replaceable.
     */
    @Override
    public void preflight() throws MigrationException {
        File file = configFile();
        try {
            ConfigValueWriter.checkReplaceable(file.toPath(), false);
        } catch (IOException e) {
            throw new MigrationException("The migration couldn't select a database in " + file + ": "
                + e.getMessage() + ".", e);
        }
    }

    /**
     * Make config.yml select the source until the switch, so that a restart
     * during the copy keeps using the source rather than the unfinished
     * target, which the docs' workflow has already selected.
     */
    @Override
    public List<String> whileCopying(Engine source, Engine target) throws MigrationException {
        boolean selectMySQL = source == Engine.MYSQL;
        if (mySQL.getBoolean(readConfig()) == selectMySQL) {
            return Collections.emptyList();
        }
        try {
            ConfigValueWriter.set(configFile().toPath(), "use-mysql", Boolean.toString(selectMySQL));
        } catch (IOException e) {
            throw new MigrationException("The migration couldn't select " + source.displayName() + " in config.yml"
                + " while it copies: " + e.getMessage(), e);
        }
        return Collections.singletonList("config.yml selects " + source.displayName() + " (use-mysql: "
            + selectMySQL + ") while the migration runs, so a restart in between keeps using it, and "
            + target.displayName() + " once it succeeds. The " + target.displayName() + " settings stay as they are.");
    }

    @Override
    public Selected current() {
        Object config = global.call();
        boolean wasMySQL = mySQL.getBoolean(config);
        Object wasGlobalPrefix = globalPrefix.get(config);
        Object wasMySQLHost = mySQLHost.get(config);
        int wasMySQLPort = mySQLPort.getInt(config);
        Object wasMySQLDatabase = mySQLDatabase.get(config);
        Object wasMySQLUsername = mySQLUsername.get(config);
        Object wasMySQLPassword = mySQLPassword.get(config);
        boolean wasTls = tls.getBoolean(config);
        int wasPoolSize = poolSize.getInt(config);
        Object wasHost = host.get();
        int wasPort = port.getInt();
        Object wasDatabase = database.get();
        Object wasUsername = username.get();
        Object wasPassword = password.get();
        int wasMaximumPoolSize = maximumPoolSize.getInt();
        Object wasPrefix = prefix.get();
        Object wasPrefixConfig = prefixConfig.get();
        return () -> {
            mySQL.setBoolean(config, wasMySQL);
            globalPrefix.set(config, wasGlobalPrefix);
            mySQLHost.set(config, wasMySQLHost);
            mySQLPort.setInt(config, wasMySQLPort);
            mySQLDatabase.set(config, wasMySQLDatabase);
            mySQLUsername.set(config, wasMySQLUsername);
            mySQLPassword.set(config, wasMySQLPassword);
            tls.setBoolean(config, wasTls);
            poolSize.setInt(config, wasPoolSize);
            host.set(wasHost);
            port.setInt(wasPort);
            database.set(wasDatabase);
            username.set(wasUsername);
            password.set(wasPassword);
            maximumPoolSize.setInt(wasMaximumPoolSize);
            prefix.set(wasPrefix);
            prefixConfig.set(wasPrefixConfig);
        };
    }

    /**
     * Make CoreProtect use the target's settings, as if it had started with
     * them; the pool size comes from config.yml as it is now.
     */
    @Override
    public void select(Engine target, DatabaseSettings settings) throws MigrationException {
        Object file = readConfig();
        Object config = global.call();
        if (target == Engine.MYSQL) {
            mySQL.setBoolean(config, true);
            globalPrefix.set(config, settings.prefix());
            mySQLHost.set(config, settings.host());
            mySQLPort.setInt(config, settings.port());
            mySQLDatabase.set(config, settings.database());
            mySQLUsername.set(config, settings.username());
            mySQLPassword.set(config, settings.password());
            tls.setBoolean(config, settings.tls());
            poolSize.setInt(config, poolSize.getInt(file));
            host.set(settings.host());
            port.setInt(settings.port());
            database.set(settings.database());
            username.set(settings.username());
            password.set(settings.password());
            maximumPoolSize.setInt(poolSize.getInt(file));
            prefix.set(settings.prefix());
        } else {
            mySQL.setBoolean(config, false);
            prefixConfig.set(globalPrefix.get(file));
            globalPrefix.set(config, settings.prefix());
            prefix.set(settings.prefix());
        }
    }

    @Override
    public void load() {
        loadDatabase.call();
    }

    @Override
    public String persist(Engine target) throws IOException, MigrationException {
        boolean selectMySQL = target == Engine.MYSQL;
        String setting = "use-mysql: " + selectMySQL;
        if (mySQL.getBoolean(readConfig()) == selectMySQL) {
            return "config.yml already selects " + target.displayName() + " (" + setting + ").";
        }
        ConfigValueWriter.set(configFile().toPath(), "use-mysql", Boolean.toString(selectMySQL));
        if (mySQL.getBoolean(readConfig()) != selectMySQL) {
            throw new IOException("config.yml still doesn't select " + target.displayName() + " after setting "
                + setting);
        }
        return "config.yml now selects " + target.displayName() + " (" + setting + ").";
    }

    /**
     * After a failure, make config.yml select the database that CoreProtect
     * uses, if it selects another: the one the docs' workflow selected before
     * the migration, or none that CoreProtect could start on.
     */
    @Override
    public List<String> afterFailure() {
        boolean inUse;
        try {
            inUse = mySQL.getBoolean(global.call());
        } catch (RuntimeException e) {
            return Collections.emptyList();
        }
        try {
            if (mySQL.getBoolean(readConfig()) == inUse) {
                return Collections.emptyList();
            }
            ConfigValueWriter.set(configFile().toPath(), "use-mysql", Boolean.toString(inUse));
            return Collections.singletonList("config.yml selects " + (inUse ? "MySQL" : "SQLite") + " again"
                + " (use-mysql: " + inUse + "), the database CoreProtect uses.");
        } catch (MigrationException | IOException | RuntimeException e) {
            return Collections.singletonList("config.yml doesn't select the database CoreProtect uses, and couldn't be"
                + " changed (" + CoreProtectMigrationSession.message(e) + "). Set use-mysql: " + inUse + " before the"
                + " server restarts.");
        }
    }

    @Override
    public String markedAgain() {
        return "The target is marked as an unfinished migration again, so CoreProtect refuses to start on it.";
    }

    /**
     * @return config.yml as it is now, read with CoreProtect's own parser
     */
    private Object readConfig() throws MigrationException {
        File file = configFile();
        try (InputStream in = new FileInputStream(file)) {
            Object config = newConfig.create();
            load.call(config, in);
            return config;
        } catch (IOException e) {
            throw new MigrationException("Couldn't read " + file + ": " + e.getMessage(), e);
        }
    }

    private File configFile() {
        return new File((String) path.get(), (String) configFile.get());
    }
}
