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

package net.deltik.mc.libreprotect.extension.common;

import java.io.File;
import java.util.Objects;

/**
 * Where a CoreProtect database is and how to reach it. Embedded engines use
 * {@link #file()}; the others use the network settings.
 */
public final class DatabaseSettings {

    private final Engine engine;
    private final File file;
    private final String host;
    private final int port;
    private final String database;
    private final String username;
    private final String password;
    private final boolean tls;
    private final String prefix;

    private DatabaseSettings(Engine engine, File file, String host, int port, String database, String username,
                             String password, boolean tls, String prefix) {
        this.engine = Objects.requireNonNull(engine, "engine");
        this.file = file;
        this.host = host;
        this.port = port;
        this.database = database;
        this.username = username;
        this.password = password;
        this.tls = tls;
        this.prefix = Objects.requireNonNull(prefix, "prefix");
    }

    /**
     * An embedded database. CoreProtect always uses the table prefix {@code co_} for these.
     */
    public static DatabaseSettings embedded(Engine engine, File file) {
        if (!engine.isEmbedded()) {
            throw new IllegalArgumentException(engine + " is not an embedded engine");
        }
        return new DatabaseSettings(engine, Objects.requireNonNull(file, "file"), null, 0, null, null, null,
            false, "co_");
    }

    /**
     * A database server.
     *
     * @param tls whether to connect with TLS (MySQL's {@code enable-ssl}, ClickHouse's {@code clickhouse-tls})
     */
    public static DatabaseSettings server(Engine engine, String host, int port, String database, String username,
                                          String password, boolean tls, String prefix) {
        if (engine.isEmbedded()) {
            throw new IllegalArgumentException(engine + " is an embedded engine");
        }
        return new DatabaseSettings(engine, null, Objects.requireNonNull(host, "host"), port,
            Objects.requireNonNull(database, "database"), username, password == null ? "" : password, tls, prefix);
    }

    public Engine engine() {
        return engine;
    }

    /**
     * @return the database file, for embedded engines, otherwise {@code null}
     */
    public File file() {
        return file;
    }

    public String host() {
        return host;
    }

    public int port() {
        return port;
    }

    public String database() {
        return database;
    }

    public String username() {
        return username;
    }

    public String password() {
        return password;
    }

    public boolean tls() {
        return tls;
    }

    /**
     * @return the table prefix, e.g. {@code co_}
     */
    public String prefix() {
        return prefix;
    }

    /**
     * @return whether {@code other} is the same database, reached the same
     *         way: every setting is equal, the password included
     */
    public boolean sameAs(DatabaseSettings other) {
        return other != null && engine == other.engine && Objects.equals(file, other.file)
            && Objects.equals(host, other.host) && port == other.port && Objects.equals(database, other.database)
            && Objects.equals(username, other.username) && Objects.equals(password, other.password)
            && tls == other.tls && prefix.equals(other.prefix);
    }

    /**
     * @return where the database is, for messages; never includes the password
     */
    public String describe() {
        if (engine.isEmbedded()) {
            return engine.displayName() + " database " + file.getPath();
        }
        return engine.displayName() + " database '" + database + "' on " + host + ":" + port
            + " (table prefix '" + prefix + "')";
    }

    @Override
    public String toString() {
        return describe();
    }
}
