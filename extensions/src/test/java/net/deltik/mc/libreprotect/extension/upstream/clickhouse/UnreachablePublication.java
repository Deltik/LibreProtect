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
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Config;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Pool;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Creator;
import net.deltik.mc.libreprotect.extension.upstream.reflect.InstanceMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;

import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.UUID;

/**
 * Publishes through CoreProtect's own ClickHouse publisher to a server that
 * isn't there, so tests can see how CoreProtect retries without a container.
 * The publisher and what it needs aren't public, so this builds them by
 * reflection, through the toolkit.
 */
final class UnreachablePublication implements AutoCloseable {

    private static final String PACKAGE = "net.coreprotect.database.clickhouse.";

    private final Pool jdbc;
    private final Object client;
    private final Object registration;
    private final Object publisher;
    private final StaticMethod<?, RuntimeException> newIdentity;
    private final Object allocator;
    private final Creator newBatch;
    private final InstanceMethod<?, RuntimeException> events;
    private final InstanceMethod<?, SQLException> addDatabaseLockVersion;
    private final InstanceMethod<?, SQLException> publish;
    private final InstanceMethod<?, RuntimeException> closeBatch;
    private final InstanceMethod<?, SQLException> closeRegistration;
    private final InstanceMethod<?, RuntimeException> closeClient;

    /**
     * @param controlDirectory where to register as the ClickHouse writer
     */
    UnreachablePublication(ClickHouseApi api, Path controlDirectory) throws Missing, SQLException {
        Upstream upstream = Upstream.coreProtect();
        // Nothing listens on port 1, so every connection is refused at once
        Config config = api.config("127.0.0.1", 1, "coreprotect", "coreprotect", "", false);
        jdbc = api.pool(config);
        UpstreamClass clientClass = upstream.type(Names.CLICKHOUSE_NATIVE_CLIENT);
        client = clientClass.constructor(config.upstream().getClass()).create(config.upstream());
        closeClient = clientClass.method("close", void.class);
        UpstreamClass registrationClass = upstream.type(Names.CLICKHOUSE_WRITER_REGISTRATION);
        registration = registrationClass.constructor(Path.class).create(controlDirectory);
        closeRegistration = registrationClass.method("close", void.class).throwing(SQLException.class);
        registrationClass.method("acquire", void.class).throwing(SQLException.class).call(registration);
        UpstreamClass publisherClass = upstream.type(Names.CLICKHOUSE_BATCH_PUBLISHER);
        publisher = publisherClass.constructor(jdbc.upstream().getClass(), clientClass.type(),
            registrationClass.type(), String.class, String.class)
            .create(jdbc.upstream(), client, registration, "coreprotect", "co_");

        UpstreamClass identityClass = upstream.type(PACKAGE + "ClickHouseBatchIdentity");
        newIdentity = identityClass.staticMethod("create", identityClass.type(), UUID.class, long.class);
        // Every row ID is 1
        Class<?> allocatorType = upstream.type(PACKAGE + "ClickHouseRowIdAllocator").type();
        allocator = Proxy.newProxyInstance(allocatorType.getClassLoader(), new Class<?>[]{allocatorType},
            (proxy, method, args) -> {
                switch (method.getName()) {
                    case "nextRowId":
                        return 1L;
                    case "hashCode":
                        return System.identityHashCode(proxy);
                    case "equals":
                        return proxy == args[0];
                    case "toString":
                        return "every row ID is 1";
                    default:
                        return null;
                }
            });
        UpstreamClass batchClass = upstream.type(Names.CLICKHOUSE_WRITE_BATCH);
        UpstreamClass eventsClass = upstream.type(Names.CLICKHOUSE_EVENT_BATCH);
        newBatch = batchClass.constructor(identityClass.type(), allocatorType);
        events = batchClass.method("events", eventsClass.type());
        closeBatch = batchClass.method("close", void.class);
        addDatabaseLockVersion = eventsClass.method("addDatabaseLockVersion", long.class, long.class, int.class,
            int.class).throwing(SQLException.class);
        publish = publisherClass.method("publish", Object.class, batchClass.type()).throwing(SQLException.class);
    }

    /**
     * Publish a database lock row, as a migration's incomplete mark does.
     * Fails for as long as CoreProtect keeps retrying.
     */
    void publish() throws SQLException {
        Object batch = newBatch.create(newIdentity.call(UUID.randomUUID(), 1L), allocator);
        try {
            addDatabaseLockVersion.call(events.call(batch), 1L, 1, 2);
            publish.call(publisher, batch);
        } finally {
            closeBatch.call(batch);
        }
    }

    @Override
    public void close() throws SQLException {
        try {
            closeRegistration.call(registration);
        } finally {
            try {
                closeClient.call(client);
            } finally {
                jdbc.close();
            }
        }
    }
}
