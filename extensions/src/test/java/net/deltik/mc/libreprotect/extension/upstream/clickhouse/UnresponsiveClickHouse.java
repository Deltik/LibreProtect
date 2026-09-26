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

import com.sun.net.httpserver.HttpServer;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Config;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * A loopback stand-in for ClickHouse's HTTP interface that accepts
 * connections, answers the driver's connection check, and then never
 * answers a query, like a server that hangs.
 */
final class UnresponsiveClickHouse implements AutoCloseable {

    private final HttpServer server;
    private final ExecutorService executor = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "Unresponsive ClickHouse");
        thread.setDaemon(true);
        return thread;
    });
    private final CountDownLatch released = new CountDownLatch(1);
    private final CountDownLatch queried = new CountDownLatch(1);

    UnresponsiveClickHouse() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(executor);
        server.createContext("/", exchange -> {
            String sql = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            // The driver checks each new connection with this
            if (sql.trim().equals("SELECT 1 FORMAT TabSeparated")) {
                byte[] reply = "1\n".getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, reply.length);
                exchange.getResponseBody().write(reply);
                exchange.close();
                return;
            }
            queried.countDown();
            try {
                released.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            exchange.close();
        });
        server.start();
    }

    Config config(ClickHouseApi api) {
        return api.config("127.0.0.1", server.getAddress().getPort(), "coreprotect", "coreprotect", "", false);
    }

    /**
     * @return whether a query arrived, and is now waiting for an answer
     */
    boolean awaitQuery(long seconds) throws InterruptedException {
        return queried.await(seconds, TimeUnit.SECONDS);
    }

    @Override
    public void close() {
        released.countDown();
        server.stop(0);
        executor.shutdownNow();
    }
}
