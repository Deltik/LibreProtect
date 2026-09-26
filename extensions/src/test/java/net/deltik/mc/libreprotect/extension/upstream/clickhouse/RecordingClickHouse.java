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
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * A loopback stand-in for ClickHouse's HTTP interface that records each
 * query with the settings sent along, and refuses it.
 */
final class RecordingClickHouse implements AutoCloseable {

    /**
     * A query as the ClickHouse client sent it
     *
     * @param settings the URL's query string, where the client puts server settings
     */
    record Request(String sql, String settings) {
    }

    private final HttpServer server;
    private final List<Request> requests = new ArrayList<>();

    RecordingClickHouse() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String sql = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            URI uri = exchange.getRequestURI();
            synchronized (requests) {
                requests.add(new Request(sql, uri.getRawQuery() == null ? "" : uri.getRawQuery()));
            }
            byte[] reply = "Code: 497. DB::Exception: Refused by the test. (ACCESS_DENIED)"
                .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("X-ClickHouse-Exception-Code", "497");
            exchange.sendResponseHeaders(500, reply.length);
            exchange.getResponseBody().write(reply);
            exchange.close();
        });
        server.start();
    }

    Config config(ClickHouseApi api) {
        return api.config("127.0.0.1", server.getAddress().getPort(), "coreprotect", "coreprotect", "", false);
    }

    /**
     * @return the recorded queries that contain the text
     */
    List<Request> requests(String sqlContaining) {
        List<Request> matching = new ArrayList<>();
        synchronized (requests) {
            for (Request request : requests) {
                if (request.sql().contains(sqlContaining)) {
                    matching.add(request);
                }
            }
        }
        return matching;
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
