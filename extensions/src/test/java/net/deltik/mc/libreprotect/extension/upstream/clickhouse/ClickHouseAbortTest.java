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

import net.deltik.mc.libreprotect.extension.migration.Row;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Config;
import net.deltik.mc.libreprotect.extension.upstream.clickhouse.ClickHouseApi.Target;
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Aborting a ClickHouse source or sink from another thread, as a migration's
 * watchdog does when the migration has to stop, while a call waits on a
 * server that doesn't answer.
 */
class ClickHouseAbortTest {

    /** How soon an aborted call must fail */
    private static final long PROMPTLY_MILLIS = 3_000;
    private static final List<String> CHAT = List.of("time", "user", "wid", "x", "y", "z", "message");

    @TempDir
    Path controlDirectory;

    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final List<AutoCloseable> closeables = new ArrayList<>();
    private ClickHouseApi api;

    @BeforeEach
    void setUpApi() {
        api = ClickHouseTestServer.writes();
    }

    @AfterEach
    void tearDown() throws Exception {
        executor.shutdownNow();
        for (int index = closeables.size() - 1; index >= 0; index--) {
            closeables.get(index).close();
        }
    }

    private <T extends AutoCloseable> T closing(T closeable) {
        closeables.add(closeable);
        return closeable;
    }

    private ClickHouseRowSink sink(Config config, String prefix) throws SQLException {
        return closing(new ClickHouseRowSink(api, config, prefix, controlDirectory, "2.24.1",
            (map, floor, candidates) -> List.of(), new PublishDeadline(ClickHouseRowSink.PUBLISH_LIMIT, () -> false),
            ClickHouseTestServer.serverVersion()));
    }

    /**
     * Start a call in another thread, check that it waits, abort, and check
     * that it fails promptly
     */
    private SQLException abortWhileWaiting(Callable<?> call, Runnable abort) throws Exception {
        Future<?> waiting = executor.submit(call);
        Thread.sleep(1_000);
        assertFalse(waiting.isDone(), "the call waits for the server");
        long start = System.nanoTime();
        abort.run();
        ExecutionException failure = assertThrows(ExecutionException.class,
            () -> waiting.get(PROMPTLY_MILLIS, TimeUnit.MILLISECONDS), "the aborted call failed promptly");
        long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        assertTrue(millis < PROMPTLY_MILLIS, "failed after " + millis + " ms");
        return assertInstanceOf(SQLException.class, failure.getCause());
    }

    private static void assertAborted(Callable<?> call) {
        SQLException e = assertThrows(SQLException.class, call::call);
        assertInstanceOf(SQLNonTransientConnectionException.class, e, e.toString());
        assertTrue(e.getMessage().endsWith("stopped because the migration is stopping"), e.getMessage());
    }

    @Nested
    @DisplayName("Without a ClickHouse server")
    class Unresponsive {

        @Test
        @DisplayName("should end a table stream waiting on a server that doesn't answer, and every call after")
        void stream() throws Exception {
            UnresponsiveClickHouse clickHouse = closing(new UnresponsiveClickHouse());
            ClickHouseRowSource source = closing(new ClickHouseRowSource(api, clickHouse.config(api), "co_"));

            abortWhileWaiting(() -> source.read("chat", CHAT, 0, 10), source::abort);

            assertTrue(clickHouse.awaitQuery(0));
            assertAborted(() -> source.read("chat", CHAT, 0, 10));
            assertAborted(() -> source.stats("chat"));
            assertAborted(source::tables);
            assertTimeoutPreemptively(Duration.ofSeconds(5), source::close);
        }

        @Test
        @DisplayName("should end a short query waiting on a server that doesn't answer")
        void shortQuery() throws Exception {
            UnresponsiveClickHouse clickHouse = closing(new UnresponsiveClickHouse());
            ClickHouseRowSource source = closing(new ClickHouseRowSource(api, clickHouse.config(api), "co_"));

            abortWhileWaiting(() -> source.stats("chat"), source::abort);

            assertAborted(() -> source.readRanges("chat", CHAT, List.of(new long[]{1, 2})));
            assertAborted(() -> source.highWater("chat"));
        }

        @Test
        @DisplayName("should end a sink's check of the server's version waiting on a server that doesn't answer, as a"
            + " failure rather than a refusal")
        void sinkVersionCheck() throws Exception {
            UnresponsiveClickHouse clickHouse = closing(new UnresponsiveClickHouse());
            ClickHouseRowSink sink = sink(clickHouse.config(api), "co_");

            abortWhileWaiting(sink::unsupportedReason, sink::abort);

            assertAborted(sink::unsupportedReason);
        }

        @Test
        @DisplayName("should end a sink's query waiting on a server that doesn't answer, and every call after")
        void sinkQuery() throws Exception {
            UnresponsiveClickHouse clickHouse = closing(new UnresponsiveClickHouse());
            ClickHouseRowSink sink = sink(clickHouse.config(api), "co_");

            abortWhileWaiting(sink::nonEmptyReason, sink::abort);

            assertAborted(sink::nonEmptyReason);
            assertAborted(() -> {
                sink.prepare(Map.of());
                return null;
            });
            assertAborted(() -> sink.columns("chat"));
            assertAborted(sink::readBack);
            assertTimeoutPreemptively(Duration.ofSeconds(5), sink::close);
        }

        @Test
        @DisplayName("should never throw, and fail every call after, even before any work or when repeated")
        void idle() throws Exception {
            Config nowhere = api.config("127.0.0.1", 1, "coreprotect", "coreprotect", "", false);
            ClickHouseRowSource source = closing(new ClickHouseRowSource(api, nowhere, "co_"));
            ClickHouseRowSink sink = sink(nowhere, "co_");

            assertDoesNotThrow(source::abort);
            assertDoesNotThrow(source::abort);
            assertDoesNotThrow(sink::abort);
            assertDoesNotThrow(sink::abort);

            assertAborted(source::tables);
            assertAborted(sink::unsupportedReason);
            assertAborted(() -> sink.columns("block"));
            assertAborted(() -> {
                sink.markIncomplete();
                return null;
            });
            assertThrows(IllegalStateException.class, () -> ClickHouseEndpoints.preparedDatabase(sink));
            source.close();
            sink.close();
        }
    }

    @Nested
    @DisplayName("With ClickHouse")
    class Stalled {

        private ClickHouseTestServer server;
        private String prefix;
        private StallingProxy proxy;

        @BeforeEach
        void setUp() throws Exception {
            server = closing(ClickHouseTestServer.connect());
            server.assumeWriterSupported();
            prefix = server.newPrefix();
            proxy = closing(server.stallingProxy());
        }

        @Test
        @DisplayName("should end a table stream that stops arriving midway")
        void streamMidway() throws Exception {
            server.createSchema(prefix, controlDirectory.resolve("schema"));
            // Incompressible, so the stream outgrows every buffer on the way
            server.insertRandomChat(prefix, 200_000);
            ClickHouseRowSource source = closing(new ClickHouseRowSource(api, server.config(proxy), prefix));
            List<Row> first = source.read("chat", CHAT, 0, 1_000);
            assertEquals(1_000, first.size());

            proxy.stall();
            abortWhileWaiting(() -> source.read("chat", CHAT, 1_000, 199_000), source::abort);

            assertAborted(() -> source.read("chat", CHAT, 1_000, 10));
            assertTimeoutPreemptively(Duration.ofSeconds(5), source::close);
        }

        @Test
        @DisplayName("should end an insert that ClickHouse doesn't answer, and release the writer registration")
        void insert() throws Exception {
            ClickHouseRowSink sink = sink(server.config(proxy), prefix);
            sink.prepare(Map.of());
            sink.markIncomplete();
            List<Row> rows = List.of(new Row(1, new Object[]{1_700_000_000L, 1L, 1L, 0L, 64L, 0L, "hello"}));

            proxy.stall();
            SQLException failure = abortWhileWaiting(() -> {
                sink.write("chat", CHAT, rows);
                return null;
            }, sink::abort);

            assertInstanceOf(PublishDeadline.ExpiredException.class, failure, failure.toString());
            assertTrue(failure.getMessage().startsWith("Writing the 1 chat rows with row IDs 1 to 1 to ClickHouse"
                + " stopped because the migration is stopping"), failure.getMessage());
            assertAborted(() -> {
                sink.write("chat", CHAT, rows);
                return null;
            });
            assertAborted(() -> {
                sink.markComplete();
                return null;
            });
            assertTimeoutPreemptively(Duration.ofSeconds(5), sink::close);
            // Another target can be prepared in the same data folder, so the aborted one let go
            proxy.resume();
            sink(server.config(), server.newPrefix()).prepare(Map.of());
        }

        @Test
        @DisplayName("should end a validation read that ClickHouse doesn't answer")
        void readBack() throws Exception {
            ClickHouseRowSink sink = sink(server.config(proxy), prefix);
            sink.prepare(Map.of());
            RowSource copy = sink.readBack();
            assertEquals(0, copy.stats("chat").count());

            proxy.stall();
            abortWhileWaiting(() -> copy.stats("chat"), sink::abort);

            assertAborted(() -> copy.stats("chat"));
        }

        @Test
        @DisplayName("should leave a database handed over to CoreProtect alone, as activation still uses it")
        void handedOver() throws Exception {
            ClickHouseRowSink sink = sink(server.config(), prefix);
            sink.prepare(Map.of());
            sink.markIncomplete();
            Target prepared = ClickHouseEndpoints.preparedDatabase(sink);
            closing(prepared);

            sink.abort();

            try (Connection connection = prepared.openConnection(); Statement statement = connection.createStatement();
                 ResultSet resultSet = statement.executeQuery("SELECT 1")) {
                assertTrue(resultSet.next());
            }
            ClickHouseRowSink other = sink(server.config(), server.newPrefix());
            SQLException e = assertThrows(SQLException.class, () -> other.prepare(Map.of()));
            assertTrue(e.getMessage().contains("already has an active ClickHouse writer"), e.getMessage());
            // Activation clears the mark through the handed-over database, and marks it again if it fails
            sink.markComplete();
            assertEquals("0", server.queryString("SELECT toString(status) FROM "
                + server.table(prefix, "database_lock")));
            sink.markIncomplete();
            assertEquals("2", server.queryString("SELECT toString(status) FROM "
                + server.table(prefix, "database_lock")));
            assertAborted(() -> sink.columns("chat"));
            sink.close();
            try (Connection connection = prepared.openConnection()) {
                assertTrue(connection.isValid(5), "closing the aborted sink leaves the handed-over database open");
            }
        }

        @Test
        @DisplayName("should abort only its own connections, not CoreProtect's database it reads")
        void activeSource(@TempDir Path activeDirectory) throws Exception {
            Target active = closing(api.initialize(server.config(), prefix, activeDirectory));
            ClickHouseRowSource source = closing(new ClickHouseRowSource(api, server.config(), prefix));
            assertEquals(0, source.stats("chat").count());

            source.abort();

            assertAborted(() -> source.stats("chat"));
            try (Connection connection = active.openConnection(); Statement statement = connection.createStatement();
                 ResultSet resultSet = statement.executeQuery("SELECT count() FROM " + server.table(prefix, "chat"))) {
                assertTrue(resultSet.next());
            }
            active.ensureCoreData("2.24.1");
            assertEquals("1", server.queryString("SELECT toString(count()) FROM " + server.table(prefix, "version")));
        }
    }
}
