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

import net.deltik.mc.libreprotect.extension.upstream.Capabilities;
import net.deltik.mc.libreprotect.extension.upstream.Names;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.testutil.AssumeCapability;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.ValueSource;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLTransientConnectionException;
import java.sql.SQLTransientException;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Which ClickHouse servers a migration to ClickHouse takes before it starts:
 * those that CoreProtect's own check takes, or on a CoreProtect whose check
 * LibreProtect can't find, all of them, for CoreProtect's check to refuse
 * once the migration opens the target.
 */
class ClickHouseServerVersionTest {

    private static final String ID = "migrate-db.clickhouse-version";

    /**
     * @return CoreProtect's own check, or skip the test on a CoreProtect without it
     */
    private static ClickHouseServerVersion coreProtectCheck() {
        return (ClickHouseServerVersion) AssumeCapability.strategy(ID, "coreprotect-check").orElse(null);
    }

    @ParameterizedTest
    @ValueSource(strings = {"#requireServerVersion", "#requireServerVersion(Ljava/sql/Connection;)V"})
    @DisplayName("should check nothing before the migration starts on a CoreProtect whose check it can't find")
    void whenOpened(String hidden) throws SQLException {
        ClickHouseTestServer.serverVersion();
        Choice<ClickHouseServerVersion> choice = Capabilities.probe(Upstream.coreProtect().hiding(
            Names.CLICKHOUSE_DATABASE + hidden)).get(ClickHouseServerVersion.CAPABILITY);

        assertEquals("when-opened", choice.strategy(), choice::toString);
        assertEquals("CoreProtect's own check of the server's version, only once the migration opens the target,"
            + " since LibreProtect can't run it before", choice.reason());
        assertEquals(1, choice.rejected().size(), choice.rejected()::toString);
        assertTrue(choice.rejected().get(0).startsWith("coreprotect-check: "), choice.rejected()::toString);
        ClickHouseServerVersion whenOpened = choice.orElse(null);
        assertFalse(whenOpened.isCoreProtectCheck());
        // It doesn't even ask the server
        assertEquals(Optional.empty(), whenOpened.refusal(stub(Connection.class, (method, args) -> {
            throw new UnsupportedOperationException(method.getName());
        })));
    }

    @Test
    @DisplayName("should refuse what CoreProtect's check refuses, in its words")
    void coreProtectRefusals() throws SQLException {
        AssumeCapability.reviewedUpstream();
        ClickHouseServerVersion coreProtect = coreProtectCheck();

        assertTrue(coreProtect.isCoreProtectCheck());
        assertEquals(Optional.of("ClickHouse 26.1 or newer is required; found 25.8.3.66"),
            coreProtect.refusal(answering("25.8.3.66", true)));
        assertEquals(Optional.of("Unsupported ClickHouse server version: unknown"),
            coreProtect.refusal(answering("unknown", true)));
        assertEquals(Optional.of("ClickHouse did not return its server version"),
            coreProtect.refusal(answering(null, false)));
        assertEquals(Optional.empty(), coreProtect.refusal(answering("26.1.2.11", true)));
        assertEquals(Optional.empty(), coreProtect.refusal(answering("26.3.33.24", true)));
    }

    @Test
    @DisplayName("should take a failure of the check for a refusal only if the server answers its query")
    void refusalOrFailure() throws SQLException {
        SQLTransientException busy = new SQLTransientException("Code: 202. DB::Exception: Too many simultaneous"
            + " queries. (TOO_MANY_SIMULTANEOUS_QUERIES)");
        ClickHouseServerVersion refusing = ClickHouseServerVersion.checking(connection -> {
            throw new SQLException("ClickHouse 99.1 or newer is required; found 26.3.33.24");
        });

        assertEquals(Optional.of("ClickHouse 99.1 or newer is required; found 26.3.33.24"),
            refusing.refusal(answering("26.3.33.24", true)));
        assertSame(busy, assertThrows(SQLTransientException.class, () -> ClickHouseServerVersion.checking(
            connection -> connection.prepareStatement("SELECT version()")).refusal(failing(busy))));
        SQLException refusedOrBusy = assertThrows(SQLException.class, () -> refusing.refusal(failing(busy)));
        assertEquals("ClickHouse 99.1 or newer is required; found 26.3.33.24", refusedOrBusy.getMessage());
        assertSame(busy, refusedOrBusy.getSuppressed()[0]);
        // Such as CoreProtect's check on a server too busy to answer, although its connection is valid
        ClickHouseServerVersion coreProtect = coreProtectCheck();
        assertSame(busy, assertThrows(SQLTransientException.class, () -> coreProtect.refusal(failing(busy))));
    }

    @Test
    @DisplayName("should take the test server, asking it over the connection it's given")
    void testServer() throws Exception {
        try (ClickHouseTestServer server = ClickHouseTestServer.connect();
             ClickHouseApi.Pool pool = server.api().pool(server.config());
             Connection connection = pool.openConnection()) {
            server.assumeWriterSupported();
            ClickHouseServerVersion refusing = ClickHouseServerVersion.checking(ignored -> {
                throw new SQLException("Refused by the test");
            });

            assertEquals(Optional.empty(), coreProtectCheck().refusal(connection));
            assertEquals(Optional.of("Refused by the test"), refusing.refusal(connection));
        }
    }

    @Test
    @DisplayName("should take a transient failure of the check for no refusal once the server answers a version it"
        + " takes")
    void transientFailure() throws SQLException {
        SQLTransientConnectionException reset = new SQLTransientConnectionException("Connection reset");
        // Decides by the version alone, as CoreProtect's does
        ClickHouseServerVersion only26 = ClickHouseServerVersion.checking(connection -> {
            try (PreparedStatement statement = connection.prepareStatement("SELECT version()");
                 ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next() || !resultSet.getString(1).startsWith("26.")) {
                    throw new SQLException("Only 26 will do");
                }
            }
        });

        assertSame(reset, assertThrows(SQLTransientConnectionException.class,
            () -> only26.refusal(flaky(reset, "26.3.33.24"))));
        assertEquals(Optional.of("Only 26 will do"), only26.refusal(flaky(reset, "25.8.3.66")));
        AssumeCapability.reviewedUpstream();
        ClickHouseServerVersion coreProtect = coreProtectCheck();
        assertSame(reset, assertThrows(SQLTransientConnectionException.class,
            () -> coreProtect.refusal(flaky(reset, "26.3.33.24"))));
        assertEquals(Optional.of("ClickHouse 26.1 or newer is required; found 25.8.3.66"),
            coreProtect.refusal(flaky(reset, "25.8.3.66")));
    }

    @Test
    @DisplayName("should take a failure of a check that asks for more than the version for no refusal")
    void moreThanVersion() {
        SQLException refused = new SQLException("Refused by the test");
        AtomicInteger runs = new AtomicInteger();
        ClickHouseServerVersion asksMore = ClickHouseServerVersion.checking(connection -> {
            if (runs.getAndIncrement() > 0) {
                connection.createStatement();
            }
            throw refused;
        });

        assertSame(refused, assertThrows(SQLException.class, () -> asksMore.refusal(answering("26.3.33.24", true))));
        assertEquals(2, runs.get());
        assertInstanceOf(UnsupportedOperationException.class, refused.getSuppressed()[0]);
    }

    /**
     * @param version what the server's {@code version()} returns
     * @param row     whether it returns a row at all
     * @return a connection to a server that answers only {@code SELECT version()}
     */
    private static Connection answering(String version, boolean row) {
        return flaky(null, version, row);
    }

    /**
     * @param first what the first query fails with
     * @return a connection to a server that fails the first query, and then
     *         answers only {@code SELECT version()}
     */
    private static Connection flaky(SQLException first, String version) {
        return flaky(first, version, true);
    }

    private static Connection flaky(SQLException first, String version, boolean row) {
        AtomicBoolean failed = new AtomicBoolean(first == null);
        return stub(Connection.class, (method, args) -> switch (method.getName()) {
            case "prepareStatement" -> {
                assertEquals("SELECT version()", args[0]);
                if (!failed.getAndSet(true)) {
                    throw first;
                }
                yield versionQuery(version, row);
            }
            case "isValid" -> true;
            case "close" -> null;
            default -> throw new UnsupportedOperationException(method.getName());
        });
    }

    private static PreparedStatement versionQuery(String version, boolean row) {
        AtomicBoolean read = new AtomicBoolean();
        ResultSet resultSet = stub(ResultSet.class, (method, args) -> switch (method.getName()) {
            case "next" -> row && !read.getAndSet(true);
            case "getString" -> version;
            case "close" -> null;
            default -> throw new UnsupportedOperationException(method.getName());
        });
        return stub(PreparedStatement.class, (method, args) -> switch (method.getName()) {
            case "executeQuery" -> resultSet;
            case "close" -> null;
            default -> throw new UnsupportedOperationException(method.getName());
        });
    }

    /**
     * @return a connection that is valid, but whose every query fails
     */
    private static Connection failing(SQLException failure) {
        return stub(Connection.class, (method, args) -> switch (method.getName()) {
            case "prepareStatement" -> throw failure;
            case "isValid" -> true;
            case "close" -> null;
            default -> throw new UnsupportedOperationException(method.getName());
        });
    }

    @FunctionalInterface
    private interface Answer {
        Object answer(Method method, Object[] args) throws Throwable;
    }

    private static <T> T stub(Class<T> type, Answer answer) {
        return type.cast(Proxy.newProxyInstance(ClickHouseServerVersionTest.class.getClassLoader(),
            new Class<?>[]{type}, (proxy, method, args) -> switch (method.getName()) {
                case "toString" -> "stub " + type.getSimpleName();
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> answer.answer(method, args);
            }));
    }
}
