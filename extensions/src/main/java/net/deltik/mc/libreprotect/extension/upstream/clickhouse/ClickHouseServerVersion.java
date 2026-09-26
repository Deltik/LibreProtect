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
import net.deltik.mc.libreprotect.extension.upstream.Designs;
import net.deltik.mc.libreprotect.extension.upstream.MigrationProtocol;
import net.deltik.mc.libreprotect.extension.upstream.Names;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Whether CoreProtect's ClickHouse writer takes a ClickHouse server, which a
 * migration to ClickHouse asks before anything else, since it writes through
 * that writer.
 *
 * <p>CoreProtect checks the server's version itself when it opens a
 * ClickHouse database, which a migration does only once it has paused
 * CoreProtect and read the source. So the migration runs that check first,
 * over its own connection, and takes exactly the servers that CoreProtect
 * takes. LibreProtect has no minimum of its own, which could refuse a server
 * that CoreProtect takes: on a CoreProtect whose check it can't find, it asks
 * nothing first, and CoreProtect's check still refuses the server when the
 * migration opens the target, before anything is copied. (Some CoreProtect
 * 25 development builds check for 25.6 only, though their writer needs 26.1;
 * a migration from one of them to an older server passes their check, and
 * fails at its first write.)
 *
 * <p>Nothing else of LibreProtect's needs the check: a migration from
 * ClickHouse only reads it, which needs none of the settings that the writer
 * sends, and automatic purging on ClickHouse runs CoreProtect's own purge on
 * the database that CoreProtect opened, and checked, itself. So LibreProtect
 * asks the server for its version only when a migration to it starts.
 */
public final class ClickHouseServerVersion {

    public static final Capability<ClickHouseServerVersion> CAPABILITY = Capability.of(
        "migrate-db.clickhouse-version",
        Choice.way("coreprotect-check", "CoreProtect's own check of the server's version, before the migration"
            + " starts", ClickHouseServerVersion::coreProtectCheck),
        Choice.fallback("when-opened", "CoreProtect's own check of the server's version, only once the migration"
            + " opens the target, since LibreProtect can't run it before", ClickHouseServerVersion::whenOpened));

    /** The query of the server's version, the only one that the check makes */
    private static final String QUERY = "SELECT version()";

    /**
     * Checks the server behind a connection, throwing an SQLException that
     * says why if it refuses it, by what {@code SELECT version()} returns alone
     */
    @FunctionalInterface
    interface Check {
        void run(Connection connection) throws SQLException;
    }

    /** What checks the server before the migration starts, or {@code null} for nothing */
    private final Check check;
    private final boolean coreProtectCheck;

    private ClickHouseServerVersion(Check check, boolean coreProtectCheck) {
        this.check = check;
        this.coreProtectCheck = coreProtectCheck;
    }

    private static ClickHouseServerVersion coreProtectCheck(Upstream upstream) throws Missing {
        requireMigrations(upstream);
        StaticMethod<Void, SQLException> check = upstream.type(Names.CLICKHOUSE_DATABASE)
            .staticMethod("requireServerVersion", void.class, Connection.class).throwing(SQLException.class);
        upstream.relyOn("refuses a ClickHouse server that CoreProtect's writer doesn't support by throwing an"
            + " SQLException that says why, deciding by what SELECT version() returns alone, the only thing it reads,"
            + " so that it decides the same again on a connection that answers only that", check);
        return new ClickHouseServerVersion(check::call, true);
    }

    /**
     * Nothing to check before the migration starts: CoreProtect checks the
     * server when the sink opens the target (see
     * {@link ClickHouseRowSink#prepare}), which is always safe, only later.
     */
    private static ClickHouseServerVersion whenOpened(Upstream upstream) throws Missing {
        requireMigrations(upstream);
        return new ClickHouseServerVersion(null, false);
    }

    /**
     * Only a CoreProtect with the multi-engine design has ClickHouse, and
     * only migrations check its version, which all need the protocol, so the
     * capability report says that the check doesn't work whenever migrations
     * don't.
     */
    private static void requireMigrations(Upstream upstream) throws Missing {
        Designs.MULTI_ENGINE.requireIn(upstream);
        MigrationProtocol.CAPABILITY.probe(upstream).require();
    }

    /**
     * For tests: another check of the server, such as one that refuses it.
     */
    static ClickHouseServerVersion checking(Check check) {
        return new ClickHouseServerVersion(Objects.requireNonNull(check, "check"), false);
    }

    /**
     * @return whether this is CoreProtect's own check before the migration
     *         starts, rather than none until the target opens
     */
    boolean isCoreProtectCheck() {
        return coreProtectCheck;
    }

    /**
     * Ask the server behind a connection whether CoreProtect's writer takes
     * it, if CoreProtect's check can run before the migration starts.
     *
     * @return why CoreProtect's writer doesn't take the server, in
     *         CoreProtect's words, such as {@code ClickHouse 26.1 or newer is
     *         required; found 25.8.3.66}, or empty if it does, or if the
     *         check only runs once the migration opens the target
     * @throws SQLException what the check threw if the server couldn't be
     *                      asked, which says nothing about it, or if the
     *                      check takes the version that the server tells
     *                      when asked again, as after a transient failure
     */
    public Optional<String> refusal(Connection connection) throws SQLException {
        if (check == null) {
            return Optional.empty();
        }
        try {
            check.run(connection);
            return Optional.empty();
        } catch (SQLException e) {
            // Refused, or the query failed, such as because the migration stopped or the server was busy. The
            // check decides by the server's version alone, so run it again on the version the server tells now,
            // which fails only if it refuses the server.
            Answer answer = ask(connection, e);
            try {
                check.run(answer.connection());
            } catch (SQLException refused) {
                return Optional.of(String.valueOf(refused.getMessage()));
            } catch (RuntimeException changed) {
                // It asked for more than the version, which says nothing about the server
                e.addSuppressed(changed);
            }
            throw e;
        }
    }

    /**
     * Ask the server for its version, as the check does.
     *
     * @param failure what the check threw, which is thrown if the server
     *                doesn't answer, with why it didn't
     */
    private static Answer ask(Connection connection, SQLException failure) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(QUERY);
             ResultSet resultSet = statement.executeQuery()) {
            return resultSet.next() ? new Answer(true, resultSet.getString(1)) : new Answer(false, null);
        } catch (SQLException | RuntimeException e) {
            if (e != failure) {
                failure.addSuppressed(e);
            }
            throw failure;
        }
    }

    /**
     * What a server answered to {@code SELECT version()}, to run the check
     * again on, with the same outcome every time.
     */
    private static final class Answer {
        private final boolean row;
        private final String version;

        Answer(boolean row, String version) {
            this.row = row;
            this.version = version;
        }

        /**
         * @return a connection that answers {@code SELECT version()} as the
         *         server did, and fails anything else with an unchecked
         *         exception, which says nothing about the server
         */
        Connection connection() {
            AtomicBoolean read = new AtomicBoolean();
            ResultSet resultSet = replay(ResultSet.class, (method, args) -> {
                switch (method) {
                    case "next":
                        return row && !read.getAndSet(true);
                    case "getString":
                        return version;
                    case "wasNull":
                        return version == null;
                    default:
                        throw unexpected(ResultSet.class, method);
                }
            });
            PreparedStatement statement = replay(PreparedStatement.class, (method, args) -> {
                if (method.equals("executeQuery") && args == null) {
                    return resultSet;
                }
                throw unexpected(PreparedStatement.class, method);
            });
            return replay(Connection.class, (method, args) -> {
                if (method.equals("prepareStatement") && args.length == 1 && QUERY.equals(args[0])) {
                    return statement;
                }
                throw unexpected(Connection.class, method);
            });
        }

        private static UnsupportedOperationException unexpected(Class<?> type, String method) {
            return new UnsupportedOperationException("CoreProtect's check of the server's version called "
                + type.getSimpleName() + "." + method + ", not only " + QUERY);
        }

        /**
         * @param reply what each method returns, by name, but for those of
         *              {@code Object} and {@code close}
         */
        private static <T> T replay(Class<T> type, Reply reply) {
            return type.cast(Proxy.newProxyInstance(ClickHouseServerVersion.class.getClassLoader(),
                new Class<?>[]{type}, (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "toString":
                            return "the server's answer to " + QUERY;
                        case "hashCode":
                            return System.identityHashCode(proxy);
                        case "equals":
                            return proxy == args[0];
                        case "close":
                            return null;
                        default:
                            return reply.reply(method.getName(), args);
                    }
                }));
        }
    }

    @FunctionalInterface
    private interface Reply {
        Object reply(String method, Object[] args);
    }
}
