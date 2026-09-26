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

package net.deltik.mc.libreprotect.extension.migration.jdbc;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.SQLNonTransientConnectionException;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;

/**
 * Connections of the migration's own, separate from CoreProtect's pool,
 * through the JDBC drivers that the server (SQLite, MySQL) or CoreProtect's
 * plugin libraries (DuckDB) provide.
 */
public final class Connectors {

    private static final long ABORT_POLL_MILLIS = 100;

    private Connectors() {
    }

    /**
     * @param file the database file, which SQLite creates when it's opened
     */
    public static Connector sqlite(File file) {
        return () -> {
            load("org.sqlite.JDBC");
            return DriverManager.getConnection("jdbc:sqlite:" + file.getPath());
        };
    }

    /** How long a MySQL server may take to accept a connection and to greet */
    static final int MYSQL_CONNECT_TIMEOUT_MILLIS = 10_000;
    static final int MYSQL_HANDSHAKE_TIMEOUT_MILLIS = 30_000;
    /**
     * How long one MySQL statement may wait for an answer: long enough to
     * count a table of billions of rows on a busy server. It only ends waits
     * for a server that stopped answering without closing the connection;
     * when the server shuts down, the watchdog aborts the connection at once.
     * A statement that runs out of it isn't repeated.
     */
    static final int MYSQL_STATEMENT_TIMEOUT_MILLIS = 30 * 60_000;

    /**
     * A MySQL connection with CoreProtect's connection settings, plus exact
     * values and bounded waits:
     * <ul>
     *   <li>Server-side prepared statements, as CoreProtect's own pool uses,
     *       return values in MySQL's binary protocol; the text protocol
     *       rounds {@code FLOAT} columns to six digits.</li>
     *   <li>{@code TINYINT(1)} stays a number rather than a boolean.</li>
     *   <li>Connecting and the server's greeting have to be quick, and each
     *       statement's answer comes within half an hour.</li>
     * </ul>
     */
    public static Connector mysql(String host, int port, String database, String username, String password,
                                  boolean tls) {
        return () -> {
            if (!load("com.mysql.cj.jdbc.Driver")) {
                load("com.mysql.jdbc.Driver");
            }
            Properties properties = new Properties();
            properties.setProperty("user", username == null ? "" : username);
            properties.setProperty("password", password == null ? "" : password);
            properties.setProperty("characterEncoding", "UTF-8");
            properties.setProperty("useSSL", Boolean.toString(tls));
            properties.setProperty("allowPublicKeyRetrieval", "true");
            properties.setProperty("useServerPrepStmts", "true");
            properties.setProperty("rewriteBatchedStatements", "true");
            properties.setProperty("tinyInt1isBit", "false");
            properties.setProperty("connectTimeout", Integer.toString(MYSQL_CONNECT_TIMEOUT_MILLIS));
            // The greeting is read under the socket timeout, not the connect timeout
            properties.setProperty("socketTimeout", Integer.toString(MYSQL_HANDSHAKE_TIMEOUT_MILLIS));
            Connection connection = DriverManager.getConnection("jdbc:mysql://" + host + ":" + port + "/" + database,
                properties);
            try {
                connection.setNetworkTimeout(Runnable::run, MYSQL_STATEMENT_TIMEOUT_MILLIS);
            } catch (SQLException e) {
                JdbcRowSource.closeQuietly(connection);
                throw e;
            }
            return connection;
        };
    }

    /**
     * Open a connection. For network engines, connect on a thread of its own
     * and give up waiting once {@code aborted} says so, since connecting to a
     * server that accepts the connection but never greets waits for the
     * whole handshake timeout; a connection that arrives after that is closed.
     */
    static Connection open(Dialect dialect, Connector connector, BooleanSupplier aborted) throws SQLException {
        if (!dialect.abortsConnections()) {
            return connector.open();
        }
        CompletableFuture<Connection> opening = new CompletableFuture<>();
        Thread thread = new Thread(() -> {
            try {
                opening.complete(connector.open());
            } catch (Throwable e) {
                opening.completeExceptionally(e);
            }
        }, "LibreProtect migration connect");
        thread.setDaemon(true);
        thread.start();
        while (true) {
            if (aborted.getAsBoolean()) {
                opening.thenAccept(JdbcRowSource::closeQuietly);
                throw aborted();
            }
            try {
                return opening.get(ABORT_POLL_MILLIS, TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
                // Keep waiting
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                opening.thenAccept(JdbcRowSource::closeQuietly);
                throw new SQLException("Interrupted while connecting", e);
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof SQLException) {
                    throw (SQLException) cause;
                }
                if (cause instanceof RuntimeException) {
                    throw (RuntimeException) cause;
                }
                if (cause instanceof Error) {
                    throw (Error) cause;
                }
                throw new SQLException(cause);
            }
        }
    }

    /**
     * @return the error of a call after the migration aborted its database work
     */
    static SQLException aborted() {
        return new SQLNonTransientConnectionException("The migration stopped its database work");
    }

    /**
     * Abort a connection from another thread, so that a call waiting on it
     * fails at once. The driver closes it on a thread of its own.
     */
    static void abort(Connection connection) {
        if (connection == null) {
            return;
        }
        try {
            connection.abort(command -> {
                Thread thread = new Thread(command, "LibreProtect migration abort");
                thread.setDaemon(true);
                thread.start();
            });
        } catch (SQLException | RuntimeException | AbstractMethodError e) {
            // Nothing more to do; the migration stops at its next check
        }
    }

    /**
     * @param properties the settings CoreProtect opens its DuckDB database
     *                   with, which fix the file's block size when it's created
     */
    public static Connector duckdb(File file, Properties properties) {
        return () -> {
            load("org.duckdb.DuckDBDriver");
            Properties copy = new Properties();
            copy.putAll(properties);
            return DriverManager.getConnection("jdbc:duckdb:" + file.getAbsolutePath(), copy);
        };
    }

    /**
     * @return a connector that fails with a clear message instead of
     *         returning {@code null} when {@code connector} does
     */
    public static Connector nonNull(Connector connector, String what) {
        return () -> {
            Connection connection = connector.open();
            if (connection == null) {
                throw new SQLException("Couldn't open " + what);
            }
            return connection;
        };
    }

    private static boolean load(String driver) {
        try {
            Class.forName(driver);
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }
}
