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

package net.deltik.mc.libreprotect.extension.purge;

import net.coreprotect.config.ConfigHandler;
import net.coreprotect.consumer.Consumer;
import net.coreprotect.hikari.HikariConfig;
import net.coreprotect.hikari.HikariDataSource;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.common.PurgeChunkLock;
import net.deltik.mc.libreprotect.extension.migration.MigrationBridge;
import net.deltik.mc.libreprotect.extension.migration.MigrationException;
import net.deltik.mc.libreprotect.extension.migration.MigrationSession;
import net.deltik.mc.libreprotect.extension.upstream.Capabilities;
import net.deltik.mc.libreprotect.extension.upstream.CoreProtectMigration;
import net.deltik.mc.libreprotect.extension.upstream.CoreProtectPurge;
import net.deltik.mc.libreprotect.testutil.AssumeCapability;
import net.deltik.mc.libreprotect.testutil.CoreProtectFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import javax.sql.DataSource;
import java.io.File;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Auto-purge and {@code /co migrate-db} together with MySQL. On a CoreProtect
 * that coordinates them with its lifecycle flags, as CoreProtect 24 does, an
 * auto-purge chunk holds only a pooled connection and not CoreProtect's
 * {@code Consumer.isPaused} gate, so only the {@code PurgeChunkLock} keeps a
 * migration from reading the source while a chunk deletes from it.
 * CoreProtect's pool is pointed at a SQLite file standing in for MySQL: what
 * matters is which flags and locks each side holds, not the engine's SQL.
 * Only members of CoreProtect's that both generations have are named here;
 * {@link CoreProtectFixture} reaches the rest.
 */
class AutoPurgeDuringMigrationTest {

    private static final long NOW = System.currentTimeMillis() / 1000;
    private static final long CUTOFF = NOW - 1000;

    @TempDir
    Path directory;

    @RegisterExtension
    final CoreProtectFixture coreProtect = new CoreProtectFixture();

    private String url;
    private HikariDataSource pool;

    @BeforeEach
    void setUp() throws Exception {
        Consumer.initialize();
        coreProtect.set("Config.ERROR_REPORTING", false).set("Config.DATABASE_LOCK", true)
            .set("ConfigHandler.path", directory + File.separator).set("ConfigHandler.sqlite", "database.db")
            .set("ConfigHandler.prefix", "co_").set("ConfigHandler.prefixConfig", "co_")
            .set("ConfigHandler.host", "127.0.0.1").set("ConfigHandler.port", 3306)
            .set("ConfigHandler.database", "coreprotect").set("ConfigHandler.username", "root")
            .set("ConfigHandler.password", "")
            .set("ConfigHandler.serverRunning", true).set("ConfigHandler.purgeRunning", false)
            .set("ConfigHandler.migrationRunning", false).set("ConfigHandler.converterRunning", false)
            .set("ConfigHandler.pauseConsumer", false).set("Consumer.isPaused", false)
            .set("ConfigHandler.hikariDataSource", null);
        ConfigHandler.activeRollbacks.clear();
        // config.yml selects MySQL, the database in use, so the pause doesn't rewrite it
        Files.writeString(directory.resolve("config.yml"), "use-mysql: true\ndatabase-type: mysql\n"
            + "database-lock: true\n");

        url = "jdbc:sqlite:" + directory.resolve("mysql-stand-in.db");
        try (Connection connection = DriverManager.getConnection(url); Statement statement = connection.createStatement()) {
            for (String table : List.of("sign", "container", "item", "skull", "session", "chat", "command", "entity",
                "block")) {
                statement.executeUpdate("CREATE TABLE co_" + table + " (time INTEGER)");
            }
            // Three chat messages older than the cutoff, and one newer
            statement.executeUpdate("INSERT INTO co_chat (time) VALUES (100), (200), (300), (" + NOW + ")");
        }
    }

    @AfterEach
    void tearDown() {
        // The fixture puts CoreProtect's fields back after this
        if (pool != null) {
            pool.close();
        }
        Consumer.initialize();
    }

    /**
     * CoreProtect's MySQL pool, whose connections hold up each DELETE for a
     * while after announcing it, like a slow statement on a large table.
     */
    private void slowDeletes(CountDownLatch deleting, long delayMillis) {
        DataSource slow = new DataSource() {
            @Override
            public Connection getConnection() throws SQLException {
                return StatementHooks.wrap(DriverManager.getConnection(url), (sql, parameters) -> {
                    if (sql.startsWith("DELETE")) {
                        deleting.countDown();
                        try {
                            Thread.sleep(delayMillis);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }
                });
            }

            @Override
            public Connection getConnection(String username, String password) throws SQLException {
                return getConnection();
            }

            @Override
            public PrintWriter getLogWriter() {
                return null;
            }

            @Override
            public void setLogWriter(PrintWriter out) {
            }

            @Override
            public void setLoginTimeout(int seconds) {
            }

            @Override
            public int getLoginTimeout() {
                return 0;
            }

            @Override
            public Logger getParentLogger() {
                return Logger.getGlobal();
            }

            @Override
            public <T> T unwrap(Class<T> type) throws SQLException {
                throw new SQLException("Not a wrapper");
            }

            @Override
            public boolean isWrapperFor(Class<?> type) {
                return false;
            }
        };
        HikariConfig config = new HikariConfig();
        config.setDataSource(slow);
        config.setMaximumPoolSize(2);
        pool = new HikariDataSource(config);
        coreProtect.set("ConfigHandler.hikariDataSource", pool).useEngine(Engine.MYSQL);
    }

    private long chatRows() throws SQLException {
        try (Connection connection = DriverManager.getConnection(url); Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("SELECT COUNT(*) FROM co_chat")) {
            result.next();
            return result.getLong(1);
        }
    }

    /**
     * The migrations of this CoreProtect, running their tasks for the
     * server's thread on the calling thread. That constructor is
     * package-private in the upstream package, and this test needs the purge
     * package's.
     */
    private static MigrationBridge migrationBridge() throws Exception {
        Constructor<CoreProtectMigration> constructor = CoreProtectMigration.class.getDeclaredConstructor(
            Capabilities.class, Executor.class);
        constructor.setAccessible(true);
        return constructor.newInstance(Capabilities.current(), (Executor) Runnable::run);
    }

    @Test
    @DisplayName("should make a migration's pause wait for an auto-purge chunk that is deleting from the MySQL source")
    void pauseWaitsForChunkOnMySQL() throws Exception {
        // CoreProtect 25's claims keep the reload out while a chunk runs; see ReloadLifecyclePauseTest
        AssumeCapability.strategy("migrate-db.protocol", "flag-protocol");
        AssumeCapability.strategy("auto-purge.coordination", "cooperative-flags");
        CountDownLatch deleting = new CountDownLatch(1);
        slowDeletes(deleting, 2_000);
        PurgeContext context = new PurgeContext();
        AtomicReference<PurgeResult> purged = new AtomicReference<>();
        Thread autoPurge = new Thread(() -> purged.set(new ChunkedPurge(CoreProtectPurge.create(), context,
            new RecordingLog(), () -> null, CUTOFF, NOW).timing(0, 1, 60_000).run(false)), "LibreProtect auto-purge");
        context.bind(autoPurge);
        autoPurge.start();
        assertTrue(deleting.await(10, TimeUnit.SECONDS), "auto-purge didn't start deleting");

        // /co migrate-db sqlite, while the chunk's DELETE is under way
        MigrationSession session = migrationBridge().claim(Engine.SQLITE);
        long rowsAtPause;
        boolean chunkRunningAtPause;
        try {
            session.pause();
            // What the migration reads first once paused: each table's statistics, which validation compares at the end
            rowsAtPause = chatRows();
            chunkRunningAtPause = autoPurge.isAlive();
            autoPurge.join(10_000);
        } finally {
            session.close();
        }
        long rowsAfterChunk = chatRows();

        assertEquals(StopReason.MIGRATION, purged.get().stopReason());
        assertEquals(rowsAtPause, rowsAfterChunk, "auto-purge removed " + purged.get().removed() + " rows from the"
            + " source after the migration paused (chunk still running then: " + chunkRunningAtPause + "), so"
            + " validation would find the source changed after the whole copy");
    }

    @Test
    @DisplayName("should let a migration that waits for an auto-purge chunk stop when the server does")
    void pauseStopsWhileWaiting() throws Exception {
        coreProtect.useEngine(Engine.SQLITE);
        CountDownLatch holding = new CountDownLatch(1);
        CountDownLatch finish = new CountDownLatch(1);
        // A chunk that doesn't end, such as one waiting on an unresponsive database
        Thread chunk = new Thread(() -> {
            try {
                assertTrue(PurgeChunkLock.tryHold(1000));
                holding.countDown();
                finish.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                if (PurgeChunkLock.isHeldByCurrentThread()) {
                    PurgeChunkLock.release();
                }
            }
        });
        chunk.start();
        assertTrue(holding.await(5, TimeUnit.SECONDS));
        MigrationSession session = migrationBridge().claim(Engine.MYSQL);
        try {
            Thread stopper = new Thread(() -> {
                try {
                    Thread.sleep(300);
                } catch (InterruptedException e) {
                    return;
                }
                coreProtect.set("ConfigHandler.serverRunning", false);
            });
            stopper.start();
            long started = System.nanoTime();

            MigrationException thrown = assertThrows(MigrationException.class, session::pause);

            assertTrue(thrown.getMessage().contains("the server is stopping"), thrown.getMessage());
            assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(3));
            stopper.join(5000);
        } finally {
            session.close();
            finish.countDown();
            chunk.join(5000);
        }
    }
}
