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
import net.coreprotect.database.Database;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.upstream.Capabilities;
import net.deltik.mc.libreprotect.extension.upstream.CoreProtectPurge;
import net.deltik.mc.libreprotect.extension.upstream.StartResult;
import net.deltik.mc.libreprotect.testutil.AssumeCapability;
import net.deltik.mc.libreprotect.testutil.CoreProtectFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link CoreProtectPurge} against CoreProtect's real classes, set up as a
 * server would have them, on SQLite unless a test says otherwise. What it
 * does on every CoreProtect comes first; what it does with each way of
 * taking turns with CoreProtect's database work, which the CoreProtect
 * being built decides, is in {@link WithCooperativeFlags} and
 * {@link WithBackgroundClaims}. Only members of CoreProtect's that both
 * generations have are named here; {@link CoreProtectFixture} reaches the
 * rest.
 */
class CoreProtectPurgeTest {

    static final long CUTOFF = 1_700_000_000L;
    static final long DAY = 86400;

    @TempDir
    Path directory;

    @RegisterExtension
    final CoreProtectFixture coreProtect = new CoreProtectFixture();

    final CoreProtectPurge bridge = CoreProtectPurge.create();
    final PurgeContext context = new PurgeContext();

    @BeforeEach
    void setUpCoreProtect() throws Exception {
        Consumer.initialize();
        coreProtect.set("ConfigHandler.path", directory + File.separator).set("ConfigHandler.sqlite", "database.db")
            .set("ConfigHandler.prefix", "co_").set("ConfigHandler.serverRunning", true)
            .set("Config.AUTO_PURGE", null).set("Config.AUTO_PURGE_TIME", null);
        resetFlags();
        coreProtect.useEngine(Engine.SQLITE);
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + directory.resolve("database.db"));
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE TABLE co_block (time INTEGER)");
            statement.executeUpdate("INSERT INTO co_block VALUES (1), (2)");
        }
        context.bind(Thread.currentThread());
    }

    @AfterEach
    void tearDownCoreProtect() {
        resetFlags();
        Consumer.initialize();
        Database.closeConnection();
    }

    void resetFlags() {
        coreProtect.set("ConfigHandler.purgeRunning", false).set("ConfigHandler.migrationRunning", false)
            .set("ConfigHandler.converterRunning", false).set("ConfigHandler.pauseConsumer", false)
            .set("Consumer.isPaused", false);
        ConfigHandler.activeRollbacks.clear();
    }

    /**
     * Use a fresh folder, whose database CoreProtect creates with its own schema.
     */
    void useFreshDatabase() throws Exception {
        Path folder = Files.createDirectories(directory.resolve("fresh"));
        coreProtect.set("ConfigHandler.path", folder + File.separator);
        coreProtect.createTables("co_");
    }

    void execute(String... sql) throws Exception {
        try (Connection connection = Database.getConnection(true, 0); Statement statement = connection.createStatement()) {
            for (String each : sql) {
                statement.executeUpdate(each);
            }
        }
    }

    List<Long> longs(String sql) throws Exception {
        List<Long> values = new ArrayList<>();
        try (Connection connection = Database.getConnection(true, 0); Statement statement = connection.createStatement();
             ResultSet results = statement.executeQuery(sql)) {
            while (results.next()) {
                values.add(results.getLong(1));
            }
        }
        return values;
    }

    /**
     * Block rows older than the cutoff, then one newer.
     */
    void seed(int rows) throws Exception {
        execute("WITH RECURSIVE r(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM r WHERE x < " + rows + ")"
                + " INSERT INTO co_block (rowid, time, user, wid, x, y, z, type, data, action, rolled_back)"
                + " SELECT x, " + (CUTOFF - 10 * DAY) + ", 1, 1, x % 100, 64, x / 100, 1, 0, 0, 0 FROM r",
            "INSERT INTO co_block (time) VALUES (" + (CUTOFF + DAY) + ")");
    }

    /**
     * A purge with a 30-day retention, run by the given context's thread.
     */
    ChunkedPurge purger(PurgeContext purgeContext) {
        return new ChunkedPurge(bridge, purgeContext, new RecordingLog(), () -> null, CUTOFF, CUTOFF + 30 * DAY);
    }

    /**
     * Run a purge on its own thread, as the auto-purge thread would.
     */
    static Thread start(PurgeContext purgeContext, AtomicReference<PurgeResult> result, ChunkedPurge purge) {
        Thread worker = new Thread(() -> result.set(purge.run(false)));
        purgeContext.bind(worker);
        worker.start();
        return worker;
    }

    private static long rows(Connection connection) throws Exception {
        try (Statement statement = connection.createStatement();
             ResultSet results = statement.executeQuery("SELECT COUNT(*) FROM co_block")) {
            results.next();
            return results.getLong(1);
        }
    }

    /**
     * @return CoreProtect's answer to starting maintenance, by name
     */
    private static StartResult.Kind kind(Object result) {
        return StartResult.of(result).kind();
    }

    private static String strategy(String capability) {
        return Capabilities.current().get(capability).strategy();
    }

    @Test
    @DisplayName("should read the settings as CoreProtect read them from config.yml")
    void settings() {
        coreProtect.set("Config.AUTO_PURGE", "6mo").set("Config.AUTO_PURGE_TIME", "03:30");
        assertEquals("6mo", bridge.retentionSetting());
        assertEquals("03:30", bridge.timeSetting());
        assertEquals("co_", bridge.tablePrefix());
        assertEquals(Engine.SQLITE, bridge.activeEngine());
        assertTrue(bridge.purgeableTables().containsAll(List.of("block", "chat", "command", "session", "sign",
            "container", "item", "skull", "entity")));
        assertFalse(bridge.purgeableTables().contains("user"));
        assertFalse(bridge.purgeableTables().contains("entity_spawn"));
    }

    @Test
    @DisplayName("should count removed rows toward /co status")
    void counts() {
        long before = ConfigHandler.autoPurgeRowsPurged.get();
        bridge.rowsPurged(12_345);
        assertEquals(before + 12_345, ConfigHandler.autoPurgeRowsPurged.get());
    }

    @Nested
    @DisplayName("stopReason")
    class Stops {

        @Test
        @DisplayName("should have none on a running server")
        void none() {
            assertNull(bridge.stopReason());
            assertNull(bridge.unavailableReason());
        }

        @Test
        @DisplayName("should stop for shutdown, a manual purge, a migration, a conversion and a paused consumer")
        void signals() {
            ConfigHandler.serverRunning = false;
            assertEquals(StopReason.SHUTDOWN, bridge.stopReason());
            ConfigHandler.serverRunning = true;

            ConfigHandler.purgeRunning = true;
            assertEquals(StopReason.MANUAL_PURGE, bridge.stopReason());
            // A migration on CoreProtect 24 sets purgeRunning too
            ConfigHandler.migrationRunning = true;
            assertEquals(StopReason.MIGRATION, bridge.stopReason());
            resetFlags();

            ConfigHandler.converterRunning = true;
            assertEquals(StopReason.CONVERSION, bridge.stopReason());
            resetFlags();

            ConfigHandler.pauseConsumer = true;
            assertEquals(StopReason.CONSUMER_PAUSED, bridge.stopReason());
        }

        @Test
        @DisplayName("should refuse a lease for a reason to stop, holding nothing")
        void refusesLease() throws Exception {
            ConfigHandler.pauseConsumer = true;
            Lease lease = bridge.lease(context, false);
            assertFalse(lease.isGranted());
            assertEquals(StopReason.CONSUMER_PAUSED, lease.stopReason());
            assertFalse(Consumer.isPaused);
            assertFalse(coreProtect.backgroundPurgeClaimed());
        }
    }

    @Nested
    @DisplayName("lease on SQLite")
    class SQLiteLease {

        @Test
        @DisplayName("should hold the consumer's gate and a working connection, and give both back")
        void holdsGate() throws Exception {
            Connection connection;
            try (Lease lease = bridge.lease(context, false)) {
                assertTrue(lease.isGranted());
                assertTrue(Consumer.isPaused, "the gate is held");
                connection = lease.connection();
                assertEquals(2, rows(connection));
            }
            assertFalse(Consumer.isPaused, "the gate is free");
            assertTrue(connection.isClosed());
            assertFalse(coreProtect.backgroundPurgeClaimed());
        }

        @Test
        @DisplayName("should wait for a lookup or consumer batch to let go of the gate")
        void waitsForGate() throws Exception {
            Consumer.isPaused = true;
            Thread lookup = new Thread(() -> {
                try {
                    Thread.sleep(200);
                } catch (InterruptedException ignored) {
                }
                Consumer.isPaused = false;
            });
            lookup.start();
            long started = System.nanoTime();
            try (Lease lease = bridge.lease(context, false)) {
                assertTrue(lease.isGranted());
                assertTrue(System.nanoTime() - started >= TimeUnit.MILLISECONDS.toNanos(150));
            }
            assertFalse(Consumer.isPaused);
        }

        @Test
        @DisplayName("should stop instead of taking the gate when told to stop while waiting")
        void stopsWhileWaiting() throws Exception {
            Consumer.isPaused = true;
            new Thread(() -> {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ignored) {
                }
                context.requestStop();
            }).start();
            long started = System.nanoTime();
            Lease lease = bridge.lease(context, false);
            assertFalse(lease.isGranted());
            assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(5));
            assertTrue(Consumer.isPaused, "someone else's gate stays held");
            assertFalse(coreProtect.backgroundPurgeClaimed());
        }

        @Test
        @DisplayName("should wait while a rollback marks the rows it undid")
        void rollback() throws Exception {
            ConfigHandler.activeRollbacks.put("lpit", true);
            try {
                Lease lease = bridge.lease(context, false);
                assertFalse(lease.isGranted());
                assertEquals("a rollback is running", lease.busyReason());
                assertFalse(Consumer.isPaused);
                assertFalse(coreProtect.backgroundPurgeClaimed());
            } finally {
                ConfigHandler.activeRollbacks.remove("lpit");
            }
            try (Lease lease = bridge.lease(context, false)) {
                assertTrue(lease.isGranted());
            }
        }

        @Test
        @DisplayName("abandon should give back a gate that a stuck purge holds")
        void abandon() throws Exception {
            Lease lease = bridge.lease(context, false);
            assertTrue(Consumer.isPaused);
            bridge.abandon();
            assertFalse(Consumer.isPaused);
            Consumer.isPaused = true;
            lease.close();
            assertTrue(Consumer.isPaused, "closing later doesn't clear someone else's gate");
        }

        @Test
        @DisplayName("databaseIdentity should change when the file is replaced, as a manual purge does")
        void identity() throws Exception {
            Object before = bridge.databaseIdentity();
            assertNotNull(before);
            assertEquals(before, bridge.databaseIdentity());
            Path rebuilt = directory.resolve("database.db.tmp");
            Files.copy(directory.resolve("database.db"), rebuilt);
            Files.move(rebuilt, directory.resolve("database.db"), StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE);
            assertNotEquals(before, bridge.databaseIdentity());
        }
    }

    @Nested
    @DisplayName("purging CoreProtect's own schema")
    class OwnSchema {

        @Test
        @DisplayName("should purge SQLite, and count what it removed")
        void sqlite() throws Exception {
            useFreshDatabase();
            execute("INSERT INTO co_block (time) VALUES (" + (CUTOFF - DAY) + ")",
                "INSERT INTO co_block (time) VALUES (" + (CUTOFF - 1) + ")",
                "INSERT INTO co_block (time) VALUES (" + CUTOFF + ")",
                "INSERT INTO co_chat (time) VALUES (" + (CUTOFF - DAY) + ")",
                "INSERT INTO co_chat (time) VALUES (" + (CUTOFF + DAY) + ")");
            long counted = ConfigHandler.autoPurgeRowsPurged.get();

            PurgeResult result = purger(context).timing(0, 1, 60_000).run(false);

            assertTrue(result.completed(), () -> result.stopReason() + ": " + result.detail());
            assertEquals(List.of(3L), longs("SELECT rowid FROM co_block ORDER BY rowid"));
            assertEquals(List.of(CUTOFF + DAY), longs("SELECT time FROM co_chat"));
            assertEquals(3, result.removed());
            assertEquals(counted + 3, ConfigHandler.autoPurgeRowsPurged.get());
            assertFalse(Consumer.isPaused);
            assertFalse(coreProtect.backgroundPurgeClaimed());
        }

        @Test
        @DisplayName("should give back every claim and the gate when statements keep failing")
        void failuresReleaseEverything() throws Exception {
            useFreshDatabase();
            seed(1000);
            execute("DROP TABLE co_sign");
            PurgeContext purgeContext = new PurgeContext();
            AtomicReference<PurgeResult> result = new AtomicReference<>();

            Thread worker = start(purgeContext, result, purger(purgeContext).timing(0, 1, 60_000));
            worker.join(30_000);

            assertFalse(worker.isAlive());
            assertEquals(StopReason.ERROR, result.get().stopReason(), () -> String.valueOf(result.get().detail()));
            assertFalse(Consumer.isPaused);
            assertFalse(coreProtect.backgroundPurgeClaimed());
        }
    }

    /**
     * CoreProtect 24's way: its lifecycle flags, and the consumer's pause
     * gate on SQLite.
     */
    @Nested
    @DisplayName("with cooperative flags")
    class WithCooperativeFlags {

        @BeforeEach
        void assumeCooperativeFlags() {
            AssumeCapability.strategy("auto-purge.coordination", "cooperative-flags");
        }

        @Test
        @DisplayName("should be for CoreProtect 24, without entity tracking, and have shutdown wait up to 10 seconds")
        void generation() throws Exception {
            useFreshDatabase();
            assertEquals("purge-command-list", strategy("auto-purge.tables"));
            assertEquals("absent", strategy("auto-purge.engine.duckdb"));
            assertEquals("absent", strategy("auto-purge.engine.clickhouse"));
            assertFalse(bridge.tracksEntitySpawns());
            assertEquals(10_000, bridge.stopTimeoutMillis());
        }

        @Test
        @DisplayName("should know there are no entity spawns to clean up, whatever the list of tables says")
        void noEntityTracking() throws Exception {
            useFreshDatabase();
            @SuppressWarnings("unchecked")
            List<String> tables = (List<String>) coreProtect.get("ConfigHandler.databaseTables");
            List<String> created = new ArrayList<>(tables);
            try {
                assertEquals(Boolean.FALSE, bridge.entitySpawnTracking());
                tables.clear();
                assertEquals(Boolean.FALSE, bridge.entitySpawnTracking(), "no orphans stay due on CoreProtect 24");
            } finally {
                tables.clear();
                tables.addAll(created);
            }
        }

        @Test
        @DisplayName("should refuse an exclusive lease, which CoreProtect 24 has nothing to make, holding nothing")
        void noExclusiveLease() throws Exception {
            Lease lease = bridge.lease(context, true);

            assertFalse(lease.isGranted());
            assertEquals(StopReason.UNSUPPORTED_DATABASE, lease.stopReason());
            assertEquals("CoreProtect has no claims that keep every other database user waiting", lease.stopDetail());
            assertFalse(Consumer.isPaused);
        }
    }

    /**
     * CoreProtect 25's way: its background purge claims, which its
     * maintenance and shutdown wait for.
     */
    @Nested
    @DisplayName("with background claims")
    class WithBackgroundClaims {

        @BeforeEach
        void assumeBackgroundClaims() {
            AssumeCapability.strategy("auto-purge.coordination", "background-claims");
        }

        private void useClickHouse() {
            coreProtect.useEngine(Engine.CLICKHOUSE);
            assertEquals(Engine.CLICKHOUSE, bridge.activeEngine());
        }

        @Test
        @DisplayName("should be for CoreProtect 25, with entity tracking, and leave waiting for its claims to shutdown")
        void generation() throws Exception {
            useFreshDatabase();
            assertEquals("purge-policy", strategy("auto-purge.tables"));
            assertTrue(bridge.tracksEntitySpawns());
            assertEquals(0, bridge.stopTimeoutMillis());
        }

        @Test
        @DisplayName("should stop once CoreProtect 25's shutdown begins, before serverRunning clears")
        void shutdownSignals() {
            coreProtect.set("ConfigHandler.shutdownDrainRunning", true);
            assertEquals(StopReason.SHUTDOWN, bridge.stopReason());
            coreProtect.set("ConfigHandler.shutdownDrainRunning", false);

            coreProtect.call("Consumer.blockDatabaseReloadForShutdown");
            assertEquals(StopReason.SHUTDOWN, bridge.stopReason());
        }

        @Nested
        @DisplayName("claims")
        class Claims {

            @Test
            @DisplayName("should hold a background purge claim with each lease, and release it on closing")
            void claim() throws Exception {
                try (Lease lease = bridge.lease(context, false)) {
                    assertTrue(lease.isGranted());
                    assertTrue(coreProtect.backgroundPurgeClaimed());
                }
                assertFalse(coreProtect.backgroundPurgeClaimed());
            }

            @Test
            @DisplayName("should wait while a rollback runs")
            void rollback() throws Exception {
                assertEquals(StartResult.Kind.STARTED, kind(coreProtect.call("Consumer.claimRollback", "lpit")));
                try {
                    Lease lease = bridge.lease(context, false);
                    assertFalse(lease.isGranted());
                    assertEquals("a rollback is running", lease.busyReason());
                    assertFalse(coreProtect.backgroundPurgeClaimed());
                    assertFalse(Consumer.isPaused);
                } finally {
                    coreProtect.call("Consumer.releaseRollback", "lpit");
                }
                try (Lease lease = bridge.lease(context, false)) {
                    assertTrue(lease.isGranted());
                }
            }

            @Test
            @DisplayName("should wait while a database reload is pending")
            void reload() throws Exception {
                coreProtect.call("Consumer.requireDatabaseReload");
                Lease lease = bridge.lease(context, false);
                assertFalse(lease.isGranted());
                assertEquals("CoreProtect is reloading the database", lease.busyReason());
                assertFalse(coreProtect.backgroundPurgeClaimed());
            }

            @Test
            @DisplayName("should stop when another purge holds the claim")
            void otherPurge() throws Exception {
                AtomicReference<Object> claimed = new AtomicReference<>();
                Thread other = new Thread(() -> claimed.set(coreProtect.call("Consumer.claimBackgroundPurge", false)));
                other.start();
                other.join();
                assertEquals(StartResult.Kind.STARTED, kind(claimed.get()));
                try {
                    Lease lease = bridge.lease(context, false);
                    assertFalse(lease.isGranted());
                    assertEquals(StopReason.MANUAL_PURGE, lease.stopReason());
                    assertFalse(Consumer.isPaused);
                } finally {
                    coreProtect.call("Consumer.releaseBackgroundPurge");
                }
            }

            @Test
            @DisplayName("an exclusive lease should keep new connections waiting until it is closed")
            void exclusive() throws Exception {
                Lease lease = bridge.lease(context, true);
                assertTrue(lease.isGranted());
                AtomicReference<Connection> other = new AtomicReference<>();
                CountDownLatch connected = new CountDownLatch(1);
                Thread lookup = new Thread(() -> {
                    other.set(Database.getConnection(true, 0));
                    connected.countDown();
                });
                lookup.start();
                try {
                    try {
                        assertFalse(connected.await(300, TimeUnit.MILLISECONDS), "other connections wait for the lease");
                    } finally {
                        lease.close();
                    }
                    assertTrue(connected.await(5, TimeUnit.SECONDS));
                    assertNotNull(other.get());
                } finally {
                    lookup.join(5000);
                    if (other.get() != null) {
                        other.get().close();
                    }
                }
                assertFalse(coreProtect.backgroundPurgeClaimed());
            }

            @Test
            @DisplayName("an exclusive lease should wait for open connections to close")
            void drains() throws Exception {
                Connection open = Database.getConnection(true, 0);
                try {
                    Lease lease = bridge.lease(context, true);
                    assertFalse(lease.isGranted());
                    assertEquals("other database connections are open", lease.busyReason());
                    assertFalse(coreProtect.backgroundPurgeClaimed(), "the claim is released on the same thread");
                } finally {
                    open.close();
                }
                try (Lease lease = bridge.lease(context, true)) {
                    assertTrue(lease.isGranted());
                }
            }

            @Test
            @DisplayName("a stop should interrupt waiting for an exclusive claim, which is then released")
            void interruptsClaim() throws Exception {
                CountDownLatch locked = new CountDownLatch(1);
                CountDownLatch unlock = new CountDownLatch(1);
                Thread holder = new Thread(() -> {
                    coreProtect.call("Consumer.lockDatabaseMaintenance");
                    locked.countDown();
                    try {
                        unlock.await();
                    } catch (InterruptedException ignored) {
                    } finally {
                        coreProtect.call("Consumer.unlockDatabaseMaintenance");
                    }
                });
                holder.start();
                assertTrue(locked.await(5, TimeUnit.SECONDS));
                PurgeContext stopping = new PurgeContext();
                AtomicReference<Lease> result = new AtomicReference<>();
                Thread worker = new Thread(() -> {
                    try {
                        result.set(bridge.lease(stopping, true));
                    } catch (InterruptedException e) {
                        result.set(Lease.stop(StopReason.SHUTDOWN));
                    }
                });
                stopping.bind(worker);
                worker.start();
                Thread.sleep(200);
                assertTrue(worker.isAlive(), "waiting for the lock");

                stopping.requestStop();
                worker.join(5000);

                assertFalse(worker.isAlive());
                assertEquals(StopReason.SHUTDOWN, result.get().stopReason());
                assertFalse(coreProtect.backgroundPurgeClaimed());
                unlock.countDown();
                holder.join(5000);
            }
        }

        @Nested
        @DisplayName("ClickHouse")
        class ClickHouse {

            @Test
            @DisplayName("should take a manual purge's claim, which turns lookups away at once rather than making them"
                + " wait")
            void manualPurgeClaim() throws Exception {
                useClickHouse();
                Lease lease = bridge.lease(context, true);
                try {
                    assertTrue(lease.isGranted());
                    assertTrue(ConfigHandler.purgeRunning, "the consumer parks for purgeRunning");
                    assertFalse(coreProtect.backgroundPurgeClaimed());
                    assertEquals(StartResult.Kind.PURGE_RUNNING, kind(coreProtect.call("Consumer.claimRollback", "lpit")));
                    assertEquals(StartResult.Kind.PURGE_RUNNING, kind(coreProtect.call("Consumer.beginDatabaseReload")));
                    // No write lock: a lookup's connection request returns at once, empty-handed
                    AtomicReference<Object> lookup = new AtomicReference<>("not asked yet");
                    Thread thread = new Thread(() -> lookup.set(Database.getConnection(false, 0)));
                    long started = System.nanoTime();
                    thread.start();
                    thread.join(5000);
                    assertFalse(thread.isAlive());
                    assertNull(lookup.get());
                    assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(1));
                } finally {
                    lease.close();
                }
                assertFalse(ConfigHandler.purgeRunning);
                assertFalse(coreProtect.backgroundPurgeClaimed());
            }

            /**
             * A manual ClickHouse purge invalidates entity verification right
             * after purging, while its claim still keeps the consumer parked,
             * and releases the claim after.
             */
            @Test
            @DisplayName("should have tracked entities rechecked before the consumer resumes, as /co purge does")
            void rechecksUnderClaim() {
                useClickHouse();
                coreProtect.set("Config.DATABASE_LOCK", true);
                List<Boolean> claimedAtPurge = new CopyOnWriteArrayList<>();
                List<Boolean> claimedAtRecheck = new CopyOnWriteArrayList<>();
                PurgeBridge watched = (PurgeBridge) Proxy.newProxyInstance(PurgeBridge.class.getClassLoader(),
                    new Class<?>[]{PurgeBridge.class}, (proxy, method, arguments) -> {
                        if (method.getName().equals("purgeClickHouse")) {
                            claimedAtPurge.add(ConfigHandler.purgeRunning);
                            return 42L;
                        }
                        if (method.getName().equals("purged")) {
                            claimedAtRecheck.add(ConfigHandler.purgeRunning);
                        }
                        try {
                            return method.invoke(bridge, arguments);
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        }
                    });

                PurgeResult result = new ChunkedPurge(watched, context, new RecordingLog(), () -> null, CUTOFF,
                    CUTOFF + 30 * DAY).timing(0, 1, 60_000).run(false);

                assertTrue(result.completed(), () -> result.stopReason() + " " + result.detail());
                assertEquals(List.of(true), claimedAtPurge);
                assertEquals(List.of(true), claimedAtRecheck, "rechecked before the claim was released");
                assertFalse(ConfigHandler.purgeRunning);
            }

            /**
             * A stop while the lease waits for a busy consumer to park ends
             * the wait at once and gives back purgeRunning, which
             * CoreProtect's shutdown waits for.
             */
            @Test
            @DisplayName("should release its claim at once on a stop while it waits for the consumer to park")
            void stopWhileWaitingForConsumer() throws Exception {
                useClickHouse();
                // A consumer busy with a batch, which doesn't park; tests don't run the real one
                Thread busyConsumer = new Thread(() -> {
                    try {
                        Thread.sleep(60_000);
                    } catch (InterruptedException e) {
                        // Done
                    }
                });
                busyConsumer.setDaemon(true);
                busyConsumer.start();
                coreProtect.set("Consumer.consumerThread", busyConsumer);
                try {
                    PurgeContext stopping = new PurgeContext();
                    AtomicReference<Lease> lease = new AtomicReference<>();
                    Thread worker = new Thread(() -> {
                        try {
                            lease.set(bridge.lease(stopping, true));
                        } catch (InterruptedException e) {
                            lease.set(Lease.stop(StopReason.SHUTDOWN));
                        }
                    });
                    stopping.bind(worker);
                    worker.start();
                    Thread.sleep(500);
                    assertTrue(worker.isAlive(), "waiting for the consumer to park");
                    assertTrue(ConfigHandler.purgeRunning, "holding the purge claim while it waits");

                    long started = System.nanoTime();
                    coreProtect.call("Consumer.blockDatabaseReloadForShutdown");
                    stopping.requestStop();
                    while (ConfigHandler.purgeRunning && System.nanoTime() - started < 5_000_000_000L) {
                        Thread.sleep(5);
                    }
                    long waited = (System.nanoTime() - started) / 1_000_000;
                    worker.join(5000);

                    assertFalse(ConfigHandler.purgeRunning);
                    assertTrue(waited < 500, "purgeRunning released after " + waited + " ms");
                    assertFalse(lease.get().isGranted());
                    assertEquals(StopReason.SHUTDOWN, lease.get().stopReason());
                } finally {
                    busyConsumer.interrupt();
                    coreProtect.set("Consumer.consumerThread", null);
                }
            }

            @Test
            @DisplayName("should stop for a manual purge without touching its claim")
            void manualPurge() throws Exception {
                useClickHouse();
                assertEquals(StartResult.Kind.STARTED, kind(coreProtect.call("Consumer.claimPurge")));
                try {
                    Lease lease = bridge.lease(context, true);
                    assertFalse(lease.isGranted());
                    assertEquals(StopReason.MANUAL_PURGE, lease.stopReason());
                    assertTrue(ConfigHandler.purgeRunning, "the manual purge's claim stays");
                } finally {
                    coreProtect.call("Consumer.releasePurge");
                }
            }

            @Test
            @DisplayName("should wait while a rollback runs, and not keep the claim")
            void rollback() throws Exception {
                useClickHouse();
                assertEquals(StartResult.Kind.STARTED, kind(coreProtect.call("Consumer.claimRollback", "lpit")));
                try {
                    Lease lease = bridge.lease(context, true);
                    assertFalse(lease.isGranted());
                    assertEquals("a rollback is running", lease.busyReason());
                    assertFalse(ConfigHandler.purgeRunning);
                } finally {
                    coreProtect.call("Consumer.releaseRollback", "lpit");
                }
            }
        }

        @Nested
        @DisplayName("purging CoreProtect 25's schema")
        class Schema25 {

            /**
             * A despawned entity linked to an old block row, an orphan once
             * that row is gone, then one that is alive, since SQLite keeps
             * entity_spawn's newest row.
             */
            private void purgeWithEntitySpawns() throws Exception {
                execute("INSERT INTO co_block (time) VALUES (" + (CUTOFF - DAY) + ")",
                    "INSERT INTO co_block (time) VALUES (" + CUTOFF + ")",
                    "INSERT INTO co_entity_spawn (time, block_rowid, uuid, removed) VALUES (" + (CUTOFF - DAY)
                        + ", 1, 'gone', 1)",
                    "INSERT INTO co_entity_spawn (time, block_rowid, uuid, removed) VALUES (" + CUTOFF
                        + ", NULL, 'alive', 0)");

                PurgeResult result = purger(context).timing(0, 1, 60_000).run(false);

                assertTrue(result.completed(), () -> result.stopReason() + ": " + result.detail());
                assertEquals(List.of(2L), longs("SELECT rowid FROM co_block ORDER BY rowid"));
                assertEquals(List.of(CUTOFF), longs("SELECT time FROM co_entity_spawn"));
                assertEquals(2, result.removed());
                assertFalse(coreProtect.backgroundPurgeClaimed());
                assertFalse(Consumer.isPaused);
            }

            @Test
            @DisplayName("should remove orphaned entity spawns on SQLite")
            void sqlite() throws Exception {
                useFreshDatabase();
                purgeWithEntitySpawns();
            }

            @Test
            @DisplayName("should leave orphan cleanup to a later run while CoreProtect refills its list of tables")
            void tablesRefilling() throws Exception {
                useFreshDatabase();
                execute("INSERT INTO co_block (time) VALUES (" + (CUTOFF - DAY) + ")",
                    "INSERT INTO co_block (time) VALUES (" + CUTOFF + ")",
                    "INSERT INTO co_entity_spawn (time, block_rowid, uuid, removed) VALUES (" + (CUTOFF - DAY)
                        + ", 1, 'gone', 1)",
                    "INSERT INTO co_entity_spawn (time, block_rowid, uuid, removed) VALUES (" + CUTOFF
                        + ", NULL, 'alive', 0)");
                @SuppressWarnings("unchecked")
                List<String> tables = (List<String>) coreProtect.get("ConfigHandler.databaseTables");
                List<String> created = new ArrayList<>(tables);
                PurgeResult refilling;
                try {
                    // As between CoreProtect's clear() and addAll() of them
                    tables.clear();
                    assertNull(bridge.entitySpawnTracking());
                    // As a read that meets clear() part-way sees them, the first ones nulled
                    tables.addAll(created.subList(created.indexOf("entity_spawn") + 1, created.size()));
                    assertNull(bridge.entitySpawnTracking(), "can't tell, rather than no entity tracking");
                    assertFalse(bridge.tracksEntitySpawns());
                    refilling = purger(context).timing(0, 1, 60_000).run(false);
                } finally {
                    tables.clear();
                    tables.addAll(created);
                }

                assertTrue(refilling.completed(), () -> refilling.stopReason() + ": " + refilling.detail());
                assertFalse(refilling.orphansCleaned());
                assertEquals(List.of(CUTOFF - DAY, CUTOFF), longs("SELECT time FROM co_entity_spawn ORDER BY rowid"));
                assertEquals(Boolean.TRUE, bridge.entitySpawnTracking());

                PurgeResult later = purger(context).timing(0, 1, 60_000).run(true);

                assertTrue(later.completed(), () -> later.stopReason() + ": " + later.detail());
                assertTrue(later.orphansCleaned());
                assertEquals(List.of(CUTOFF), longs("SELECT time FROM co_entity_spawn"));
                assertFalse(coreProtect.backgroundPurgeClaimed());
            }

            /**
             * CoreProtect's own clear() and addAll() of its tables, as it
             * creates a schema, racing the question of whether there are
             * orphans: a "no" would mark the orphan cleanup done without
             * doing it.
             */
            @Test
            @DisplayName("should never take a list of tables that CoreProtect is refilling for a schema without entity"
                + " tracking")
            void racingRefill() throws Exception {
                useFreshDatabase();
                @SuppressWarnings("unchecked")
                List<String> tables = (List<String>) coreProtect.get("ConfigHandler.databaseTables");
                List<String> created = new ArrayList<>(tables);
                assertTrue(created.contains("entity_spawn"), created::toString);
                AtomicBoolean refilling = new AtomicBoolean(true);
                Thread coreProtectThread = new Thread(() -> {
                    while (refilling.get()) {
                        // As Database.createDatabaseTables does
                        tables.clear();
                        tables.addAll(created);
                    }
                });
                int unknown = 0;
                int tracked = 0;
                coreProtectThread.start();
                try {
                    // A second at least, and until a read got the whole list, as most do
                    long started = System.nanoTime();
                    while (System.nanoTime() - started < 1_000_000_000L
                        || (tracked == 0 && System.nanoTime() - started < 30_000_000_000L)) {
                        Boolean tracking = bridge.entitySpawnTracking();
                        assertNotEquals(Boolean.FALSE, tracking);
                        if (tracking == null) {
                            unknown++;
                        } else {
                            tracked++;
                        }
                    }
                } finally {
                    refilling.set(false);
                    coreProtectThread.join(5000);
                    tables.clear();
                    tables.addAll(created);
                }
                assertTrue(tracked > 0, "tracked " + tracked + ", unknown " + unknown);
            }

            @Test
            @DisplayName("should purge DuckDB")
            void duckdb() throws Exception {
                coreProtect.useEngine(Engine.DUCKDB).set("ConfigHandler.duckdb", "database.duckdb");
                useFreshDatabase();
                assertEquals(Engine.DUCKDB, bridge.activeEngine());
                purgeWithEntitySpawns();
            }

            /**
             * How often {@code /co rollback} is told a purge is in progress
             * while an auto-purge runs. Pausing four times as long as each
             * chunk holds its claim keeps that to about a fifth.
             */
            @Test
            @DisplayName("should let rollbacks through at least three times in four while it runs")
            void rollbackRefusals() throws Exception {
                useFreshDatabase();
                seed(600_000);
                PurgeContext purgeContext = new PurgeContext();
                AtomicReference<PurgeResult> result = new AtomicReference<>();
                Thread worker = start(purgeContext, result, purger(purgeContext));
                Thread.sleep(500);
                int started = 0;
                int refused = 0;
                long end = System.nanoTime() + 4_000_000_000L;
                while (System.nanoTime() < end && worker.isAlive()) {
                    StartResult.Kind claim = kind(coreProtect.call("Consumer.claimRollback", "lpit"));
                    if (claim == StartResult.Kind.STARTED) {
                        started++;
                        coreProtect.call("Consumer.releaseRollback", "lpit");
                    } else if (claim == StartResult.Kind.PURGE_RUNNING) {
                        refused++;
                    }
                    Thread.sleep(37);
                }
                purgeContext.requestStop();
                worker.join(10_000);

                assertTrue(started + refused >= 50, "attempts: " + (started + refused));
                assertTrue(refused * 4 <= started + refused, "refused " + refused + " of " + (started + refused));
                assertFalse(coreProtect.backgroundPurgeClaimed());
            }

            /**
             * CoreProtect 25's shutdown, in ShutdownService's order, while a
             * purge works through a large table and a consumer-like thread
             * writes: the claim is released within a moment, and the gate
             * with it.
             */
            @Test
            @DisplayName("should let CoreProtect 25's shutdown through within a second, with the gate clear")
            void shutdownMidRun() throws Exception {
                useFreshDatabase();
                seed(300_000);
                PurgeContext purgeContext = new PurgeContext();
                AtomicReference<PurgeResult> result = new AtomicReference<>();
                AtomicBoolean writing = new AtomicBoolean(true);
                AtomicInteger batches = new AtomicInteger();
                Thread writer = new Thread(() -> {
                    while (writing.get()) {
                        try {
                            // As the consumer: wait for the gate, then write under it
                            long deadline = System.nanoTime() + 500_000_000L;
                            while (Consumer.isPaused && System.nanoTime() < deadline) {
                                Thread.sleep(1);
                            }
                            try (Connection connection = Database.getConnection(false, 500)) {
                                if (connection != null) {
                                    Consumer.isPaused = true;
                                    try (Statement statement = connection.createStatement()) {
                                        statement.executeUpdate("INSERT INTO co_chat (time, user, message) VALUES ("
                                            + (CUTOFF + DAY) + ", 1, 'x')");
                                        batches.incrementAndGet();
                                    } finally {
                                        Consumer.isPaused = false;
                                    }
                                }
                            }
                            Thread.sleep(50);
                        } catch (Exception e) {
                            // Keep writing
                        }
                    }
                });
                writer.start();
                Thread worker = start(purgeContext, result, purger(purgeContext));
                Thread.sleep(1500);
                assertTrue(worker.isAlive(), "still purging");

                long started = System.nanoTime();
                coreProtect.call("Consumer.blockDatabaseReloadForShutdown");
                purgeContext.requestStop();
                coreProtect.set("ConfigHandler.shutdownDrainRunning", true);
                while (coreProtect.backgroundPurgeClaimed() && System.nanoTime() - started < 10_000_000_000L) {
                    Thread.sleep(10);
                }
                long waited = (System.nanoTime() - started) / 1_000_000;
                worker.join(10_000);
                writing.set(false);
                writer.join(10_000);

                assertTrue(waited < 1000, "shutdown waited " + waited + " ms for the claim");
                assertFalse(worker.isAlive());
                assertEquals(StopReason.SHUTDOWN, result.get().stopReason());
                assertTrue(batches.get() > 0, "the writer got through");
                assertFalse(Consumer.isPaused);
            }
        }
    }
}
