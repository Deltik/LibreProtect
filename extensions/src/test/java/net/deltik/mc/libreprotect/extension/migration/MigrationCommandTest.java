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

package net.deltik.mc.libreprotect.extension.migration;

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.FakeBridge.FakeSession;
import net.deltik.mc.libreprotect.testutil.RecordingSender;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.entity.Player;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.Executor;

import static org.junit.jupiter.api.Assertions.*;

class MigrationCommandTest {

    @TempDir
    Path folder;

    private RecordingSender console;
    private FakeSession session;
    private FakeBridge bridge;
    private final List<Runnable> started = new ArrayList<>();
    private final Executor deferred = started::add;

    @BeforeEach
    void setUp() throws Exception {
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(new TestLogger());
        console = new RecordingSender(ConsoleCommandSender.class);
        TestDatabases.createLegacySqlite(folder.resolve("source.db").toFile(), 10);
        session = new FakeSession(Engine.SQLITE, folder.resolve("source.db").toFile(), Engine.DUCKDB,
            folder.resolve("target.duckdb").toFile());
        bridge = new FakeBridge(session);
    }

    @AfterEach
    void tearDown() {
        // Let a migration a test left pending finish, so the next test can start one
        started.forEach(Runnable::run);
        LibreProtectLogger.reset();
    }

    private void run(CommandSender sender, String... arguments) {
        MigrationCommand.run(sender, arguments, bridge, deferred);
    }

    private void run(String... arguments) {
        run(console.sender(), arguments);
    }

    @Nested
    @DisplayName("arguments")
    class Arguments {

        @ParameterizedTest
        @ValueSource(strings = {"", "postgres", "mysql sqlite", "duckdb --fast", "--full-validation"})
        @DisplayName("should show the usage for missing or unknown arguments")
        void usage(String arguments) {
            List<String> tokens = new ArrayList<>(List.of("migrate-db"));
            if (!arguments.isEmpty()) {
                tokens.addAll(List.of(arguments.split(" ")));
            }

            run(tokens.toArray(new String[0]));

            // Not SQLite, which CoreProtect uses
            assertEquals("LibreProtect - Usage: /co migrate-db <mysql|duckdb> [--full-validation]",
                console.plainMessages().get(0));
            assertTrue(bridge.claims.isEmpty());
            assertTrue(started.isEmpty());
        }

        @Test
        @DisplayName("should list only the databases it can migrate to, without the one in use")
        void usageListsTargets() {
            bridge.unavailableTargets.put(Engine.DUCKDB, "SQLite and DuckDB encode data differently, and"
                + " CoreProtect's conversions aren't available");
            run("migrate-db");
            bridge.active = Engine.MYSQL;
            bridge.unavailableTargets.clear();
            run("migrate-db");

            assertEquals(List.of("LibreProtect - Usage: /co migrate-db <mysql> [--full-validation]",
                "LibreProtect - Usage: /co migrate-db <sqlite|duckdb> [--full-validation]"), console.plainMessages()
                .stream().filter(line -> line.contains("Usage:")).toList());
        }

        @Test
        @DisplayName("should say why there's no database to migrate to")
        void usageWithoutTargets() {
            bridge.engines = EnumSet.of(Engine.SQLITE, Engine.MYSQL);
            bridge.unavailableTargets.put(Engine.MYSQL, "CoreProtect's MySQL schema code changed");

            run("migrate-db");

            List<String> messages = console.plainMessages();
            assertEquals("LibreProtect - Usage: /co migrate-db <database> [--full-validation]", messages.get(0));
            assertEquals("No database can be migrated to with this CoreProtect build: CoreProtect's MySQL schema code"
                + " changed", messages.get(messages.size() - 1));
        }

        @Test
        @DisplayName("should show the usage when upstream passes only the subcommand, or nothing at all")
        void noArguments() {
            run();
            run("migrate-db");

            assertEquals(2, console.plainMessages().stream().filter(line -> line.contains("Usage:")).count());
        }

        @Test
        @DisplayName("should accept the engine and --full-validation in any order and case")
        void parses() {
            MigrationArguments arguments = MigrationArguments.parse(new String[]{"migrate-db", "--FULL-validation", "DuckDB"});

            assertNotNull(arguments);
            assertEquals(Engine.DUCKDB, arguments.target());
            assertTrue(arguments.fullValidation());
            assertFalse(MigrationArguments.parse(new String[]{"migrate-db", "mysql"}).fullValidation());
        }

        @Test
        @DisplayName("should list only the engines of the CoreProtect generation")
        void usagePerGeneration() {
            assertEquals("/co migrate-db <sqlite|mysql> [--full-validation]",
                MigrationArguments.usage(EnumSet.of(Engine.MYSQL, Engine.SQLITE)));
            assertEquals("/co migrate-db <sqlite|mysql|duckdb|clickhouse> [--full-validation]",
                MigrationArguments.usage(EnumSet.allOf(Engine.class)));
            assertEquals("/co migrate-db <database> [--full-validation]",
                MigrationArguments.usage(EnumSet.noneOf(Engine.class)));
        }

        @Test
        @DisplayName("should say that an engine isn't available with this CoreProtect version")
        void unavailableEngine() {
            bridge.engines = EnumSet.of(Engine.SQLITE, Engine.MYSQL);

            run("migrate-db", "clickhouse");

            assertEquals("LibreProtect - ClickHouse isn't available with this CoreProtect version. Usage: /co migrate-db"
                + " <mysql> [--full-validation]", console.plainMessages().get(0));
            assertTrue(bridge.claims.isEmpty());
        }

        @Test
        @DisplayName("should say why migrations aren't available with this CoreProtect build, whatever the arguments")
        void unavailableMigrations() {
            bridge.unavailable = "CoreProtect has no Consumer.lockDatabaseReload(long)";

            run("migrate-db", "duckdb");
            run("migrate-db");

            assertEquals(List.of("LibreProtect - /co migrate-db isn't available with this CoreProtect build: CoreProtect"
                + " has no Consumer.lockDatabaseReload(long)", "LibreProtect - /co migrate-db isn't available with this"
                + " CoreProtect build: CoreProtect has no Consumer.lockDatabaseReload(long)"), console.plainMessages());
            assertTrue(bridge.claims.isEmpty());
        }

        @Test
        @DisplayName("should say why migrating to an engine isn't available with this CoreProtect build")
        void unavailableTarget() {
            bridge.engines = EnumSet.of(Engine.SQLITE, Engine.MYSQL);
            bridge.unavailableTargets.put(Engine.CLICKHOUSE, "LibreProtect can't write ClickHouse databases in"
                + " migrations yet");
            bridge.unavailableTargets.put(Engine.DUCKDB, "SQLite and DuckDB encode data differently, and CoreProtect's"
                + " conversions aren't available");

            run("migrate-db", "clickhouse");
            run("migrate-db", "duckdb");

            assertEquals(List.of("LibreProtect - Migrating to ClickHouse isn't available with this CoreProtect build:"
                + " LibreProtect can't write ClickHouse databases in migrations yet", "LibreProtect - Migrating to"
                + " DuckDB isn't available with this CoreProtect build: SQLite and DuckDB encode data differently, and"
                + " CoreProtect's conversions aren't available"), console.plainMessages());
            assertTrue(bridge.claims.isEmpty());
        }
    }

    @Nested
    @DisplayName("refusals")
    class Refusals {

        @Test
        @DisplayName("should only take the command from the console")
        void consoleOnly() {
            RecordingSender player = new RecordingSender(Player.class);

            run(player.sender(), "migrate-db", "duckdb");

            assertEquals(List.of("LibreProtect - Only the server console can run /co migrate-db."),
                player.plainMessages());
            assertTrue(bridge.claims.isEmpty());
        }

        @Test
        @DisplayName("should refuse the engine CoreProtect already uses")
        void sameEngine() {
            run("migrate-db", "sqlite");

            assertEquals(List.of("LibreProtect - CoreProtect already uses SQLite. Name a different database to"
                + " migrate to."), console.plainMessages());
            assertTrue(bridge.claims.isEmpty());
        }

        @Test
        @DisplayName("should pass on why CoreProtect can't start a migration now")
        void claimRefused() {
            bridge.refusal = new MigrationException("A purge is running. Wait for it to finish.");

            run("migrate-db", "duckdb");

            assertEquals(List.of("LibreProtect - A purge is running. Wait for it to finish."), console.plainMessages());
            assertTrue(started.isEmpty());
            bridge.refusal = null;
            run("migrate-db", "duckdb");
            assertEquals(1, started.size(), "a refused claim kept blocking migrations");
        }

        @Test
        @DisplayName("should run one migration at a time")
        void oneAtATime() {
            run("migrate-db", "duckdb");
            run("migrate-db", "duckdb");

            assertEquals(1, started.size());
            assertEquals(List.of(Engine.DUCKDB), bridge.claims);
            assertTrue(console.text().contains("A migration is already running."), console.text());

            started.remove(0).run();
            run("migrate-db", "duckdb");
            assertEquals(1, started.size(), "the finished migration still blocks new ones");
        }

        @Test
        @DisplayName("should release the claim when the migration's thread can't start")
        void threadFails() {
            MigrationCommand.run(console.sender(), new String[]{"migrate-db", "duckdb"}, bridge, command -> {
                throw new OutOfMemoryError("unable to create native thread");
            });

            assertEquals(1, session.closes.get());
            assertTrue(console.text().contains("The migration couldn't start"), console.text());
            run("migrate-db", "duckdb");
            assertEquals(1, started.size());
        }
    }

    @Test
    @DisplayName("should migrate on the executor's thread, and release the claim there")
    void migrates() {
        run("migrate-db", "duckdb", "--full-validation");

        assertEquals(1, started.size());
        assertEquals(0, session.pauses.get(), "work started on the command's thread");
        started.remove(0).run();

        assertTrue(console.text().contains("Migration complete."), console.text());
        assertTrue(console.text().contains("Validating every copied row"), console.text());
        assertEquals(1, session.closes.get());
    }
}
