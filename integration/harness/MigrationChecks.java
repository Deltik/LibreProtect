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

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * {@code /co migrate-db} across database engines, using the MySQL container,
 * and for CoreProtect 25 the ClickHouse container. The test plugin's side is
 * {@code MigrationScenario}.
 *
 * <p>One server migrates along a chain of engines, one hop per boot, and the
 * boot after each hop checks that CoreProtect starts on the target and finds
 * everything. CoreProtect 24 goes SQLite → MySQL → SQLite, the way its docs
 * have users do it: select the target in config.yml while the server runs,
 * then migrate (the way back relies on the migration selecting SQLite in
 * config.yml). CoreProtect 25 goes SQLite → MySQL → ClickHouse → DuckDB →
 * SQLite with the targets configured before the boot, as its docs require,
 * so every engine is a source and a target. At each hop:
 * <ul>
 *   <li>placements logged while the migration runs end up in the target;</li>
 *   <li>every table of the target holds exactly the source's rows, with the
 *       same row IDs, by a digest of each side, and by counting MySQL and
 *       ClickHouse targets directly;</li>
 *   <li>config.yml selects the target;</li>
 *   <li>a target that already holds data is refused, as is the engine in use.</li>
 * </ul>
 * A ClickHouse target also keeps its own single version row, is no longer
 * marked unfinished, hands out row IDs after the source's high-water marks,
 * and CoreProtect's lookups by player find the copied rows there, through
 * its lookup index where it has one. To insert a hop, add it to
 * {@link #hops} and its settings to the server's config.yml.
 */
final class MigrationChecks {

    /** CoreProtect 25's tables, a superset of CoreProtect 24's */
    private static final List<String> TABLES = List.of("art_map", "block", "chat", "command", "container",
        "entity_container", "entity_interaction", "item", "database_lock", "entity", "entity_spawn", "entity_map",
        "material_map", "blockdata_map", "session", "sign", "skull", "user", "username_log", "version", "world");

    private static final int SEEDED = 1_500;
    private static final int DURING = 25;
    /** config.yml's line that turns update checks off: they are requests of their own, which UpdateChecks covers */
    private static final String NO_UPDATE_CHECKS = "check-updates: false\n";

    private MigrationChecks() {
    }

    /**
     * @param target the engine to migrate to
     * @param configLines config.yml lines to set while the server runs,
     *                    before migrating, separated by {@code |}; empty for none
     */
    private record Hop(String target, String configLines) {
    }

    static void run(Harness.Suite suite) throws Exception {
        Harness.Database mysql = suite.containers().mysql();
        Harness.Database clickHouse = suite.generation() == 24 ? null : suite.containers().clickhouse();
        String prefix = "lpit" + ProcessHandle.current().pid() % 100_000 + "_";
        String interruptedPrefix = "lpit" + ProcessHandle.current().pid() % 100_000 + "i_";
        // Each on a server of its own, and under a table prefix of its own
        Map<String, Harness.Checks> parts = new LinkedHashMap<>();
        parts.put("chain", part -> {
            dropTables(mysql, prefix);
            dropClickHouseTables(clickHouse, prefix);
            try {
                Harness.Server server = part.newServer("chain");
                server.timeout(Duration.ofMinutes(8));
                if (part.generation() == 24) {
                    server.coreProtectConfig("use-mysql: false\n" + NO_UPDATE_CHECKS + "table-prefix: " + prefix + "\n");
                } else {
                    server.coreProtectConfig("database-type: sqlite\n" + NO_UPDATE_CHECKS + "table-prefix: " + prefix
                        + "\n" + mysql.coreProtectConfig() + clickHouse.coreProtectConfig());
                }
                chain(part, server, mysql, clickHouse, prefix, hops(part, mysql));
            } finally {
                dropTables(mysql, prefix);
                dropClickHouseTables(clickHouse, prefix);
            }
        });
        parts.put("interrupt", part -> {
            dropTables(mysql, interruptedPrefix);
            try {
                interrupted(part, mysql, interruptedPrefix);
            } finally {
                dropTables(mysql, interruptedPrefix);
            }
        });
        suite.concurrently(parts);
    }

    /**
     * The server stops while a migration writes its target: the migration
     * stops without switching, CoreProtect saves the events queued meanwhile
     * to the source and shuts down, and the next boot runs on the source. The
     * target stays marked unfinished.
     */
    private static void interrupted(Harness.Suite suite, Harness.Database mysql, String prefix) throws Exception {
        int seeded = 50_000;
        Harness.Server server = suite.newServer("interrupt");
        server.timeout(Duration.ofMinutes(8));
        server.coreProtectConfig((suite.generation() == 24 ? "use-mysql: false\n" : "database-type: sqlite\n")
            + NO_UPDATE_CHECKS + "table-prefix: " + prefix + "\n" + mysql.coreProtectConfig());
        Harness.Scenario scenario = Harness.Scenario.steps("migration.seed", "migration.interrupt")
            .set("timeout.ticks", 8_400)
            .set("migration.seed.count", seeded)
            .set("migration.interrupt.target", "mysql")
            .set("migration.interrupt.prefix", prefix)
            .set("migration.interrupt.during", DURING)
            .set("migration.interrupt.lane", 1);
        // The step watches the target, and ends the boot once the migration has marked it unfinished
        access(scenario, mysql);
        Harness.Run stopped = server.boot(Harness.Variant.FORK, scenario);
        String name = "stopping during a migration";
        checkBoot(suite, stopped, name);
        suite.check("true".equals(stopped.result("migration.interrupt.running")),
            name + ": the migration was running when the server began to stop");
        suite.check(stopped.console().contains("LibreProtect - Migration failed. The migration stopped because the"
            + " server is stopping."), name + ": the migration stops and says why");
        suite.check(stopped.console().contains("Success! Disabled LibreProtect"), name + ": LibreProtect shuts down");
        String tables = mysql.query("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()"
            + " AND TABLE_NAME = '" + prefix + "database_lock'").trim();
        String lock = tables.equals("0") ? ""
            : mysql.query("SELECT status, time FROM " + prefix + "database_lock WHERE rowid = 1").trim();
        boolean unfinished = suite.generation() == 24 ? lock.equals("1\t" + Integer.MAX_VALUE) : lock.startsWith("2\t");
        suite.check(unfinished, name + ": the partly written target is marked unfinished ("
            + (lock.isEmpty() ? "no lock row" : lock.replace('\t', ' ')) + ")");

        Harness.Run next = server.boot(Harness.Variant.FORK, Harness.Scenario.steps("migration.check")
            .set("migration.check.lanes", "0:" + seeded + ",1:" + DURING));
        name = "boot after stopping during a migration";
        checkBoot(suite, next, name);
        checkStartup(suite, next, name, "sqlite", 1);
    }

    private static List<Hop> hops(Harness.Suite suite, Harness.Database mysql) {
        if (suite.generation() == 24) {
            String selectMySQL = "use-mysql: true|mysql-host: " + mysql.host() + "|mysql-port: " + mysql.port()
                + "|mysql-database: " + mysql.database() + "|mysql-username: " + mysql.username()
                + "|mysql-password: \"" + mysql.password() + "\"";
            return List.of(new Hop("mysql", selectMySQL), new Hop("sqlite", ""));
        }
        return List.of(new Hop("mysql", ""), new Hop("clickhouse", ""), new Hop("duckdb", ""), new Hop("sqlite", ""));
    }

    /**
     * @param clickHouse the ClickHouse container, or {@code null} for CoreProtect 24
     */
    private static void chain(Harness.Suite suite, Harness.Server server, Harness.Database mysql,
                              Harness.Database clickHouse, String prefix, List<Hop> hops) throws Exception {
        String active = "sqlite";
        List<String> used = new ArrayList<>(List.of("sqlite"));
        for (int hop = 0; hop <= hops.size(); hop++) {
            List<String> steps = new ArrayList<>();
            Harness.Scenario scenario = Harness.Scenario.steps();
            scenario.set("timeout.ticks", 8_400);
            access(scenario, mysql);
            if (clickHouse != null) {
                access(scenario, clickHouse);
            }
            if (hop == 0) {
                steps.add("migration.seed");
                scenario.set("migration.seed.count", SEEDED);
                scenario.set("migration.seed.encoded", true);
                // Rows for each table that CoreProtect 25's ClickHouse lookup index indexes
                scenario.set("migration.seed.indexed", clickHouse != null);
                steps.add("migration.run-same");
                scenario.set("migration.run-same.target", active);
            } else {
                steps.add("migration.check");
                scenario.set("migration.check.lanes", lanes(hop));
            }
            List<String> occupied = new ArrayList<>();
            Hop next = hop < hops.size() ? hops.get(hop) : null;
            for (String engine : used) {
                // Every engine that holds data refuses to be a target, until it's moved away
                if (!engine.equals(active) && (next == null || engine.equals(next.target()))) {
                    String step = "migration.run-occupied-" + engine;
                    steps.add(step);
                    scenario.set(step + ".target", engine);
                    occupied.add(engine);
                }
            }
            if (next != null && used.contains(next.target())) {
                steps.add("migration.archive");
            }
            String run = null;
            if (next != null) {
                if (!next.configLines().isEmpty()) {
                    steps.add("migration.config");
                    scenario.set("migration.config.lines", next.configLines());
                }
                run = "migration.run-" + next.target();
                steps.add(run);
                scenario.set(run + ".target", next.target());
                scenario.set(run + ".during", DURING);
                scenario.set(run + ".lane", hop + 1);
                // Whether CoreProtect's lookups by player, which read ClickHouse's lookup index, find what was copied
                scenario.set(run + ".lookups", next.target().equals("clickhouse"));
                if (hop == hops.size() - 1) {
                    scenario.set(run + ".options", "--full-validation");
                }
            }
            scenario.set("steps", String.join(",", steps));

            Harness.Run boot = server.boot(Harness.Variant.FORK, scenario);
            String name = "boot " + boot.number() + (next == null ? " on " + active : " (" + active + " -> "
                + next.target() + ")");
            checkBoot(suite, boot, name);
            if (hop == 0) {
                suite.check(boot.console().contains("LibreProtect - CoreProtect already uses SQLite. Name a different"
                    + " database to migrate to."), name + ": refuses to migrate to the engine in use");
                suite.check("true".equals(boot.result("migration.seed.killed")),
                    name + ": a named cow died, so CoreProtect logged entity data");
                suite.note(name + ": banner " + boot.result("migration.seed.banner") + ", dispenser spawned "
                    + boot.result("migration.seed.dispensed"));
            } else {
                checkStartup(suite, boot, name, active, hop);
            }
            for (String engine : occupied) {
                checkOccupied(suite, boot, name, engine, prefix);
            }
            if (next != null) {
                checkHop(suite, server, boot, name, run, active, next.target(), mysql, clickHouse, prefix);
                active = next.target();
                if (!used.contains(active)) {
                    used.add(active);
                }
            }
        }
    }

    /** Lanes 0 (seeded) to {@code hops}, each with its number of placements */
    private static String lanes(int hops) {
        StringBuilder lanes = new StringBuilder("0:" + SEEDED);
        for (int lane = 1; lane <= hops; lane++) {
            lanes.append(',').append(lane).append(':').append(DURING);
        }
        return lanes.toString();
    }

    /** How the test plugin reads the database as a source: {@code migration.mysql.*} or {@code migration.clickhouse.*} */
    private static void access(Harness.Scenario scenario, Harness.Database database) {
        String key = "migration." + database.kind() + ".";
        scenario.set(key + "host", database.host())
            .set(key + "port", database.port())
            .set(key + "database", database.database())
            .set(key + "username", database.username())
            .set(key + "password", database.password());
    }

    private static void checkBoot(Harness.Suite suite, Harness.Run boot, String name) {
        List<String> errors = new ArrayList<>();
        boot.results().stringPropertyNames().stream()
            .filter(key -> key.endsWith(".error") || key.endsWith(".timeout"))
            .sorted()
            .forEach(key -> errors.add(key + "=" + boot.result(key)));
        suite.check(errors.isEmpty(), name + ": every step ran" + (errors.isEmpty() ? "" : ": " + errors));
        suite.check(boot.exitCode() == 0, name + ": server exited cleanly (exit code " + boot.exitCode() + ")");
        suite.check(!boot.console().contains("\tat net.deltik.mc.libreprotect."),
            name + ": no stack traces from LibreProtect");
    }

    /** The boot after a hop: CoreProtect starts on the target and finds every lane logged so far */
    private static void checkStartup(Harness.Suite suite, Harness.Run boot, String name, String active, int hop) {
        suite.check(active.toUpperCase(Locale.ROOT).equals(boot.result("migration.check.active")),
            name + ": CoreProtect starts on " + active + " (" + boot.result("migration.check.active") + ")");
        String lookups = String.valueOf(boot.result("migration.check.lookups"));
        suite.note(name + " lookups (lane:placement=rows): " + lookups);
        // The first, middle and last placement of the seed's lane and of each migration's
        suite.check(lookups.split(",").length == 3 * (hop + 1) && !lookups.contains("=0") && !lookups.contains("=-1"),
            name + ": lookups find the placements of the seed and of every migration");
    }

    private static void checkOccupied(Harness.Suite suite, Harness.Run boot, String name, String engine, String prefix) {
        String step = "migration.run-occupied-" + engine;
        suite.check(boot.result(step + ".active.before") != null
                && boot.result(step + ".active.before").equals(boot.result(step + ".active.after")),
            name + ": a refused migration to " + engine + " leaves CoreProtect as it was");
        String expected = switch (engine) {
            case "sqlite" -> "The target already holds CoreProtect data: plugins/CoreProtect/database.db has rows"
                + " in table co_";
            case "duckdb" -> "The target already holds CoreProtect data: plugins/CoreProtect/database.duckdb already"
                + " exists, and a DuckDB target must be a new file";
            case "clickhouse" -> "The target already holds CoreProtect data: ClickHouse database '"
                + suite.containers().clickhouse().database() + "' already has CoreProtect data with table prefix '"
                + prefix + "'";
            default -> "The target already holds CoreProtect data: table " + prefix;
        };
        suite.check(boot.console().contains("LibreProtect - Migration failed. " + expected),
            name + ": refuses to migrate to " + engine + ", which holds data");
    }

    private static void checkHop(Harness.Suite suite, Harness.Server server, Harness.Run boot, String name, String step,
                                 String source, String target, Harness.Database mysql, Harness.Database clickHouse,
                                 String prefix) throws Exception {
        String display = switch (target) {
            case "mysql" -> "MySQL";
            case "duckdb" -> "DuckDB";
            case "clickhouse" -> "ClickHouse";
            default -> "SQLite";
        };
        String console = boot.console();
        suite.check(console.contains("LibreProtect - Migration complete. CoreProtect now uses the " + display
            + " database"), name + ": the migration completes");
        suite.check(!console.contains("LibreProtect - Migration failed. CoreProtect couldn't switch"),
            name + ": the switch succeeded the first time");
        suite.check(target.toUpperCase(Locale.ROOT).equals(boot.result(step + ".active.after")),
            name + ": CoreProtect uses " + target + " right away (" + boot.result(step + ".active.after") + ")");
        suite.check("true".equals(boot.result(step + ".loggedWhilePaused")),
            name + ": placements were logged while the migration held CoreProtect's queue");
        suite.check("true".equals(boot.result(step + ".saved")),
            name + ": placements logged during the migration are saved to the target");

        String digests = String.valueOf(boot.result(step + ".digests"));
        if (digests.startsWith("skipped")) {
            suite.note(name + ": no table digests (" + digests + ")");
            checkConfig(suite, server, name, target);
            return;
        }
        List<String> differences = new ArrayList<>();
        List<String> tables = new ArrayList<>();
        for (String key : boot.results().stringPropertyNames()) {
            if (key.startsWith(step + ".table.") && key.endsWith(".source")) {
                String table = key.substring((step + ".table.").length(), key.length() - ".source".length());
                tables.add(table);
                String copied = boot.result(step + ".table." + table + ".target");
                if (!boot.result(key).equals(copied)) {
                    differences.add(table + ": source " + boot.result(key) + ", target " + copied);
                }
            }
        }
        tables.sort(null);
        suite.note(name + " rows (source>target): " + tables.stream()
            .map(table -> table + "=" + boot.result(step + ".table." + table + ".rows")).toList());
        suite.check(!tables.isEmpty() && differences.isEmpty(), name + ": every table of the target holds the"
            + " source's rows with their row IDs (" + tables.size() + " tables)"
            + (differences.isEmpty() ? "" : ": " + differences));
        String coverage = String.valueOf(boot.result(step + ".coverage"));
        suite.note(name + " encoded values in the source: " + coverage);
        suite.check(count(coverage, "block.meta") >= 2 && count(coverage, "entity.data") >= 1,
            name + ": the source has block metadata and entity data, which CoreProtect 25 encodes per engine");
        suite.check(!String.valueOf(boot.result(step + ".table.block.source")).startsWith("0;"),
            name + ": the source had block rows to copy");
        // The consumer held the placements logged during the migration and wrote them after the switch
        String[] blocks = String.valueOf(boot.result(step + ".table.block.rows")).split(">");
        suite.check(blocks.length == 2 && Integer.parseInt(blocks[1]) - Integer.parseInt(blocks[0]) == DURING,
            name + ": the " + DURING + " placements logged during the migration are in the target, not the source"
                + " (block rows in source>target: " + boot.result(step + ".table.block.rows") + ")");

        if (target.equals("mysql") || target.equals("clickhouse")) {
            Harness.Database database = target.equals("mysql") ? mysql : clickHouse;
            List<String> miscounted = new ArrayList<>();
            for (String table : tables) {
                String[] copied = boot.result(step + ".table." + table + ".source").split(";");
                String counted = database.query("SELECT COUNT(*), COALESCE(MIN(rowid), 0), COALESCE(MAX(rowid), 0)"
                    + " FROM " + prefix + table + " WHERE rowid <= " + copied[2]).trim();
                if (!counted.equals(copied[0] + "\t" + copied[1] + "\t" + copied[2])) {
                    miscounted.add(table + ": " + counted.replace('\t', ';') + " instead of " + copied[0] + ";"
                        + copied[1] + ";" + copied[2]);
                }
            }
            suite.check(miscounted.isEmpty(), name + ": " + display + " itself counts the copied rows and row IDs"
                + (miscounted.isEmpty() ? "" : ": " + miscounted));
        }
        if (target.equals("clickhouse")) {
            checkClickHouseTarget(suite, boot, name, step, mysql, clickHouse, prefix);
        }
        checkConfig(suite, server, name, target);
    }

    /**
     * What only a ClickHouse target does: keep its own single version row
     * instead of the source's, clear its unfinished-migration mark only once
     * CoreProtect uses it, hand out row IDs after the source's high-water
     * marks, as the placements logged during the migration show, and let
     * CoreProtect's lookups by player, which read its lookup index where it
     * has one, find what they found on the source. Where CoreProtect has the
     * index, it indexes every row of the tables that those lookups read.
     */
    private static void checkClickHouseTarget(Harness.Suite suite, Harness.Run boot, String name, String step,
                                              Harness.Database mysql, Harness.Database clickHouse, String prefix)
        throws Exception {
        String versions = clickHouse.query("SELECT count() FROM " + prefix + "version").trim();
        suite.check(versions.equals("1"), name + ": ClickHouse keeps its own single version row (" + versions + ")");
        String locks = clickHouse.query("SELECT status FROM " + prefix + "database_lock").trim();
        suite.check(!locks.isEmpty() && !locks.contains("\n") && !locks.equals("2"),
            name + ": ClickHouse's database lock isn't marked unfinished (status " + locks.replace('\n', ',') + ")");

        // The source is left as it was, so its high-water marks are those of the migration
        String[] source = mysql.query("SET SESSION information_schema_stats_expiry = 0; SELECT"
            + " (SELECT COALESCE(MAX(rowid), 0) FROM " + prefix + "block),"
            + " (SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()"
            + " AND TABLE_NAME = '" + prefix + "block')").trim().split("\t");
        long highWater = Math.max(Long.parseLong(source[0]), Long.parseLong(source[1]) - 1);
        String after = clickHouse.query("SELECT count(), min(rowid) FROM " + prefix + "block WHERE rowid > "
            + source[0]).trim();
        String[] logged = after.split("\t");
        suite.check(logged.length == 2 && logged[0].equals(String.valueOf(DURING))
                && Long.parseLong(logged[1]) > highWater,
            name + ": the " + DURING + " placements saved after the switch have row IDs above MySQL's high-water mark "
                + highWater + " (count and smallest row ID above MySQL's largest: " + after.replace('\t', ' ') + ")");

        // The seed's user's rows, up to when the migration started, which CoreProtect counted on each side
        String onSource = boot.result(step + ".lookups.before");
        String onTarget = boot.result(step + ".lookups.after");
        suite.check(onSource != null && !onSource.equals("0") && onSource.equals(onTarget), name + ": CoreProtect's"
            + " lookup by player finds as many of the migrated rows on ClickHouse as it did on the source (" + onSource
            + " on the source, " + onTarget + " on ClickHouse)");

        String lookupIndex = clickHouse.query("SELECT count() FROM system.columns WHERE database = currentDatabase()"
            + " AND table = '" + prefix + "event_data' AND name = 'lookup_kind'").trim();
        if (lookupIndex.equals("0")) {
            suite.note(name + ": CoreProtect has no ClickHouse lookup index");
            return;
        }
        // CoreProtect's index rows, under its batch receipt family, number the tables that they index in x
        List<String> indexed = List.of("block", "container", "entity_container", "item", "entity_interaction");
        List<String> counts = new ArrayList<>();
        boolean complete = true;
        for (int code = 1; code <= indexed.size(); code++) {
            String table = indexed.get(code - 1);
            String[] rows = clickHouse.query("SELECT (SELECT count() FROM " + prefix + table + "), (SELECT count()"
                + " FROM " + prefix + "event_data FINAL WHERE family = '_batch_receipt' AND lookup_kind = 1"
                + " AND x = " + code + ")").trim().split("\t");
            // The seed has rows in each of them, so none passes for being empty
            complete &= rows.length == 2 && !rows[0].equals("0") && rows[0].equals(rows[1]);
            counts.add(table + "=" + String.join("/", rows));
        }
        suite.check(complete, name + ": CoreProtect's lookup index has an index row for each row of every table"
            + " that it indexes, all of which have rows (rows/index rows: " + String.join(", ", counts) + ")");
    }

    private static void checkConfig(Harness.Suite suite, Harness.Server server, String name, String target)
        throws Exception {
        String config = Files.readString(server.coreProtectFolder().resolve("config.yml"), StandardCharsets.UTF_8);
        if (suite.generation() == 24) {
            String selector = "use-mysql: " + target.equals("mysql");
            suite.check(config.lines().filter(line -> line.startsWith("use-mysql:")).toList().equals(List.of(selector)),
                name + ": config.yml selects " + target + " (" + selector + ")");
        } else {
            suite.check(config.lines().filter(line -> line.startsWith("database-type:")).toList()
                    .equals(List.of("database-type: " + target)),
                name + ": config.yml selects " + target + " (database-type: " + target + ")");
        }
    }

    /**
     * @return the number after {@code name=} in a list like {@code block.meta=3,entity.data=1}, or 0
     */
    private static long count(String list, String name) {
        for (String entry : list.split(",")) {
            if (entry.startsWith(name + "=")) {
                return Long.parseLong(entry.substring(name.length() + 1));
            }
        }
        return 0;
    }

    /**
     * Remove CoreProtect's ClickHouse views and tables of a prefix, which
     * each run of this suite uses anew.
     *
     * @param clickHouse the ClickHouse container, or {@code null} for none
     */
    private static void dropClickHouseTables(Harness.Database clickHouse, String prefix) throws Exception {
        if (clickHouse == null) {
            return;
        }
        String listed = clickHouse.query("SELECT name, engine = 'View' FROM system.tables"
            + " WHERE database = currentDatabase() AND startsWith(name, '" + prefix + "') ORDER BY engine = 'View' DESC");
        for (String line : listed.split("\n")) {
            if (line.isBlank()) {
                continue;
            }
            String[] table = line.split("\t");
            clickHouse.query("DROP " + (table[1].equals("1") ? "VIEW" : "TABLE") + " IF EXISTS `" + table[0] + "`"
                + (table[1].equals("1") ? "" : " SYNC"));
        }
    }

    /**
     * Remove the MySQL tables of a prefix, which each run of this suite uses anew.
     */
    private static void dropTables(Harness.Database mysql, String prefix) throws Exception {
        StringBuilder sql = new StringBuilder();
        for (String table : TABLES) {
            sql.append("DROP TABLE IF EXISTS `").append(prefix).append(table).append("`;");
        }
        mysql.query(sql.toString());
    }
}
