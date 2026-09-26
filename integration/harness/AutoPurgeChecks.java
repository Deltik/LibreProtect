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

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Auto-purge on every database engine the upstream generation supports:
 * SQLite and MySQL, plus DuckDB and ClickHouse for CoreProtect 25. The test
 * plugin's side is {@code AutoPurgeScenario}.
 *
 * <p>Each engine gets a fresh LibreProtect server with {@code auto-purge: 30d}.
 * The scenario logs a row A, and 2 seconds later rows B and C, then purges
 * everything before B through LibreProtect's test hook, which skips the
 * 30-day minimum. A must be gone and B and C must remain, {@code /co status}
 * must count the rows removed, and the startup log must show the next run.
 * On CoreProtect 25's SQLite, MySQL and DuckDB, the purge's orphan cleanup
 * must also remove an old unreferenced {@code entity_spawn} row and clear a
 * link to A. MySQL and ClickHouse tables get a prefix of their own, emptied
 * before and after. The suite first drops the tables that earlier runs left
 * behind, if they were stopped before they could.
 *
 * <p>Alongside them, a server stops while auto-purge removes many old rows
 * from SQLite, and the next boot's purge must remove what the stopped one
 * left.
 */
final class AutoPurgeChecks {

    /**
     * Table prefix on the shared database servers, so other suites' tables,
     * and those of integration tests that run at the same time, are left
     * alone. It names the harness's process, so that {@link #dropLeftovers}
     * can tell whether the harness that used a prefix still runs.
     */
    private static final String PREFIX = "lpap" + ProcessHandle.current().pid() + "_";
    /** A table under the prefix of any harness, and that harness's process ID */
    private static final Pattern PREFIXED = Pattern.compile("lpap([0-9]{1,18})_.*");
    private static final Pattern NEXT_RUN = Pattern.compile(
        "\\[LibreProtect] Auto-purge keeps 30 days of data\\. Next run: \\d{4}-\\d{2}-\\d{2} 03:30 \\(server time\\)\\.");

    private AutoPurgeChecks() {
    }

    static void run(Harness.Suite suite) throws Exception {
        List<String> engines = new ArrayList<>(List.of("sqlite", "mysql"));
        dropLeftovers(suite.containers().mysql());
        if (suite.generation() >= 25) {
            engines.addAll(List.of("duckdb", "clickhouse"));
            dropLeftovers(suite.containers().clickhouse());
        }
        // Each on a server of its own, and on MySQL and ClickHouse under a table prefix that nothing else uses
        Map<String, Harness.Checks> parts = new LinkedHashMap<>();
        for (String engine : engines) {
            parts.put(engine, part -> check(part, engine));
        }
        parts.put("interrupt", AutoPurgeChecks::interrupted);
        suite.concurrently(parts);
    }

    /**
     * The server stops while auto-purge removes rows, on SQLite: the purge
     * stops without holding up the shutdown and says why, the database keeps
     * what it hadn't removed yet, and on the next boot a purge removes the
     * rest.
     */
    private static void interrupted(Harness.Suite suite) throws Exception {
        Harness.Server server = suite.newServer("interrupt");
        server.timeout(Duration.ofMinutes(8));
        server.coreProtectConfig("auto-purge: 30d\nauto-purge-time: 3:30\ncheck-updates: false\n"
            + (suite.generation() >= 25 ? "database-type: sqlite\n" : "use-mysql: false\n"));

        Harness.Run stopped = server.boot(Harness.Variant.FORK, Harness.Scenario.steps("auto-purge.interrupt")
            .set("timeout.ticks", 8_400));
        String name = "stopping during a purge";
        long seeded = number(stopped, "auto-purge.interrupt.seeded");
        long remaining = number(stopped, "auto-purge.interrupt.remaining");
        suite.note(name + ": " + remaining + " of " + seeded + " old rows left as the server began to stop");
        checkRun(suite, stopped, "auto-purge.interrupt", name);
        suite.check("true".equals(stopped.result("auto-purge.interrupt.running")) && remaining > 0
            && remaining < seeded, name + ": the purge was removing rows when the server began to stop");
        suite.check(stopped.console().contains("[LibreProtect] Auto-purge stopped because the server is shutting down,"
            + " after removing "), name + ": the purge stops and says why");
        suite.check(!stopped.console().contains("Auto-purge didn't stop within"),
            name + ": the purge stops without holding up the shutdown");

        // Purging all the rows that are left takes a while, with the pauses that keep the server usable
        Harness.Run next = server.boot(Harness.Variant.FORK, Harness.Scenario.steps("auto-purge.resume")
            .set("timeout.ticks", 8_400));
        name = "boot after stopping during a purge";
        long before = number(next, "auto-purge.resume.before");
        suite.note(name + ": " + before + " old rows left, " + next.result("auto-purge.resume.removed") + " removed");
        checkRun(suite, next, "auto-purge.resume", name);
        suite.check(before > 0 && before <= remaining,
            name + ": the database keeps the rows that the stopped purge hadn't removed");
        suite.check(number(next, "auto-purge.resume.after") == 0 && number(next, "auto-purge.resume.removed") >= before,
            name + ": the next purge removes the rest");
        suite.check("1".equals(next.result("auto-purge.resume.newer")), name + ": the row of now remains");
    }

    /**
     * What every boot of {@link #interrupted} must do: run its step and stop
     * cleanly, without stack traces or network requests.
     */
    private static void checkRun(Harness.Suite suite, Harness.Run run, String step, String name) {
        String error = run.result(step + ".error");
        suite.check(error == null, name + ": the scenario ran without errors" + (error == null ? "" : ": " + error));
        suite.check(!run.console().contains("\tat net.deltik.mc.libreprotect.") && !run.console().contains("\tat net.coreprotect."),
            name + ": no stack traces from CoreProtect or LibreProtect");
        suite.check(run.pluginEgress().isEmpty(), name + ": no plugin network requests");
        suite.check(run.exitCode() == 0, name + ": the server stopped cleanly (exit code " + run.exitCode() + ")");
    }

    private static void check(Harness.Suite suite, String engine) throws Exception {
        boolean generation25 = suite.generation() >= 25;
        // Update checks are requests of their own, which UpdateChecks covers
        StringBuilder config = new StringBuilder("auto-purge: 30d\nauto-purge-time: 3:30\ncheck-updates: false\n");
        Harness.Database database = null;
        switch (engine) {
            case "sqlite" -> config.append(generation25 ? "database-type: sqlite\n" : "use-mysql: false\n");
            case "duckdb" -> config.append("database-type: duckdb\n");
            case "mysql" -> {
                database = suite.containers().mysql();
                dropTables(database, PREFIX);
                config.append(database.coreProtectConfig()).append("table-prefix: ").append(PREFIX).append('\n')
                    .append(generation25 ? "database-type: mysql\n" : "use-mysql: true\n");
            }
            case "clickhouse" -> {
                database = suite.containers().clickhouse();
                dropTables(database, PREFIX);
                config.append(database.coreProtectConfig()).append("table-prefix: ").append(PREFIX).append('\n')
                    .append("database-type: clickhouse\n");
            }
            default -> throw new IllegalArgumentException(engine);
        }
        Harness.Server server = suite.newServer(engine);
        server.coreProtectConfig(config.toString());
        // ClickHouse cleans up entity rows with CoreProtect's own retention
        boolean orphans = generation25 && !engine.equals("clickhouse");

        Harness.Run run;
        try {
            run = server.boot(Harness.Variant.FORK, Harness.Scenario.steps("auto-purge")
                .set("auto-purge.orphans", orphans));
        } finally {
            if (database != null) {
                dropTables(database, PREFIX);
            }
        }

        String on = " on " + engine;
        if (run.console().contains("Failed to initialize ClickHouse")) {
            // Nothing below can pass; one failure says why instead of a dozen that don't
            suite.check(false, "CoreProtect initialized the database" + on + "; it didn't, see " + run.consoleLog());
            return;
        }
        String error = run.result("auto-purge.error");
        suite.check(error == null, "the scenario ran without errors" + on + (error == null ? "" : ": " + error));
        suite.check(NEXT_RUN.matcher(run.console()).find(), "the startup log shows the next run" + on);
        long timeA = number(run, "auto-purge.time.a");
        long timeB = number(run, "auto-purge.time.b");
        long timeC = number(run, "auto-purge.time.c");
        suite.note(engine + ": A at " + timeA + ", B at " + timeB + ", C at " + timeC + ", cutoff "
            + run.result("auto-purge.cutoff") + ", removed " + run.result("auto-purge.removed"));
        suite.check(timeA > 0 && timeB > timeA && timeC >= timeB, "B was stored after A, and C after B" + on);
        suite.check("0".equals(run.result("auto-purge.rows.a")), "row A, before the cutoff, is gone" + on);
        suite.check("1".equals(run.result("auto-purge.rows.b")), "row B, at the cutoff and not its table's newest, remains" + on);
        suite.check("1".equals(run.result("auto-purge.rows.c")), "row C, after the cutoff, remains" + on);
        if (orphans) {
            suite.check("0".equals(run.result("auto-purge.orphan.rows")),
                "the orphan cleanup removed an old entity_spawn row nothing refers to" + on);
            suite.check("null".equals(run.result("auto-purge.linked.block")),
                "the orphan cleanup cleared a link to row A (" + run.result("auto-purge.linked.block") + ")" + on);
        }

        long removed = number(run, "auto-purge.removed");
        suite.check(removed >= (orphans ? 2 : 1), "runNow reports the rows it removed (" + removed + ")" + on);
        String counted = String.format(Locale.ROOT, "Cleanup: %,d %s auto purged since restart.", removed, removed == 1 ? "row" : "rows");
        suite.check(run.section("co status").contains(counted), "/co status shows '" + counted + "'" + on);
        suite.check(run.console().contains("[LibreProtect] Auto-purge removed " + String.format(Locale.ROOT, "%,d", removed)
            + (removed == 1 ? " row in " : " rows in ")), "the console reports the purge" + on);
        suite.check(!run.console().contains("Auto-purge stopped") && !run.console().contains("Auto-purge couldn't"),
            "the purge finished without stopping or failing" + on);
        suite.check(!run.console().contains("\tat net.deltik.mc.libreprotect.") && !run.console().contains("\tat net.coreprotect."),
            "no stack traces from CoreProtect or LibreProtect" + on);
        suite.check(run.pluginEgress().isEmpty(), "no plugin network requests" + on);
        suite.check(run.exitCode() == 0, "the server stopped cleanly (exit code " + run.exitCode() + ")" + on);
    }

    private static long number(Harness.Run run, String key) {
        try {
            return Long.parseLong(run.result(key));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * Drop the tables of earlier runs whose harness no longer runs, such as
     * one that was killed before it could drop them. A harness that runs now
     * on this machine, from this checkout or another one, keeps its tables.
     * So does one whose process ID an unrelated process has taken since; a
     * later run drops them. A harness in another PID namespace, such as a
     * container, that shares the database containers would take the runs
     * outside it for gone, and drop their tables.
     */
    private static void dropLeftovers(Harness.Database database) throws Exception {
        Set<String> prefixes = new TreeSet<>();
        for (String table : tables(database, "lpap")) {
            Matcher prefixed = PREFIXED.matcher(table);
            if (prefixed.matches() && ProcessHandle.of(Long.parseLong(prefixed.group(1))).isEmpty()) {
                prefixes.add("lpap" + prefixed.group(1) + "_");
            }
        }
        for (String prefix : prefixes) {
            dropTables(database, prefix);
        }
    }

    /**
     * Drop the tables under a prefix: this suite's own before a server uses
     * them, in case an earlier run of the same process ID left them behind,
     * and after it, since the containers can outlive a test run
     */
    private static void dropTables(Harness.Database database, String prefix) throws Exception {
        boolean clickhouse = database.kind().equals("clickhouse");
        for (String table : tables(database, prefix)) {
            database.query("DROP TABLE IF EXISTS " + (clickhouse ? database.database() + "." : "") + "`" + table + "`"
                + (clickhouse ? " SYNC" : ""));
        }
    }

    /** The database's tables whose names start with the prefix */
    private static List<String> tables(Harness.Database database, String prefix) throws Exception {
        String listing = database.kind().equals("clickhouse")
            ? "SELECT name FROM system.tables WHERE database = '" + database.database() + "' AND startsWith(name, '" + prefix + "')"
            : "SELECT table_name FROM information_schema.tables WHERE table_schema = '" + database.database()
                + "' AND table_name LIKE '" + prefix.replace("_", "\\_") + "%'";
        List<String> tables = new ArrayList<>();
        for (String table : database.query(listing).split("\n")) {
            if (!table.isBlank()) {
                tables.add(table.trim());
            }
        }
        return tables;
    }
}
