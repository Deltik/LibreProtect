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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * What LibreProtect's extensions do with CoreProtect on a real server,
 * compared with what the build found. The build probes the upstream JAR with
 * the server API and the drivers of its test class path, and bundles the
 * outcome as {@code META-INF/libreprotect/capabilities.tsv}. The server probes
 * the same classes with its own API and the libraries it downloaded for
 * plugin.yml, such as DuckDB's driver. The reports must be the same, but for
 * the bundled one's {@code upstream} line, which names the JAR the build
 * probed. The test plugin's side is {@code CapabilityScenario}.
 */
final class CapabilityChecks {

    static final String ENTRY = "META-INF/libreprotect/capabilities.tsv";

    private CapabilityChecks() {
    }

    static void run(Harness.Suite suite) throws Exception {
        List<String> bundled = bundled(suite.jar(Harness.Variant.FORK));
        suite.check(!bundled.isEmpty(), "the JAR bundles the capability report of its build");

        Harness.Server server = suite.newServer("server");
        // Update checks are requests of their own, which UpdateChecks covers. Auto-purge warns for itself when
        // it's on and won't work, so it's on, with its run hours away
        server.coreProtectConfig("check-updates: false\nauto-purge: 30d\nauto-purge-time: 3:30\n");
        Harness.Run run = server.boot(Harness.Variant.FORK, Harness.Scenario.steps("capability"));
        String error = run.result("capability.error");
        suite.check(error == null, "the scenario ran without errors" + (error == null ? "" : ": " + error));
        Path file = server.dir().resolve("plugins/LibreProtectIT/capabilities.tsv");
        List<String> live = Files.exists(file) ? Files.readAllLines(file, StandardCharsets.UTF_8) : List.of();
        suite.note("capability report: " + bundled.size() + " lines in the JAR, " + live.size() + " on the server");

        List<String> onlyBundled = missingFrom(bundled, live);
        List<String> onlyLive = missingFrom(live, bundled);
        suite.check(!live.isEmpty() && live.equals(bundled), "the server's capabilities are those the build found"
            + (onlyBundled.isEmpty() ? "" : "; only in the JAR: " + readable(onlyBundled))
            + (onlyLive.isEmpty() ? "" : "; only on the server: " + readable(onlyLive))
            + (!live.isEmpty() && onlyBundled.isEmpty() && onlyLive.isEmpty() && !live.equals(bundled)
                ? "; the same lines in another order" : ""));
        String console = run.console();
        if (suite.generation() >= 25) {
            // Migrations from and to ClickHouse aren't available yet, which CoreProtect 25 warns about
            for (String direction : new String[]{"from", "to"}) {
                console = console.replace("/co migrate-db " + direction + " ClickHouse won't work with this CoreProtect"
                    + " build", "");
            }
        }
        suite.check(!console.contains("won't work with this CoreProtect build"),
            "the server warns about no feature that won't work");
        suite.check(run.console().contains("[LibreProtect] Auto-purge keeps 30 days of data. Next run: "),
            "auto-purge is on, and announces its next run");
        suite.check(run.exitCode() == 0, "the server stopped cleanly (exit code " + run.exitCode() + ")");
    }

    /**
     * @return the lines of the JAR's capability report after its
     *         {@code upstream} line, or none if it has no report
     */
    private static List<String> bundled(Path jar) throws IOException {
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            ZipEntry entry = zip.getEntry(ENTRY);
            if (entry == null) {
                return List.of();
            }
            try (InputStream in = zip.getInputStream(entry)) {
                List<String> lines = new String(in.readAllBytes(), StandardCharsets.UTF_8).lines().toList();
                return lines.isEmpty() || !lines.get(0).startsWith("upstream\t") ? lines : lines.subList(1, lines.size());
            }
        }
    }

    private static List<String> missingFrom(List<String> lines, List<String> other) {
        List<String> missing = new ArrayList<>(lines);
        missing.removeAll(other);
        return missing;
    }

    private static String readable(List<String> lines) {
        return String.join(" / ", lines.stream().map(line -> line.replace('\t', ' ')).toList());
    }
}
