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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;
import java.util.zip.ZipFile;

/**
 * Update checks against a stub update API on loopback. The test plugin's side
 * is {@code UpdateScenario}.
 *
 * <p>The stub answers like GitHub for a repository that doesn't exist (404),
 * and like Modrinth for a project that lists a newer release. One server
 * boots LibreProtect three times with {@code update-sources} pointing at
 * both, GitHub first:
 * <ol>
 *   <li>{@code allow-updates}, {@code check-updates: true}: LibreProtect asks
 *       GitHub, then Modrinth, sending only its name. CoreProtect announces
 *       the release in LibreProtect's words and links to its Modrinth page,
 *       and {@code /co status} shows it as the latest version. After
 *       {@code /co reload} turns {@code check-updates} off, update checks
 *       fail without asking anyone.</li>
 *   <li>{@code privacy-first}: CoreProtect's update check is blocked, and the
 *       stub hears nothing.</li>
 *   <li>{@code allow-updates}, {@code check-updates: false}: CoreProtect
 *       doesn't check, and the stub hears nothing.</li>
 * </ol>
 * No run may send anything beyond loopback.
 */
final class UpdateChecks {

    private static final String USER_AGENT = "LibreProtect (+https://github.com/Deltik/LibreProtect)";
    /** Headers that Java's HTTP client and LibreProtect send, none of them about the server */
    private static final Set<String> ALLOWED_HEADERS =
        Set.of("host", "user-agent", "accept", "connection", "x-github-api-version");
    private static final String GITHUB_PATH = "/repos/Deltik/Missing/releases/latest";
    private static final String MODRINTH_PATH = "/v2/project/libreprotect/version?include_changelog=false";

    private UpdateChecks() {
    }

    static void run(Harness.Suite suite) throws Exception {
        Properties build = buildProperties(suite.jar(Harness.Variant.FORK));
        String forkVersion = build.getProperty("fork.version");
        // What CoreProtect compares as its own version, and so what the update check answers relative to
        String upstream = build.getProperty("upstream.version").split("-")[0];
        boolean dev = forkVersion.endsWith("-libre-dev");
        // Development builds are only offered releases newer than both the tag they're named after and
        // what their CoreProtect declares, which can be newer than the tag
        String offered = dev ? nextMinor(newer(upstream, forkVersion.split("-")[0])) : upstream;
        String release = offered + "-libre" + (dev ? 1 : 99);
        String synthetic = dev ? offered : raised(upstream);
        suite.note("LibreProtect " + forkVersion + "; the stub offers " + release
            + ", which CoreProtect should be told as " + synthetic);

        try (Stub stub = new Stub(release)) {
            Harness.Server server = suite.newServer("server");

            server.libreProtectConfig(libreProtectConfig("allow-updates", stub));
            server.coreProtectConfig("check-updates: true\n");
            Harness.Run announced = server.boot(Harness.Variant.FORK,
                Harness.Scenario.steps("update.check", "update.reload"));
            checkAnnounced(suite, announced, stub, release, synthetic);
            checkReloadedOff(suite, announced, stub, synthetic);

            int before = stub.requests().size();
            server.libreProtectConfig(libreProtectConfig("privacy-first", stub));
            server.coreProtectConfig("check-updates: true\n");
            Harness.Run blocked = server.boot(Harness.Variant.FORK, Harness.Scenario.steps("update.idle"));
            checkQuiet(suite, blocked, "privacy-first");
            suite.check(stub.requests().size() == before, "privacy-first: the update sources heard nothing");
            suite.check(blocked.console().lines().anyMatch(line -> line.contains("Blocked by LibreProtect")
                    && line.contains("http://update.coreprotect.net/version/")),
                "privacy-first: CoreProtect's update check was made and blocked");

            before = stub.requests().size();
            server.libreProtectConfig(libreProtectConfig("allow-updates", stub));
            server.coreProtectConfig("check-updates: false\n");
            Harness.Run off = server.boot(Harness.Variant.FORK, Harness.Scenario.steps("update.idle"));
            checkQuiet(suite, off, "check-updates: false");
            suite.check(stub.requests().size() == before, "check-updates: false: the update sources heard nothing");
            suite.check(!off.console().contains("update.coreprotect.net"),
                "check-updates: false: CoreProtect made no update check");
        }
    }

    private static void checkAnnounced(Harness.Suite suite, Harness.Run run, Stub stub, String release,
                                       String synthetic) {
        String console = run.console();
        suite.check(run.result("update.check.error") == null && run.result("update.check.timeout") == null,
            "CoreProtect's update check found a newer version (error " + run.result("update.check.error")
                + ", timeout " + run.result("update.check.timeout") + ")");
        suite.check(synthetic.equals(run.result("update.latestVersion")),
            "CoreProtect was told " + synthetic + " (" + run.result("update.latestVersion") + ")");
        suite.check(console.contains("[LibreProtect] Network policy: preset allow-updates, 0 custom routes,"
                + " default action BLOCK, 2 update sources"),
            "the startup log counts the update sources");

        suite.check(console.contains("[LibreProtect] Version " + release + " is now available."),
            "the console announces LibreProtect " + release);
        suite.check(console.contains("[LibreProtect] Download: modrinth.com/plugin/libreprotect/version/" + release),
            "the console links to the release's Modrinth page");
        String status = run.section("co status");
        suite.check(status.contains("Version: LibreProtect v") && status.contains("(Latest Version: v" + release + ")"),
            "/co status shows " + release + " as the latest version");
        String shown = run.result("update.latestVersion");
        suite.check(shown != null && !console.contains(" " + shown + " is now available") && !console.contains("v" + shown + ")")
                && !console.contains("CoreProtect CE v") && !console.contains("coreprotect.net/download"),
            "neither the version CoreProtect was told nor CoreProtect's download page is shown");

        List<Stub.Request> requests = stub.requests();
        suite.note("the stub heard: " + requests);
        suite.check(requests.size() >= 2 && requests.get(0).target().equals(GITHUB_PATH)
                && requests.get(1).target().equals(MODRINTH_PATH),
            "LibreProtect asked the GitHub source, then after its 404 the Modrinth source");
        suite.check(requests.stream().allMatch(request -> request.method().equals("GET")
                && USER_AGENT.equals(request.headers().get("user-agent"))),
            "each request is a GET whose User-Agent names only LibreProtect");
        suite.check(requests.stream().allMatch(request -> ALLOWED_HEADERS.containsAll(request.headers().keySet())),
            "the requests carry no other headers");
        suite.check(console.contains("Update source GitHub repository Deltik/Missing: GET http://127.0.0.1:" + stub.port()
                + GITHUB_PATH + " -> failed: HTTP 404")
                && console.contains("Update source Modrinth project libreprotect: GET http://127.0.0.1:" + stub.port()
                + MODRINTH_PATH + " -> newest release " + release),
            "verbose logging shows each request and its outcome");
        checkQuiet(suite, run, "allow-updates");
    }

    /**
     * CoreProtect's hourly update check keeps running after {@code /co reload}
     * turns {@code check-updates} off, so LibreProtect must stop asking the
     * update sources on its own. The test plugin asks the way that check
     * does, before and after such a reload.
     */
    private static void checkReloadedOff(Harness.Suite suite, Harness.Run run, Stub stub, String synthetic) {
        suite.check(run.result("update.reload.error") == null && synthetic.equals(run.result("update.reload.on")),
            "an update check before turning check-updates off is answered (" + run.result("update.reload.on")
                + ", error " + run.result("update.reload.error") + ")");
        String off = run.result("update.reload.off");
        suite.check(off != null && off.startsWith("failed: ") && off.contains("check-updates is off"),
            "an update check after /co reload turned check-updates off fails as if offline (" + off + ")");
        List<String> targets = stub.requests().stream().map(Stub.Request::target).toList();
        suite.check(targets.equals(List.of(GITHUB_PATH, MODRINTH_PATH, GITHUB_PATH, MODRINTH_PATH)),
            "the update sources heard nothing once check-updates was off: " + targets);
    }

    /** What every run must do: exit cleanly and send nothing beyond loopback */
    private static void checkQuiet(Harness.Suite suite, Harness.Run run, String name) {
        suite.check(run.exitCode() == 0, name + ": the server exited cleanly (exit code " + run.exitCode() + ")");
        suite.check(run.pluginEgress().isEmpty(), name + ": no requests beyond loopback"
            + (run.pluginEgress().isEmpty() ? "" : ": " + run.pluginEgress()));
        if (!name.equals("allow-updates")) {
            suite.check("null".equals(run.result("update.latestVersion")),
                name + ": CoreProtect found no update (" + run.result("update.latestVersion") + ")");
        }
    }

    private static String libreProtectConfig(String preset, Stub stub) {
        return String.join("\n",
            "preset: " + preset,
            "verbose-logging: true",
            "update-sources:",
            "  - type: github",
            "    repository: Deltik/Missing",
            "    api: http://127.0.0.1:" + stub.port(),
            "  - type: modrinth",
            "    project: libreprotect",
            "    api: http://127.0.0.1:" + stub.port() + "/v2",
            "");
    }

    /** The build information in the fork's JAR */
    private static Properties buildProperties(Path jar) throws IOException {
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            Properties properties = new Properties();
            try (InputStream in = zip.getInputStream(zip.getEntry("libreprotect-build.properties"))) {
                properties.load(in);
            }
            return properties;
        }
    }

    /** The newer of two versions of two or three numbers, such as {@code 24.1} of {@code 24.0} and {@code 24.1} */
    private static String newer(String first, String second) {
        int[] a = Arrays.stream(first.split("\\.")).mapToInt(Integer::parseInt).toArray();
        int[] b = Arrays.stream(second.split("\\.")).mapToInt(Integer::parseInt).toArray();
        for (int i = 0; i < 3; i++) {
            int compared = Integer.compare(i < a.length ? a[i] : 0, i < b.length ? b[i] : 0);
            if (compared != 0) {
                return compared > 0 ? first : second;
            }
        }
        return first;
    }

    /** {@code 24.1} becomes {@code 24.2} */
    private static String nextMinor(String upstream) {
        String[] parts = upstream.split("\\.");
        return parts[0] + "." + (Integer.parseInt(parts[1]) + 1);
    }

    /** {@code 24.1} becomes {@code 24.1.1}, and {@code 24.1.1} becomes {@code 24.1.2} */
    private static String raised(String upstream) {
        String[] parts = upstream.split("\\.");
        return parts.length == 2 ? upstream + ".1" : parts[0] + "." + parts[1] + "." + (Integer.parseInt(parts[2]) + 1);
    }

    /**
     * A loopback server that answers like GitHub's and Modrinth's APIs, and
     * records what it is asked
     */
    private static final class Stub implements AutoCloseable {

        /** A request: its method, path and query, and headers with lowercase names */
        record Request(String method, String target, Map<String, String> headers) {
            @Override
            public String toString() {
                return method + " " + target + " " + headers;
            }
        }

        private final HttpServer server;
        private final List<Request> requests = new CopyOnWriteArrayList<>();
        private final String versions;

        Stub(String release) throws IOException {
            String[] parts = release.split("-libre");
            String beta = parts[0] + "-libre" + (Integer.parseInt(parts[1]) + 1);
            // Newest first, as Modrinth lists them, with fields LibreProtect skips
            versions = "[" + String.join(",",
                version(beta, "beta"),
                version(release, "release"),
                version("not-a-libreprotect-version", "release")) + "]";
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", this::handle);
            server.start();
        }

        private static String version(String number, String type) {
            return "{\"id\":\"LPIT" + Math.abs(number.hashCode()) + "\",\"project_id\":\"TGIIS09S\",\"name\":\"LibreProtect "
                + number + "\",\"version_number\":\"" + number + "\",\"version_type\":\"" + type + "\",\"status\":\"listed\","
                + "\"loaders\":[\"paper\",\"spigot\"],\"game_versions\":[\"1.21\"],\"featured\":false,"
                + "\"files\":[{\"url\":\"https://cdn.modrinth.com/data/TGIIS09S/LibreProtect-" + number + ".jar\","
                + "\"primary\":true,\"hashes\":{\"sha512\":\"0\"}}]}";
        }

        int port() {
            return server.getAddress().getPort();
        }

        List<Request> requests() {
            return List.copyOf(requests);
        }

        private void handle(HttpExchange exchange) throws IOException {
            Map<String, String> headers = new TreeMap<>();
            exchange.getRequestHeaders().forEach((name, values) ->
                headers.put(name.toLowerCase(Locale.ROOT), values.stream().collect(Collectors.joining(", "))));
            String target = exchange.getRequestURI().toString();
            requests.add(new Request(exchange.getRequestMethod(), target, headers));

            boolean modrinth = target.equals(MODRINTH_PATH);
            byte[] body = (modrinth ? versions : "{\"message\":\"Not Found\",\"status\":\"404\"}")
                .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(modrinth ? 200 : 404, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
