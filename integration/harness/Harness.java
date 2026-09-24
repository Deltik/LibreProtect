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
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * LibreProtect's integration test: boots a real Paper server three times on
 * the same data directory.
 *
 * <ol>
 *   <li><b>Stock CoreProtect (positive control).</b> CoreProtect's own network
 *       requests must show up in the egress log. If they don't, the harness
 *       can't see network traffic, and a clean LibreProtect result would
 *       mean nothing.</li>
 *   <li><b>LibreProtect.</b> Must make no network requests, read the data
 *       stock CoreProtect wrote (drop-in replacement), work through the
 *       public API and commands, and show its branding.</li>
 *   <li><b>Stock CoreProtect again.</b> Must read everything, including what
 *       LibreProtect wrote (switching back works), and find no license file
 *       planted by LibreProtect.</li>
 * </ol>
 *
 * <p>Every server runs with LibreProtect's egress agent in deny mode, so no
 * run can reach the network, whatever the plugin under test does.
 *
 * <p>Usage: {@code java Harness.java --work DIR --paper-lock FILE --agent JAR
 * --it-plugin JAR --upstream JAR --fork JAR}
 *
 * <p>Running this accepts the Minecraft EULA (https://aka.ms/MinecraftEULA)
 * on behalf of whoever runs it.
 */
public final class Harness {

    private static final Duration SERVER_TIMEOUT = Duration.ofMinutes(5);
    private static final String CORE_PROTECT_CONFIG = """
        # Seeded by LibreProtect's integration test. The donation key makes
        # CoreProtect contact its license server, one of the requests the
        # positive control must see.
        donation-key: LPITKEY1
        check-updates: true
        """;

    private final Map<String, Path> arguments;
    private final List<String> failures = new ArrayList<>();
    private final List<String> passes = new ArrayList<>();

    private Harness(Map<String, Path> arguments) {
        this.arguments = arguments;
    }

    public static void main(String[] args) throws Exception {
        Map<String, Path> arguments = new LinkedHashMap<>();
        for (int i = 0; i + 1 < args.length; i += 2) {
            arguments.put(args[i].replaceFirst("^--", ""), Path.of(args[i + 1]).toAbsolutePath());
        }
        for (String required : List.of("work", "paper-lock", "agent", "it-plugin", "upstream", "fork")) {
            if (!arguments.containsKey(required)) {
                throw new IllegalArgumentException("Missing --" + required);
            }
        }
        System.exit(new Harness(arguments).run());
    }

    private int run() throws Exception {
        Path paper = preparePaper();
        prefetchLibraries(paper);
        Path server = newServer(paper, "server", 0);
        Files.createDirectories(server.resolve("plugins/CoreProtect"));
        Files.writeString(server.resolve("plugins/CoreProtect/config.yml"), CORE_PROTECT_CONFIG);
        Files.copy(arguments.get("it-plugin"), server.resolve("plugins/LibreProtectIT.jar"));

        Run control = boot(server, 1, "upstream");
        checkControl(control);
        Run fork = boot(server, 2, "fork");
        checkFork(fork, control);
        Run back = boot(server, 3, "upstream");
        checkSwitchBack(back, fork);

        System.out.println();
        passes.forEach(pass -> System.out.println("PASS " + pass));
        failures.forEach(failure -> System.out.println("FAIL " + failure));
        System.out.println(failures.isEmpty() ? "Integration test passed" : failures.size() + " integration check(s) failed");
        return failures.isEmpty() ? 0 : 1;
    }

    /** One server boot and what it left behind */
    private record Run(int number, String variant, int exitCode, Properties results, List<String[]> egress,
                       String console) {

        List<String[]> pluginEgress() {
            return egress.stream().filter(line -> line.length > 2 && line[2].equals("plugin")).toList();
        }

        int integer(String key) {
            try {
                return Integer.parseInt(results.getProperty(key, "-1"));
            } catch (NumberFormatException e) {
                return -1;
            }
        }
    }

    private Run boot(Path server, int number, String variant) throws Exception {
        try (Stream<Path> jars = Files.list(server.resolve("plugins"))) {
            for (Path jar : (Iterable<Path>) jars.filter(path -> path.getFileName().toString().startsWith("CoreProtect-"))::iterator) {
                Files.delete(jar);
            }
        }
        Files.copy(arguments.get(variant), server.resolve("plugins/CoreProtect-" + variant + ".jar"));
        Path results = server.resolve("plugins/LibreProtectIT/results.properties");
        Files.deleteIfExists(results);
        Path egress = server.resolve("egress-" + number + ".log");
        Path console = server.resolve("console-" + number + ".log");

        String java = ProcessHandle.current().info().command().orElse("java");
        List<String> command = List.of(java, "-Xms512M", "-Xmx2G",
            "-javaagent:" + arguments.get("agent") + "=log=" + egress + ",mode=deny",
            "-jar", "paper.jar", "--nogui");
        System.out.println("==> Run " + number + ": " + variant + " (" + String.join(" ", command) + ")");
        Process process = new ProcessBuilder(command).directory(server.toFile())
            .redirectErrorStream(true).redirectOutput(console.toFile()).redirectInput(ProcessBuilder.Redirect.PIPE)
            .start();
        process.getOutputStream().close();
        boolean exited = process.waitFor(SERVER_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
        if (!exited) {
            process.destroyForcibly().waitFor();
            failures.add("run " + number + " (" + variant + ") did not finish within " + SERVER_TIMEOUT
                + "; see " + console);
        }

        Properties properties = new Properties();
        if (Files.exists(results)) {
            try (InputStream in = Files.newInputStream(results)) {
                properties.load(in);
            }
        } else {
            failures.add("run " + number + " (" + variant + ") wrote no results; see " + console);
        }
        List<String[]> egressLines = Files.exists(egress)
            ? Files.readAllLines(egress).stream().map(line -> line.split("\t")).toList()
            : List.of();
        return new Run(number, variant, exited ? process.exitValue() : -1, properties, egressLines,
            Files.readString(console, StandardCharsets.UTF_8));
    }

    private void checkCommon(Run run) {
        String name = "run " + run.number() + " (" + run.variant() + ")";
        check(run.results().getProperty("coreprotect.enabled", "").equals("true"), name + ": CoreProtect enabled");
        check(run.results().getProperty("api.enabled", "").equals("true"), name + ": API enabled");
        check(run.integer("api.version") >= 10, name + ": API version " + run.results().getProperty("api.version"));
        check(run.results().getProperty("api.logPlacement", "").equals("true"), name + ": API logged a placement");
        check(run.integer("lookup.after") == run.integer("lookup.before") + 1,
            name + ": API lookup sees the new placement (" + run.integer("lookup.before") + " -> "
                + run.integer("lookup.after") + ")");
        check(run.exitCode() == 0, name + ": server exited cleanly (exit code " + run.exitCode() + ")");
    }

    private void checkControl(Run run) {
        checkCommon(run);
        List<String> targets = run.pluginEgress().stream().map(line -> line[1]).distinct().toList();
        System.out.println("    positive control saw CoreProtect contact: " + targets);
        check(targets.stream().anyMatch(target -> target.startsWith("update.coreprotect.net")),
            "positive control: harness sees stock CoreProtect's update check");
        check(targets.stream().anyMatch(target -> target.equals("coreprotect.net") || target.startsWith("coreprotect.net:")),
            "positive control: harness sees stock CoreProtect's license check");
        if (run.results().getProperty("errorReporter.queued", "").equals("true")) {
            check(targets.stream().anyMatch(target -> target.startsWith("error-reporting.coreprotect.net")),
                "positive control: harness sees stock CoreProtect's error report");
        }
        check(run.integer("lookup.before") == 0, "run 1: starts from an empty database");
    }

    private void checkFork(Run run, Run control) throws IOException {
        checkCommon(run);
        List<String[]> egress = run.pluginEgress();
        check(egress.isEmpty(), "LibreProtect made no network requests"
            + (egress.isEmpty() ? "" : ": " + egress.stream().map(line -> line[0] + " " + line[1] + " from " + line[3]
            + " via " + (line.length > 4 ? line[4].split("\\|")[0] : "?")).toList()));
        check(run.results().getProperty("coreprotect.class", "").equals("net.deltik.mc.libreprotect.LibreProtectPlugin"),
            "LibreProtect's generated main class is loaded (" + run.results().getProperty("coreprotect.class") + ")");
        check(run.results().getProperty("coreprotect.class.super", "").equals("net.coreprotect.CoreProtect"),
            "API consumers still get a net.coreprotect.CoreProtect");
        check(run.results().getProperty("coreprotect.version", "").contains("-libre"),
            "plugin version marks LibreProtect (" + run.results().getProperty("coreprotect.version") + ")");
        String ownVersion = run.results().getProperty("coreprotect.ownVersion");
        String stockVersion = control.results().getProperty("coreprotect.ownVersion");
        check(stockVersion != null && stockVersion.equals(ownVersion),
            "CoreProtect compares its own version, " + ownVersion + ", as stock CoreProtect of the same commit does ("
                + stockVersion + "), rather than LibreProtect's version"
                + (run.results().getProperty("coreprotect.ownVersion.error") == null ? ""
                : " (error " + run.results().getProperty("coreprotect.ownVersion.error") + ")"));
        check(run.integer("lookup.before") >= control.integer("lookup.after"),
            "LibreProtect reads the data stock CoreProtect wrote");

        // Command output is asynchronous, so check the whole console rather than between the markers
        String console = run.console().replaceAll("\u001B\\[[0-9;]*m", "");
        String version = run.results().getProperty("coreprotect.version", "?");
        check(console.contains("[LibreProtect] LibreProtect has been successfully enabled!")
                && console.contains("[LibreProtect] LibreProtect is a privacy-hardened build of CoreProtect by Intelli."),
            "startup messages name LibreProtect and credit CoreProtect");
        check(console.contains("[LibreProtect] Network policy: preset privacy-first"), "privacy-first policy is active");
        check(!console.contains("Community Edition"), "no Community Edition label");
        check(console.contains("----- LibreProtect -----") && console.contains("Version: LibreProtect v" + version + "."),
            "/co status names LibreProtect and its version");
        check(!console.contains("License:") && !console.contains("donation key"),
            "no donation-key messages, although config.yml has a donation key");
        check(!console.contains("Discord:") && !console.contains("Patreon:") && !console.contains("Enjoy CoreProtect")
                && console.contains("Website: github.com/Deltik/LibreProtect"),
            "links point to LibreProtect instead of CoreProtect's Discord and Patreon");
        check(console.contains("----- LibreProtect Help -----") && console.contains("LibreProtect - Command \"/co lpit-unknown\""),
            "/co help and error messages use LibreProtect's header and chat prefix");
        check(!console.contains("\uFDD0"), "no internal markers leak into messages");
        check(console.contains("LibreProtect - Database migration is not available in LibreProtect"),
            "/co migrate-db reaches LibreProtect's extension");
        check(!console.contains("\tat net.coreprotect.") && !console.contains("\tat net.deltik.mc.libreprotect."),
            "no stack traces from CoreProtect or LibreProtect");

        Path dataFolder = arguments.get("work").resolve("server/plugins/CoreProtect");
        check(Files.isRegularFile(dataFolder.resolve("libreprotect.yml")), "default libreprotect.yml was written");
        checkNoLicense(dataFolder, "LibreProtect");
    }

    private void checkSwitchBack(Run run, Run fork) throws IOException {
        checkCommon(run);
        check(run.integer("lookup.before") >= fork.integer("lookup.after"),
            "stock CoreProtect reads the data LibreProtect wrote");
        checkNoLicense(arguments.get("work").resolve("server/plugins/CoreProtect"), "switching back");
    }

    private void checkNoLicense(Path dataFolder, String when) throws IOException {
        Path license = dataFolder.resolve(".license");
        boolean clean = !Files.exists(license) || Files.readString(license).isBlank();
        check(clean, when + ": no license key was written to " + license);
    }

    private void check(boolean condition, String description) {
        (condition ? passes : failures).add(description);
    }

    /**
     * Create an empty server directory that shares Paper's downloads.
     */
    private Path newServer(Path paper, String name, int portOffset) throws IOException {
        Path server = arguments.get("work").resolve(name);
        deleteRecursively(server);
        Files.createDirectories(server.resolve("plugins"));
        for (String shared : List.of("cache", "libraries", "versions")) {
            Path source = paper.getParent().resolve(shared);
            Files.createDirectories(source);
            Files.createSymbolicLink(server.resolve(shared), source);
        }
        Files.copy(paper, server.resolve("paper.jar"));
        Files.writeString(server.resolve("eula.txt"), "eula=true\n");
        int port = 30000 + (int) (ProcessHandle.current().pid() % 20000) + portOffset;
        Files.writeString(server.resolve("server.properties"), String.join("\n",
            "online-mode=false", "level-type=minecraft\\:flat", "generate-structures=false", "spawn-protection=0",
            "view-distance=2", "simulation-distance=2", "server-port=" + port,
            "enable-rcon=false", "enable-query=false", ""));
        return server;
    }

    /**
     * CoreProtect can declare {@code libraries} in plugin.yml (DuckDB, on
     * upstream's master branch after v24.1), which the server downloads from Maven Central when it
     * loads the plugin. The tested runs block all network access, so fetch
     * them beforehand: boot the server once, with network access, and a
     * stand-in plugin that declares the same libraries and has no code.
     * No CoreProtect code runs while the network is reachable.
     */
    private void prefetchLibraries(Path paper) throws Exception {
        List<String> libraries = new ArrayList<>();
        for (String variant : List.of("upstream", "fork")) {
            for (String library : pluginLibraries(arguments.get(variant))) {
                if (!libraries.contains(library)) {
                    libraries.add(library);
                }
            }
        }
        if (libraries.isEmpty()) {
            return;
        }
        List<String> sorted = libraries.stream().sorted().toList();
        String key = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
            .digest(String.join("\n", sorted).getBytes(StandardCharsets.UTF_8))).substring(0, 16);
        Path marker = paper.getParent().resolve(".libraries-" + key);
        if (Files.exists(marker)) {
            return;
        }

        System.out.println("==> Prefetching plugin libraries " + sorted);
        Path server = newServer(paper, "prefetch", 1);
        StringBuilder pluginYml = new StringBuilder("name: LibraryPrefetch\nmain: net.deltik.mc.lpit.Absent\nversion: \"1\"\n"
            + "api-version: \"1.16\"\nlibraries:\n");
        sorted.forEach(library -> pluginYml.append("  - \"").append(library).append("\"\n"));
        try (java.util.zip.ZipOutputStream zip = new java.util.zip.ZipOutputStream(
                Files.newOutputStream(server.resolve("plugins/LibraryPrefetch.jar")))) {
            zip.putNextEntry(new java.util.zip.ZipEntry("plugin.yml"));
            zip.write(pluginYml.toString().getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }

        String java = ProcessHandle.current().info().command().orElse("java");
        Path console = server.resolve("console.log");
        Process process = new ProcessBuilder(java, "-Xmx1G", "-jar", "paper.jar", "--nogui")
            .directory(server.toFile()).redirectErrorStream(true).redirectOutput(console.toFile()).start();
        process.getOutputStream().close();
        // Libraries are resolved while plugins load, before the server reports that it's done.
        // Then stop it with SIGTERM: Paper 26.2 fails to run "stop" typed into a piped console.
        long deadline = System.nanoTime() + SERVER_TIMEOUT.toNanos();
        while (process.isAlive() && System.nanoTime() < deadline
            && !Files.readString(console, StandardCharsets.UTF_8).contains("Done (")) {
            Thread.sleep(500);
        }
        process.destroy();
        if (!process.waitFor(1, TimeUnit.MINUTES)) {
            process.destroyForcibly().waitFor();
        }

        for (String library : sorted) {
            String[] parts = library.split(":");
            Path jar = paper.getParent().resolve("libraries").resolve(parts[0].replace('.', '/'))
                .resolve(parts[1]).resolve(parts[parts.length - 1])
                .resolve(parts[1] + "-" + parts[parts.length - 1] + ".jar");
            if (!Files.exists(jar)) {
                throw new IOException("Library " + library + " was not downloaded to " + jar
                    + "; see " + server.resolve("console.log"));
            }
        }
        Files.writeString(marker, String.join("\n", sorted) + "\n");
    }

    /**
     * @return the top-level {@code libraries} list from a plugin JAR's plugin.yml
     */
    private static List<String> pluginLibraries(Path jar) throws IOException {
        List<String> libraries = new ArrayList<>();
        try (java.util.zip.ZipFile zip = new java.util.zip.ZipFile(jar.toFile())) {
            java.util.zip.ZipEntry entry = zip.getEntry("plugin.yml");
            if (entry == null) {
                return libraries;
            }
            boolean inLibraries = false;
            for (String line : new String(zip.getInputStream(entry).readAllBytes(), StandardCharsets.UTF_8).split("\\R")) {
                if (!line.isEmpty() && !Character.isWhitespace(line.charAt(0))) {
                    inLibraries = line.startsWith("libraries:");
                } else if (inLibraries && line.trim().startsWith("-")) {
                    libraries.add(line.trim().substring(1).trim().replaceAll("^[\"']|[\"']$", ""));
                }
            }
        }
        return libraries;
    }

    /**
     * Download and verify the pinned Paper build, then let Paperclip fetch
     * and patch the Minecraft server once, while network access is allowed.
     */
    private Path preparePaper() throws Exception {
        Properties lock = new Properties();
        try (InputStream in = Files.newInputStream(arguments.get("paper-lock"))) {
            lock.load(in);
        }
        String version = lock.getProperty("PAPER_VERSION");
        String build = lock.getProperty("PAPER_BUILD");
        Path directory = arguments.get("work").resolve("paper-" + version + "-" + build);
        Path jar = directory.resolve("paper.jar");
        Path prepared = directory.resolve(".prepared");
        if (Files.exists(prepared)) {
            return jar;
        }

        Files.createDirectories(directory);
        System.out.println("==> Downloading Paper " + version + " build " + build);
        HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();
        Path download = directory.resolve("paper.jar.part");
        HttpResponse<Path> response = client.send(HttpRequest.newBuilder(URI.create(lock.getProperty("PAPER_URL"))).build(),
            HttpResponse.BodyHandlers.ofFile(download));
        if (response.statusCode() != 200) {
            throw new IOException("Paper download failed: HTTP " + response.statusCode());
        }
        String sha256 = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(download)));
        if (!sha256.equals(lock.getProperty("PAPER_SHA256"))) {
            throw new IOException("Paper SHA-256 mismatch: expected " + lock.getProperty("PAPER_SHA256") + ", got " + sha256);
        }
        Files.move(download, jar, StandardCopyOption.REPLACE_EXISTING);

        System.out.println("==> Patching Paper (downloads the Minecraft server from Mojang)");
        String java = ProcessHandle.current().info().command().orElse("java");
        Process process = new ProcessBuilder(java, "-Dpaperclip.patchonly=true", "-jar", "paper.jar")
            .directory(directory.toFile()).inheritIO().start();
        if (process.waitFor() != 0) {
            throw new IOException("Paperclip failed with exit code " + process.exitValue());
        }
        Files.writeString(prepared, sha256 + "\n");
        return jar;
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (!Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        if (Files.isDirectory(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            try (Stream<Path> children = Files.list(path)) {
                for (Path child : (Iterable<Path>) children::iterator) {
                    deleteRecursively(child);
                }
            }
        }
        Files.delete(path);
    }
}
