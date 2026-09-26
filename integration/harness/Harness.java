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
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.ServerSocket;
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
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * LibreProtect's integration test: boots real Paper servers with stock
 * CoreProtect or LibreProtect and checks what they do.
 *
 * <p>The drop-in suite boots one server three times on the same data
 * directory:
 * <ol>
 *   <li><b>Stock CoreProtect (positive control).</b> CoreProtect's own network
 *       requests must show up in the egress log. If they don't, the harness
 *       can't see network traffic, and a clean LibreProtect result would
 *       mean nothing.</li>
 *   <li><b>LibreProtect</b>, without a {@code libreprotect.yml}. Its only
 *       network requests must be the default policy's update checks: to
 *       GitHub, then to Modrinth once GitHub fails, since the egress agent
 *       blocks both. It must read the data stock CoreProtect wrote (drop-in
 *       replacement), work through the public API and commands, show its
 *       branding, and write the default policy.</li>
 *   <li><b>Stock CoreProtect again.</b> Must read everything, including what
 *       LibreProtect wrote (switching back works), and find no license file
 *       planted by LibreProtect.</li>
 * </ol>
 *
 * <p>The feature suites run alongside it, each in its own file: {@link CapabilityChecks},
 * {@link TranslationChecks}, {@link UpdateChecks}, {@link MigrationChecks} and
 * {@link AutoPurgeChecks}.
 * A suite gets a {@link Suite}, which creates fresh {@link Server}s, boots them
 * with either plugin and a {@link Scenario} for the test plugin, gives access
 * to the {@link Containers} and the upstream generation, and records checks
 * under the suite's name. A suite can run parts of itself at the same time
 * ({@link Suite#concurrently}), each part on servers of its own. At most
 * {@code --jobs} servers run at once; the checks are reported in the same
 * order however the suites and parts interleave.
 *
 * <p>Every server runs with LibreProtect's egress agent in deny mode, so no
 * run can reach the network, whatever the plugin under test does. Loopback is
 * exempt, which lets servers reach the database containers.
 *
 * <p>Usage: {@code java Harness.java --work DIR --paper-lock FILE --agent JAR
 * --it-plugin JAR --upstream JAR --fork JAR [--generation 24|25]
 * [--containers ENV_FILE] [--jobs N]}. Java compiles the other source files in
 * this directory as they are needed (JEP 458). Without {@code --generation}, it
 * is read from the upstream JAR. Without {@code --jobs}, one server runs at a
 * time. {@code scripts/lp it} passes all of them.
 *
 * <p>Running this accepts the Minecraft EULA (https://aka.ms/MinecraftEULA)
 * on behalf of whoever runs it.
 */
public final class Harness {

    private static final Duration SERVER_TIMEOUT = Duration.ofMinutes(5);
    private static final String CORE_PROTECT_CONFIG = """
        # Seeded by LibreProtect's integration test. The donation key makes
        # CoreProtect contact its license server, one of the requests the
        # positive control must see. Update checks are on, as by default.
        donation-key: LPITKEY1
        check-updates: true
        """;
    /** Where LibreProtect's default policy asks for updates, in order */
    private static final List<String> DEFAULT_UPDATE_HOSTS = List.of("api.github.com", "api.modrinth.com");

    private final Map<String, String> arguments;
    private final int generation;
    private final Containers containers;
    /** How many servers may run at once */
    private final int jobs;
    private final Slots slots;
    /** Ports given to servers so far, which no other server of this run gets */
    private final Set<Integer> ports = ConcurrentHashMap.newKeySet();
    private Path paper;

    private Harness(Map<String, String> arguments) throws IOException {
        this.arguments = arguments;
        this.generation = arguments.containsKey("generation")
            ? Integer.parseInt(arguments.get("generation")) : generationOf(path("upstream"));
        this.containers = arguments.containsKey("containers") ? Containers.load(path("containers")) : null;
        this.jobs = Integer.parseInt(arguments.getOrDefault("jobs", "1"));
        if (jobs < 1) {
            throw new IllegalArgumentException("--jobs must be at least 1");
        }
        this.slots = new Slots(jobs);
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> arguments = new LinkedHashMap<>();
        for (int i = 0; i + 1 < args.length; i += 2) {
            arguments.put(args[i].replaceFirst("^--", ""), args[i + 1]);
        }
        for (String required : List.of("work", "paper-lock", "agent", "it-plugin", "upstream", "fork")) {
            if (!arguments.containsKey(required)) {
                throw new IllegalArgumentException("Missing --" + required);
            }
        }
        System.exit(new Harness(arguments).run());
    }

    private Path path(String argument) {
        return Path.of(arguments.get(argument)).toAbsolutePath();
    }

    private int run() throws Exception {
        paper = preparePaper();
        prefetchLibraries();
        System.out.println("==> Running the suites, up to " + jobs + " server(s) at a time");
        // Ranked by how many times they boot one server, so that the longest go first when servers wait for slots
        Suite dropIn = new Suite(this, "", "drop-in", List.of(0));
        Suite migration = new Suite(this, "migration", "migration", List.of(1));
        Suite update = new Suite(this, "update", "update", List.of(2));
        Suite autoPurge = new Suite(this, "auto-purge", "auto-purge", List.of(3));
        Suite translation = new Suite(this, "translation", "translation", List.of(4));
        Suite capability = new Suite(this, "capability", "capability", List.of(5));
        runAll(List.of(dropIn, migration, update, autoPurge, translation, capability),
            List.of(this::dropIn, MigrationChecks::run, UpdateChecks::run, AutoPurgeChecks::run, TranslationChecks::run,
                CapabilityChecks::run));

        List<String> passes = new ArrayList<>();
        List<String> failures = new ArrayList<>();
        for (Suite suite : List.of(dropIn, capability, translation, update, migration, autoPurge)) {
            suite.collect(passes, failures);
        }
        System.out.println();
        passes.forEach(pass -> System.out.println("PASS " + pass));
        failures.forEach(failure -> System.out.println("FAIL " + failure));
        System.out.println(failures.isEmpty() ? "Integration test passed" : failures.size() + " integration check(s) failed");
        return failures.isEmpty() ? 0 : 1;
    }

    /** A suite's entry point, such as {@code TranslationChecks::run}, or a part of a suite */
    @FunctionalInterface
    interface Checks {
        void run(Suite suite) throws Exception;
    }

    /**
     * Run each of the checks with its suite, all at the same time, and wait
     * for them. If one throws, even an {@link Error} such as a failed
     * assertion, record that as a failure of its suite; the others go on.
     */
    private static void runAll(List<Suite> suites, List<Checks> checks) throws InterruptedException {
        suites.forEach(suite -> suite.harness.slots.want(suite));
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < suites.size(); i++) {
            Suite suite = suites.get(i);
            Checks part = checks.get(i);
            threads.add(Thread.ofPlatform().name("suite " + suite.label).start(() -> {
                try {
                    part.run(suite);
                    suite.finished = true;
                } catch (Throwable e) {
                    suite.check(false, "suite aborted: " + e);
                    StringWriter trace = new StringWriter();
                    e.printStackTrace(new PrintWriter(trace));
                    suite.print(trace.toString().stripTrailing());
                } finally {
                    suite.releaseSlot();
                    suite.harness.slots.unwant(suite);
                }
            }));
        }
        for (Thread thread : threads) {
            thread.join();
        }
    }

    /**
     * What a suite works with. It names the suite's servers and prefixes its
     * checks. For example:
     * <pre>{@code
     * var server = suite.newServer("de");
     * server.coreProtectConfig("language: de\n");
     * var run = server.boot(Harness.Variant.FORK, Harness.Scenario.steps("translation")
     *     .set("translation.command", "co status"));
     * suite.check(run.result("translation.error") == null, "the translation step ran without errors");
     * suite.check(run.console().contains("Datenbank"), "/co status speaks German");
     * }</pre>
     */
    static final class Suite {

        private final Harness harness;
        private final String name;
        /** What its output lines start with, which tells suites and their parts apart */
        private final String label;
        /** Which suites and parts get slots for servers first: those whose ranks come first, part by part */
        private final List<Integer> rank;
        /**
         * Whether it holds one of the {@code --jobs} slots for servers. It
         * takes one when it first boots a server, and keeps it until it ends,
         * so that a server it boots again doesn't wait for other suites.
         */
        private boolean holdsSlot;
        /** Its checks, as {@code PASS ...} or {@code FAIL ...}, and its parts, in the order they began */
        private final List<Object> results = new ArrayList<>();
        /**
         * Whether its checks returned rather than threw. Checks that never
         * end aren't reported: the harness waits for them.
         */
        private volatile boolean finished;

        private Suite(Harness harness, String name, String label, List<Integer> rank) {
            this.harness = harness;
            this.name = name;
            this.label = label;
            this.rank = rank;
        }

        String name() {
            return name;
        }

        /**
         * Run parts of this suite at the same time, and wait for them. Each
         * gets a suite of the same name, whose servers must have names of
         * their own. A part that throws fails, and the others go on. Their
         * checks are reported in the order given, after the checks this
         * suite made before.
         */
        void concurrently(Map<String, Checks> parts) throws InterruptedException {
            List<Suite> suites = new ArrayList<>();
            for (String part : parts.keySet()) {
                List<Integer> partRank = new ArrayList<>(rank);
                partRank.add(suites.size());
                Suite suite = new Suite(harness, name, label + "/" + part, partRank);
                suites.add(suite);
                harness.slots.want(suite);
                synchronized (results) {
                    results.add(suite);
                }
            }
            // The parts boot servers, while this one waits for them
            releaseSlot();
            harness.slots.unwant(this);
            runAll(suites, List.copyOf(parts.values()));
        }

        /** 24 or 25: the CoreProtect generation of the upstream build, 25 having DuckDB and ClickHouse */
        int generation() {
            return harness.generation;
        }

        /** The database containers; fails if the harness was started without them */
        Containers containers() {
            if (harness.containers == null) {
                throw new IllegalStateException("No database containers; run the harness with --containers, as scripts/lp it does");
            }
            return harness.containers;
        }

        /** The plugin JAR that {@link Server#boot} installs for this variant */
        Path jar(Variant variant) {
            return harness.path(variant.toString());
        }

        /**
         * A fresh server in {@code <work>/<suite>-<name>} with Paper, the test
         * plugin and nothing else. Write its files before its first boot.
         */
        Server newServer(String name) throws IOException {
            if (!name.matches("[a-z0-9][a-z0-9-]*")) {
                throw new IllegalArgumentException("Server names are lowercase letters, digits and dashes: " + name);
            }
            Path dir = harness.prepareServer(this.name.isEmpty() ? name : this.name + "-" + name);
            Files.copy(harness.path("it-plugin"), dir.resolve("plugins/LibreProtectIT.jar"));
            return new Server(this, dir);
        }

        /** Record a check, reported as {@code PASS} or {@code FAIL} with the suite's name */
        void check(boolean condition, String description) {
            synchronized (results) {
                results.add((condition ? "PASS " : "FAIL ") + (name.isEmpty() ? description : name + ": " + description));
            }
        }

        /** Print context for the checks, such as what a run observed */
        void note(String message) {
            print("    " + message);
        }

        /** Print a line of output, marked with the suite or part it's from */
        private void print(String line) {
            String prefix = "[" + label + "] ";
            synchronized (System.out) {
                System.out.println(prefix + line.replace("\n", "\n" + prefix));
            }
        }

        /** Take a slot for servers, unless it holds one; only its own thread boots its servers */
        private void holdSlot() throws InterruptedException {
            if (!holdsSlot) {
                harness.slots.take(this);
                holdsSlot = true;
            }
        }

        private void releaseSlot() {
            if (holdsSlot) {
                holdsSlot = false;
                harness.slots.give();
            }
        }

        /**
         * Add the checks of this suite and its parts to the passes and
         * failures, in order. A suite or part that didn't finish, and so
         * never ran its later checks, but recorded no failure, such as a
         * "suite aborted", gets a failure for that.
         */
        private void collect(List<String> passes, List<String> failures) {
            boolean failed = false;
            synchronized (results) {
                for (Object result : results) {
                    if (result instanceof Suite part) {
                        part.collect(passes, failures);
                    } else if (((String) result).startsWith("PASS ")) {
                        passes.add(((String) result).substring(5));
                    } else {
                        failures.add(((String) result).substring(5));
                        failed = true;
                    }
                }
            }
            // Usually its "suite aborted" says so already
            if (!finished && !failed) {
                failures.add("suite " + label + " didn't finish, so the checks after where it stopped didn't run");
            }
        }
    }

    /**
     * The {@code --jobs} slots for servers. Each suite or part that may boot
     * a server wants one, from when it starts until it takes one or ends. A
     * slot goes to a suite only while more are free than suites of a better
     * rank want, so that those that boot one server the most times go first,
     * even if others ask sooner.
     */
    private static final class Slots {

        private static final Comparator<List<Integer>> RANKS = (a, b) -> {
            for (int i = 0; i < Math.min(a.size(), b.size()); i++) {
                int order = Integer.compare(a.get(i), b.get(i));
                if (order != 0) {
                    return order;
                }
            }
            return Integer.compare(a.size(), b.size());
        };

        /** Suites that want a slot and don't hold one */
        private final Set<Suite> wanting = new HashSet<>();
        private int free;

        private Slots(int count) {
            free = count;
        }

        synchronized void want(Suite suite) {
            wanting.add(suite);
        }

        /** The suite won't take a slot after all, for now */
        synchronized void unwant(Suite suite) {
            wanting.remove(suite);
            notifyAll();
        }

        synchronized void take(Suite suite) throws InterruptedException {
            wanting.add(suite);
            try {
                while (free <= wantingBefore(suite)) {
                    wait();
                }
            } catch (InterruptedException e) {
                wanting.remove(suite);
                notifyAll();
                throw e;
            }
            wanting.remove(suite);
            free--;
        }

        synchronized void give() {
            free++;
            notifyAll();
        }

        private long wantingBefore(Suite suite) {
            return wanting.stream().filter(other -> RANKS.compare(other.rank, suite.rank) < 0).count();
        }
    }

    /** Which plugin a server boots as CoreProtect */
    enum Variant {
        UPSTREAM, FORK;

        @Override
        public String toString() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** A server directory that can be booted any number of times */
    static final class Server {

        private final Suite suite;
        private final Path dir;
        private int runs;
        private Duration timeout = SERVER_TIMEOUT;

        private Server(Suite suite, Path dir) {
            this.suite = suite;
            this.dir = dir;
        }

        Path dir() {
            return dir;
        }

        /** The plugin's data folder, which LibreProtect shares with CoreProtect */
        Path coreProtectFolder() {
            return dir.resolve("plugins/CoreProtect");
        }

        /** Write a file, relative to the server directory */
        Server write(String relative, String content) throws IOException {
            Path file = dir.resolve(relative);
            Files.createDirectories(file.getParent());
            Files.writeString(file, content, StandardCharsets.UTF_8);
            return this;
        }

        Server coreProtectConfig(String yaml) throws IOException {
            return write("plugins/CoreProtect/config.yml", yaml);
        }

        Server libreProtectConfig(String yaml) throws IOException {
            return write("plugins/CoreProtect/libreprotect.yml", yaml);
        }

        /** How long a boot may take before the harness kills it and fails the run */
        Server timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        /** Boot with the test plugin's default probe, the one the drop-in suite uses */
        Run boot(Variant variant) throws Exception {
            return boot(variant, null);
        }

        /** Boot with the steps and values of a scenario, then wait for the server to stop */
        Run boot(Variant variant, Scenario scenario) throws Exception {
            return suite.harness.boot(this, variant, scenario);
        }
    }

    /**
     * What the test plugin does in one boot, written to its
     * {@code scenario.properties}: the steps it runs in order, and any values
     * they read. The step {@code default} is the drop-in probe. Other steps go
     * to the plugin's per-feature {@code Scenario} classes by the part of their
     * name before the first dot, so {@code migration} and {@code migration.seed}
     * both go to {@code MigrationScenario}. Prefix keys with the step's feature.
     * The plugin stops the server after {@code timeout.ticks} (default 3600,
     * 3 minutes) even if steps are still running, and the harness kills a
     * boot after {@link Server#timeout} (default 5 minutes); raise both for
     * longer steps.
     */
    static final class Scenario {

        private final Properties values = new Properties();

        private Scenario() {
        }

        static Scenario steps(String... steps) {
            Scenario scenario = new Scenario();
            scenario.values.setProperty("steps", String.join(",", steps));
            return scenario;
        }

        Scenario set(String key, Object value) {
            values.setProperty(key, String.valueOf(value));
            return this;
        }

        private void write(Path file) throws IOException {
            Files.createDirectories(file.getParent());
            try (Writer out = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
                values.store(out, "Written by LibreProtect's integration test harness");
            }
        }
    }

    /** One server boot and what it left behind */
    record Run(int number, Variant variant, int exitCode, Properties results, List<Egress> egress, String console,
               Path consoleLog) {

        /** Network attempts with CoreProtect or LibreProtect on the stack */
        List<Egress> pluginEgress() {
            return egress.stream().filter(Egress::fromPlugin).toList();
        }

        /** Network attempts by the server itself or other plugins */
        List<Egress> serverEgress() {
            return egress.stream().filter(line -> !line.fromPlugin()).toList();
        }

        /** A value from the test plugin's results.properties, or null */
        String result(String key) {
            return results.getProperty(key);
        }

        int integer(String key) {
            try {
                return Integer.parseInt(results.getProperty(key, "-1"));
            } catch (NumberFormatException e) {
                return -1;
            }
        }

        /**
         * The console lines between the test plugin's {@code [LPIT] begin <name>}
         * and {@code [LPIT] end <name>} markers, of every such pair, or "".
         * Asynchronous command output can land after the end marker, unless
         * the step ran the command with a settle time.
         */
        String section(String name) {
            StringBuilder text = new StringBuilder();
            int begin = console.indexOf("[LPIT] begin " + name + "\n");
            while (begin >= 0) {
                int from = console.indexOf('\n', begin) + 1;
                int end = console.indexOf("[LPIT] end " + name + "\n", from);
                if (end < 0) {
                    break;
                }
                text.append(console, from, console.lastIndexOf('\n', end) + 1);
                begin = console.indexOf("[LPIT] begin " + name + "\n", end);
            }
            return text.toString();
        }
    }

    /**
     * One network attempt from the egress log. Attempts to loopback addresses
     * aren't logged.
     */
    record Egress(String kind, String target, String attribution, String thread, String stack) {

        static Egress parse(String line) {
            String[] fields = line.split("\t", 5);
            return new Egress(field(fields, 0), field(fields, 1), field(fields, 2), field(fields, 3), field(fields, 4));
        }

        private static String field(String[] fields, int index) {
            return index < fields.length ? fields[index] : "";
        }

        boolean fromPlugin() {
            return attribution.equals("plugin");
        }

        @Override
        public String toString() {
            return kind + " " + target + " from " + thread + " via " + (stack.isEmpty() ? "?" : stack.split("\\|")[0]);
        }
    }

    private Run boot(Server server, Variant variant, Scenario scenario) throws Exception {
        Path dir = server.dir();
        int number = ++server.runs;
        try (Stream<Path> jars = Files.list(dir.resolve("plugins"))) {
            for (Path jar : (Iterable<Path>) jars.filter(path -> path.getFileName().toString().startsWith("CoreProtect-"))::iterator) {
                Files.delete(jar);
            }
        }
        Files.copy(path(variant.toString()), dir.resolve("plugins/CoreProtect-" + variant + ".jar"));
        Path results = dir.resolve("plugins/LibreProtectIT/results.properties");
        Files.deleteIfExists(results);
        Path scenarioFile = dir.resolve("plugins/LibreProtectIT/scenario.properties");
        if (scenario == null) {
            Files.deleteIfExists(scenarioFile);
        } else {
            scenario.write(scenarioFile);
        }
        Path egress = dir.resolve("egress-" + number + ".log");
        Path console = dir.resolve("console-" + number + ".log");

        String java = ProcessHandle.current().info().command().orElse("java");
        List<String> command = List.of(java, "-Xms512M", "-Xmx2G",
            "-javaagent:" + path("agent") + "=log=" + egress + ",mode=deny",
            "-jar", "paper.jar", "--nogui");
        String where = server.suite.name().isEmpty() ? "" : " on " + dir.getFileName();
        server.suite.holdSlot();
        choosePort(dir);
        server.suite.print("==> Run " + number + where + ": " + variant + " (" + String.join(" ", command) + ")");
        long started = System.nanoTime();
        Process process = new ProcessBuilder(command).directory(dir.toFile())
            .redirectErrorStream(true).redirectOutput(console.toFile()).redirectInput(ProcessBuilder.Redirect.PIPE)
            .start();
        process.getOutputStream().close();
        boolean exited = process.waitFor(server.timeout.toSeconds(), TimeUnit.SECONDS);
        if (!exited) {
            process.destroyForcibly().waitFor();
            server.suite.check(false, "run " + number + " (" + variant + ") did not finish within " + server.timeout
                + "; see " + console);
        }
        server.suite.print("==> Run " + number + where + " took "
            + TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) / 1000.0 + " s");

        Properties properties = new Properties();
        if (Files.exists(results)) {
            try (Reader in = Files.newBufferedReader(results, StandardCharsets.UTF_8)) {
                properties.load(in);
            }
        } else {
            server.suite.check(false, "run " + number + " (" + variant + ") wrote no results; see " + console);
        }
        List<Egress> egressLines = Files.exists(egress)
            ? Files.readAllLines(egress).stream().map(Egress::parse).toList()
            : List.of();
        return new Run(number, variant, exited ? process.exitValue() : -1, properties, egressLines,
            Files.readString(console, StandardCharsets.UTF_8).replaceAll("\u001B\\[[0-9;]*m", ""), console);
    }

    /** The drop-in suite; see the class comment */
    private void dropIn(Suite suite) throws Exception {
        Server server = suite.newServer("server");
        server.coreProtectConfig(CORE_PROTECT_CONFIG);

        Run control = server.boot(Variant.UPSTREAM);
        checkControl(suite, control);
        Run fork = server.boot(Variant.FORK);
        checkFork(suite, fork, control);
        Run back = server.boot(Variant.UPSTREAM);
        checkSwitchBack(suite, back, fork);
    }

    private void checkCommon(Suite suite, Run run) {
        String name = "run " + run.number() + " (" + run.variant() + ")";
        suite.check(run.results().getProperty("coreprotect.enabled", "").equals("true"), name + ": CoreProtect enabled");
        suite.check(run.results().getProperty("api.enabled", "").equals("true"), name + ": API enabled");
        suite.check(run.integer("api.version") >= 10, name + ": API version " + run.results().getProperty("api.version"));
        suite.check(run.results().getProperty("api.logPlacement", "").equals("true"), name + ": API logged a placement");
        suite.check(run.integer("lookup.after") == run.integer("lookup.before") + 1,
            name + ": API lookup sees the new placement (" + run.integer("lookup.before") + " -> "
                + run.integer("lookup.after") + ")");
        suite.check(run.exitCode() == 0, name + ": server exited cleanly (exit code " + run.exitCode() + ")");
    }

    private void checkControl(Suite suite, Run run) {
        checkCommon(suite, run);
        List<String> targets = run.pluginEgress().stream().map(Egress::target).distinct().toList();
        suite.note("positive control saw CoreProtect contact: " + targets);
        suite.check(targets.stream().anyMatch(target -> target.startsWith("update.coreprotect.net")),
            "positive control: harness sees stock CoreProtect's update check");
        suite.check(targets.stream().anyMatch(target -> target.equals("coreprotect.net") || target.startsWith("coreprotect.net:")),
            "positive control: harness sees stock CoreProtect's license check");
        if (run.results().getProperty("errorReporter.queued", "").equals("true")) {
            suite.check(targets.stream().anyMatch(target -> target.startsWith("error-reporting.coreprotect.net")),
                "positive control: harness sees stock CoreProtect's error report");
        }
        suite.check(run.integer("lookup.before") == 0, "run 1: starts from an empty database");
    }

    private void checkFork(Suite suite, Run run, Run control) throws IOException {
        checkCommon(suite, run);
        checkDefaultUpdateChecks(suite, run);
        suite.check(run.results().getProperty("coreprotect.class", "").equals("net.deltik.mc.libreprotect.LibreProtectPlugin"),
            "LibreProtect's generated main class is loaded (" + run.results().getProperty("coreprotect.class") + ")");
        suite.check(run.results().getProperty("coreprotect.class.super", "").equals("net.coreprotect.CoreProtect"),
            "API consumers still get a net.coreprotect.CoreProtect");
        suite.check(run.results().getProperty("coreprotect.version", "").contains("-libre"),
            "plugin version marks LibreProtect (" + run.results().getProperty("coreprotect.version") + ")");
        String ownVersion = run.results().getProperty("coreprotect.ownVersion");
        String stockVersion = control.results().getProperty("coreprotect.ownVersion");
        suite.check(stockVersion != null && stockVersion.equals(ownVersion),
            "CoreProtect compares its own version, " + ownVersion + ", as stock CoreProtect of the same commit does ("
                + stockVersion + "), rather than LibreProtect's version"
                + (run.results().getProperty("coreprotect.ownVersion.error") == null ? ""
                : " (error " + run.results().getProperty("coreprotect.ownVersion.error") + ")"));
        suite.check(run.integer("lookup.before") >= control.integer("lookup.after"),
            "LibreProtect reads the data stock CoreProtect wrote");

        // Command output is asynchronous, so check the whole console rather than between the markers
        String console = run.console();
        String version = run.results().getProperty("coreprotect.version", "?");
        suite.check(console.contains("[LibreProtect] LibreProtect has been successfully enabled!")
                && console.contains("[LibreProtect] LibreProtect is a privacy-hardened build of CoreProtect by Intelli."),
            "startup messages name LibreProtect and credit CoreProtect");
        suite.check(console.contains("[LibreProtect] Network policy: preset allow-updates, 0 custom routes, default action BLOCK,"
                + " 2 update sources\n"), "the default allow-updates policy is active");
        suite.check(!console.contains("Community Edition"), "no Community Edition label");
        suite.check(console.contains("----- LibreProtect -----") && console.contains("Version: LibreProtect v" + version + "."),
            "/co status names LibreProtect and its version");
        suite.check(!console.contains("License:") && !console.contains("donation key"),
            "no donation-key messages, although config.yml has a donation key");
        suite.check(!console.contains("Discord:") && !console.contains("Patreon:") && !console.contains("Enjoy CoreProtect")
                && console.contains("Website: github.com/Deltik/LibreProtect"),
            "links point to LibreProtect instead of CoreProtect's Discord and Patreon");
        suite.check(console.contains("----- LibreProtect Help -----") && console.contains("LibreProtect - Command \"/co lpit-unknown\""),
            "/co help and error messages use LibreProtect's header and chat prefix");
        suite.check(!console.contains("﷐"), "no internal markers leak into messages");
        // CoreProtect uses SQLite here, so the usage names only the databases it can migrate to
        suite.check(console.contains("LibreProtect - Usage: /co migrate-db <" + (generation >= 25 ? "mysql|duckdb|clickhouse"
                : "mysql") + "> [--full-validation]\n"),
            "/co migrate-db reaches LibreProtect's extension, and lists the databases it can migrate to");
        suite.check(!console.contains("\tat net.coreprotect.") && !console.contains("\tat net.deltik.mc.libreprotect."),
            "no stack traces from CoreProtect or LibreProtect");

        Path dataFolder = path("work").resolve("server/plugins/CoreProtect");
        Path policy = dataFolder.resolve("libreprotect.yml");
        suite.check(Files.isRegularFile(policy), "default libreprotect.yml was written");
        String written = Files.isRegularFile(policy) ? Files.readString(policy, StandardCharsets.UTF_8) : "";
        suite.check(written.contains("\npreset: allow-updates\n"), "the default libreprotect.yml sets preset: allow-updates");
        suite.check(written.contains("\nupdate-sources:\n  - type: github\n    repository: Deltik/LibreProtect\n"
                + "  - type: modrinth\n    project: libreprotect\n"),
            "the default libreprotect.yml lists GitHub's update source, then Modrinth's");
        checkNoLicense(suite, dataFolder, "LibreProtect");
    }

    /**
     * LibreProtect answers CoreProtect's update check under its default
     * policy by asking its update sources, GitHub first. The egress agent
     * blocks that request, so LibreProtect asks Modrinth next, and that is
     * blocked too. Nothing else may leave.
     */
    private void checkDefaultUpdateChecks(Suite suite, Run run) {
        List<Egress> egress = run.pluginEgress();
        suite.note("LibreProtect tried to contact: " + egress.stream().map(Egress::target).toList());
        List<String> hosts = new ArrayList<>();
        for (Egress attempt : egress) {
            // A request shows up as a name lookup, then a connection to the name, both blocked
            String host = attempt.target().replaceFirst(":\\d+$", "");
            if (hosts.isEmpty() || !hosts.get(hosts.size() - 1).equals(host)) {
                hosts.add(host);
            }
        }
        suite.check(hosts.equals(DEFAULT_UPDATE_HOSTS), "LibreProtect's only network requests are update checks to GitHub,"
            + " then Modrinth once GitHub failed" + (hosts.equals(DEFAULT_UPDATE_HOSTS) ? "" : ": " + egress));
        List<Egress> other = egress.stream()
            .filter(attempt -> !attempt.stack().contains("net.deltik.mc.libreprotect.update.UpdateHttp.")
                || !(attempt.kind().equals("resolve") || attempt.target().endsWith(":443")))
            .toList();
        suite.check(other.isEmpty(), "each of them is an HTTPS request from LibreProtect's update check"
            + (other.isEmpty() ? "" : ": " + other));
    }

    private void checkSwitchBack(Suite suite, Run run, Run fork) throws IOException {
        checkCommon(suite, run);
        suite.check(run.integer("lookup.before") >= fork.integer("lookup.after"),
            "stock CoreProtect reads the data LibreProtect wrote");
        checkNoLicense(suite, path("work").resolve("server/plugins/CoreProtect"), "switching back");
    }

    private void checkNoLicense(Suite suite, Path dataFolder, String when) throws IOException {
        Path license = dataFolder.resolve(".license");
        boolean clean = !Files.exists(license) || Files.readString(license).isBlank();
        suite.check(clean, when + ": no license key was written to " + license);
    }

    /**
     * The database containers that {@code scripts/lp} started, from the
     * shell-style KEY=VALUE file it wrote ({@code build/containers.env}).
     * MySQL is always there; ClickHouse is there for CoreProtect 25 builds.
     */
    static final class Containers {

        private final Properties env = new Properties();

        private Containers() {
        }

        static Containers load(Path file) throws IOException {
            Containers containers = new Containers();
            try (Reader in = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                containers.env.load(in);
            }
            return containers;
        }

        /** A raw value from the file, such as {@code MYSQL_ROOT_PASSWORD}, or null */
        String value(String key) {
            return env.getProperty(key);
        }

        Database mysql() {
            return database("mysql");
        }

        Database clickhouse() {
            return database("clickhouse");
        }

        boolean hasClickHouse() {
            return env.containsKey("CLICKHOUSE_CONTAINER");
        }

        private Database database(String kind) {
            String prefix = kind.toUpperCase(Locale.ROOT) + "_";
            if (!env.containsKey(prefix + "CONTAINER")) {
                throw new IllegalStateException("No " + kind + " container; scripts/lp it starts ClickHouse for"
                    + " CoreProtect 25 builds, and scripts/lp db up --all always");
            }
            return new Database(kind, this, prefix);
        }
    }

    /** A database in one of the {@link Containers}, empty unless a test filled it */
    static final class Database {

        private final String kind;
        private final Containers containers;
        private final String prefix;

        private Database(String kind, Containers containers, String prefix) {
            this.kind = kind;
            this.containers = containers;
            this.prefix = prefix;
        }

        /** {@code mysql} or {@code clickhouse}, as in CoreProtect's config keys */
        String kind() {
            return kind;
        }

        String host() {
            return containers.value(prefix + "HOST");
        }

        /** The published port: MySQL's protocol, or ClickHouse's HTTP interface */
        int port() {
            return Integer.parseInt(containers.value(prefix + "PORT"));
        }

        String database() {
            return containers.value(prefix + "DATABASE");
        }

        String username() {
            return containers.value(prefix + "USERNAME");
        }

        String password() {
            return containers.value(prefix + "PASSWORD");
        }

        /**
         * CoreProtect's config.yml keys that connect to this database, such
         * as {@code mysql-host}. Selecting it ({@code use-mysql} or
         * {@code database-type}) is up to the caller.
         */
        String coreProtectConfig() {
            return kind + "-host: " + host() + "\n"
                + kind + "-port: " + port() + "\n"
                + kind + "-database: " + database() + "\n"
                + kind + "-username: " + username() + "\n"
                + kind + "-password: \"" + password() + "\"\n";
        }

        /**
         * Run SQL as an administrator in this database and return the output:
         * one line per row, tab-separated, without column names.
         */
        String query(String sql) throws IOException, InterruptedException {
            if (kind.equals("clickhouse")) {
                HttpRequest request = HttpRequest.newBuilder(URI.create("http://" + host() + ":" + port() + "/?database=" + database()))
                    .header("X-ClickHouse-User", username()).header("X-ClickHouse-Key", password())
                    .POST(HttpRequest.BodyPublishers.ofString(sql)).build();
                HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    throw new IOException("ClickHouse query failed: HTTP " + response.statusCode() + ": " + response.body());
                }
                return response.body();
            }
            Process process = new ProcessBuilder(containers.value("CONTAINER_ENGINE"), "exec",
                "-e", "MYSQL_PWD=" + containers.value("MYSQL_ROOT_PASSWORD"), containers.value("MYSQL_CONTAINER"),
                "mysql", "--protocol=TCP", "-h127.0.0.1", "-uroot", "--batch", "--skip-column-names",
                "-D", database(), "-e", sql)
                .redirectError(ProcessBuilder.Redirect.INHERIT).start();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (process.waitFor() != 0) {
                throw new IOException("MySQL query failed with exit code " + process.exitValue() + ": " + sql);
            }
            return output;
        }
    }

    /**
     * Create an empty server directory that shares Paper's downloads.
     */
    private Path prepareServer(String name) throws IOException {
        Path server = path("work").resolve(name);
        deleteRecursively(server);
        Files.createDirectories(server.resolve("plugins"));
        for (String shared : List.of("cache", "libraries", "versions")) {
            Path source = paper.getParent().resolve(shared);
            Files.createDirectories(source);
            Files.createSymbolicLink(server.resolve(shared), source);
        }
        Files.copy(paper, server.resolve("paper.jar"));
        Files.writeString(server.resolve("eula.txt"), "eula=true\n");
        Files.writeString(server.resolve("server.properties"), String.join("\n",
            "online-mode=false", "level-type=minecraft\\:flat", "generate-structures=false", "spawn-protection=0",
            "view-distance=2", "simulation-distance=2", "server-port=0",
            "enable-rcon=false", "enable-query=false", ""));
        return server;
    }

    /**
     * Give the server a port that is free right now, and that no other
     * server of this run was given. Other integration tests may be running on
     * this machine, so a fixed or derived port can clash.
     */
    private void choosePort(Path server) throws IOException {
        int port;
        do {
            try (ServerSocket socket = new ServerSocket(0)) {
                port = socket.getLocalPort();
            }
        } while (!ports.add(port));
        Path properties = server.resolve("server.properties");
        Files.writeString(properties, Files.readString(properties).replaceAll("(?m)^server-port=.*$", "server-port=" + port));
    }

    /**
     * @return 25 if the upstream JAR has CoreProtect's multi-engine database layer, otherwise 24
     */
    private static int generationOf(Path upstreamJar) throws IOException {
        try (java.util.zip.ZipFile zip = new java.util.zip.ZipFile(upstreamJar.toFile())) {
            return zip.getEntry("net/coreprotect/database/DatabaseType.class") != null ? 25 : 24;
        }
    }

    /**
     * CoreProtect can declare {@code libraries} in plugin.yml (DuckDB, on
     * upstream's master branch after v24.1), which the server downloads from Maven Central when it
     * loads the plugin. The tested runs block all network access, so fetch
     * them beforehand: boot the server once, with network access, and a
     * stand-in plugin that declares the same libraries and has no code.
     * No CoreProtect code runs while the network is reachable.
     */
    private void prefetchLibraries() throws Exception {
        List<String> libraries = new ArrayList<>();
        for (Variant variant : Variant.values()) {
            for (String library : pluginLibraries(path(variant.toString()))) {
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
        Path server = prepareServer("prefetch");
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
        try (InputStream in = Files.newInputStream(path("paper-lock"))) {
            lock.load(in);
        }
        String version = lock.getProperty("PAPER_VERSION");
        String build = lock.getProperty("PAPER_BUILD");
        Path directory = path("work").resolve("paper-" + version + "-" + build);
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
