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
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Bundled translations: servers booted with a {@code language} other than
 * English. The test plugin's side is {@code TranslationScenario}.
 *
 * <ul>
 *   <li><b>German, twice.</b> The first boot answers CoreProtect's translation
 *       request from the bundle, without a network request, and CoreProtect
 *       saves every bundled phrase to its cache. A phrase customized in
 *       {@code language.yml} stays as customized. The second boot uses the
 *       cache and doesn't ask again.</li>
 *   <li><b>German with the passthrough preset, twice.</b> LibreProtect asks
 *       CoreProtect's translation service, which the egress agent blocks, so
 *       the bundled translation answers alone. As after any failed request,
 *       the second boot asks again.</li>
 *   <li><b>Dutch</b>, which isn't bundled: messages stay in English,
 *       CoreProtect saves no cache, and LibreProtect says why, once.</li>
 * </ul>
 */
final class TranslationChecks {

    /** A phrase that {@code /co help} shows, customized in language.yml */
    private static final String CUSTOMIZED_PHRASE = "HELP_STATUS_COMMAND";
    private static final String CUSTOMIZED_TEXT = "LPIT custom status help";

    private TranslationChecks() {
    }

    static void run(Harness.Suite suite) throws Exception {
        Map<String, Harness.Checks> parts = new LinkedHashMap<>();
        parts.put("de", TranslationChecks::german);
        parts.put("passthrough", TranslationChecks::passthrough);
        parts.put("nl", TranslationChecks::notBundled);
        suite.concurrently(parts);
    }

    /**
     * CoreProtect's config.yml for a language, with update checks off: they
     * are requests of their own, which {@link UpdateChecks} covers
     */
    private static String coreProtectConfig(String language) {
        return "language: " + language + "\ncheck-updates: false\n";
    }

    private static void german(Harness.Suite suite) throws Exception {
        Harness.Server server = suite.newServer("de");
        server.coreProtectConfig(coreProtectConfig("de"));
        server.write("plugins/CoreProtect/language.yml",
            "# CoreProtect Language File (en)\n\n" + CUSTOMIZED_PHRASE + ": \"" + CUSTOMIZED_TEXT + "\"\n");
        Path cache = server.coreProtectFolder().resolve(".language");

        Harness.Run first = server.boot(Harness.Variant.FORK, Harness.Scenario.steps("translation"));
        checkRun(suite, "de, first boot", first);
        String saved = read(cache);
        String header = "# CoreProtect v" + first.result("translation.version") + " Language Cache (de)";
        String savedHeader = saved.lines().findFirst().orElse("nothing");
        suite.check(savedHeader.equals(header), "de: CoreProtect saved its cache, starting " + header
            + (savedHeader.equals(header) ? "" : ", not " + savedHeader));
        suite.check(saved.contains("\nHELP_HEADER: \"{0} Hilfe\"\n"), "de: the cache has the bundled German translation");
        suite.check(saved.contains("\nHELP_ACTION_2: \"Beispiele: [a:block], [a:+block], [a:-block]")
                && saved.contains("\nHELP_INSPECT_7: \"Tipp: Benutze \\\"/co i\\\" für schnelleren Zugriff\"\n"),
            "de: phrases with plus signs, quotes, slashes and umlauts are translated too");
        suite.check(!saved.contains(CUSTOMIZED_PHRASE), "de: the phrase customized in language.yml isn't in the cache");
        Set<String> expected = new TreeSet<>(phrases(jarEntry(suite, "META-INF/libreprotect/lang/de.yml")));
        Properties builtIn = new Properties();
        builtIn.load(new StringReader(jarEntry(suite, "META-INF/libreprotect/lang/defaults.properties")));
        expected.retainAll(builtIn.stringPropertyNames());
        expected.remove(CUSTOMIZED_PHRASE);
        Set<String> cached = new TreeSet<>(phrases(saved));
        Set<String> lost = new TreeSet<>(expected);
        lost.removeAll(cached);
        suite.check(!expected.isEmpty() && cached.equals(expected), "de: every bundled German phrase but the "
            + "customized one is in the cache (" + cached.size() + " of " + expected.size() + ")"
            + (lost.isEmpty() ? "" : "; missing " + lost));
        String firstHelp = first.section("co help");
        suite.check(firstHelp.contains("----- LibreProtect Hilfe -----") && firstHelp.contains(CUSTOMIZED_TEXT),
            "de: /co help turns German as soon as the translation arrives, but keeps the customized phrase");
        FileTime savedAt = Files.exists(cache) ? Files.getLastModifiedTime(cache) : null;

        Harness.Run second = server.boot(Harness.Variant.FORK, Harness.Scenario.steps("translation"));
        checkRun(suite, "de, second boot", second);
        String help = second.section("co help");
        suite.check(help.contains("----- LibreProtect Hilfe -----") && help.contains("Blockdaten nachschlagen."),
            "de: the second boot's /co help is German from the cache");
        suite.check(help.contains(CUSTOMIZED_TEXT) && !help.contains("Zeigt den Plugin-Status an."),
            "de: the customized phrase stays as customized on the second boot");
        suite.check(savedAt != null && savedAt.equals(Files.getLastModifiedTime(cache)) && saved.equals(read(cache)),
            "de: the second boot kept the cache instead of translating again");
    }

    private static void passthrough(Harness.Suite suite) throws Exception {
        Harness.Server server = suite.newServer("passthrough");
        server.coreProtectConfig(coreProtectConfig("de"));
        server.libreProtectConfig("preset: passthrough\n");

        Harness.Run first = server.boot(Harness.Variant.FORK, Harness.Scenario.steps("translation"));
        checkRun(suite, "passthrough, first boot", first);
        checkAsked(suite, "passthrough, first boot", first);
        suite.check(read(server.coreProtectFolder().resolve(".language")).contains("\nHELP_HEADER: \"{0} Hilfe\"\n")
                && first.section("co help").contains("----- LibreProtect Hilfe -----"),
            "passthrough: without the service, the bundled German translation answers alone");

        // CoreProtect saves no cache when its request fails, so it asks again at its next start
        Harness.Run second = server.boot(Harness.Variant.FORK, Harness.Scenario.steps("translation"));
        checkRun(suite, "passthrough, second boot", second);
        suite.check(second.console().contains("[LibreProtect] Asking CoreProtect's translation service for "
            + "translations again, since it failed last time"), "passthrough: the next boot says it asks the "
            + "service again");
        checkAsked(suite, "passthrough, second boot", second);
        suite.check(second.section("co help").contains("----- LibreProtect Hilfe -----"),
            "passthrough: the next boot is German again");
    }

    /** Check that LibreProtect asked CoreProtect's translation service, and nothing else */
    private static void checkAsked(Harness.Suite suite, String name, Harness.Run run) {
        List<Harness.Egress> asked = run.pluginEgress().stream()
            .filter(egress -> egress.stack().contains("LayeredTranslationAnswer")).toList();
        boolean askedService = !asked.isEmpty() && asked.stream().allMatch(egress ->
            egress.target().equals("coreprotect.net") || egress.target().startsWith("coreprotect.net:"));
        suite.check(askedService, name + ": LibreProtect asked CoreProtect's translation service, which the test "
            + "blocks" + (askedService ? "" : "; it asked " + asked));
    }

    private static void notBundled(Harness.Suite suite) throws Exception {
        Harness.Server server = suite.newServer("nl");
        server.coreProtectConfig(coreProtectConfig("nl"));

        Harness.Run run = server.boot(Harness.Variant.FORK, Harness.Scenario.steps("translation")
            .set("translation.wait", "ticks").set("translation.wait.ticks", 200));
        checkRun(suite, "nl", run);
        suite.check(read(server.coreProtectFolder().resolve(".language")).isEmpty(),
            "nl: CoreProtect saved no translation cache");
        suite.check(run.section("co help").contains("----- LibreProtect Help -----"), "nl: /co help stays in English");
        int warnings = run.console().split("\\[LibreProtect\\] No bundled translation for 'nl'", -1).length - 1;
        suite.check(warnings == 1, "nl: LibreProtect explained once that nl isn't bundled"
            + (warnings == 1 ? "" : ", but " + warnings + " times"));
    }

    /** What every boot of this suite must do: run its step, make no network request, and exit cleanly */
    private static void checkRun(Harness.Suite suite, String name, Harness.Run run) {
        String error = run.result("translation.error");
        String timeout = run.result("translation.timeout");
        suite.check(error == null && timeout == null, name + ": the translation step ran"
            + (error != null ? ": " + error : "") + (timeout != null ? ": timed out waiting for the " + timeout : ""));
        if (!name.startsWith("passthrough")) {
            List<Harness.Egress> egress = run.pluginEgress();
            suite.check(egress.isEmpty(), name + ": no network requests" + (egress.isEmpty() ? "" : ": " + egress));
        }
        suite.check(!run.console().contains("\tat net.coreprotect.")
                && !run.console().contains("\tat net.deltik.mc.libreprotect."),
            name + ": no stack traces from CoreProtect or LibreProtect");
        suite.check(run.exitCode() == 0, name + ": the server exited cleanly (exit code " + run.exitCode() + ")");
    }

    /** @return the names of the phrases that a language file or cache gives a text, as CoreProtect reads it */
    private static List<String> phrases(String file) {
        return file.lines()
            .filter(line -> !line.startsWith("#") && line.indexOf(':') > 0)
            .filter(line -> !line.substring(line.indexOf(':') + 1).trim().matches("|\"\"|''"))
            .map(line -> line.substring(0, line.indexOf(':')).trim().toUpperCase(Locale.ROOT))
            .toList();
    }

    /** @return a text file from LibreProtect's JAR */
    private static String jarEntry(Harness.Suite suite, String name) throws IOException {
        try (ZipFile jar = new ZipFile(suite.jar(Harness.Variant.FORK).toFile())) {
            ZipEntry entry = jar.getEntry(name);
            if (entry == null) {
                throw new IOException("LibreProtect's JAR has no " + name);
            }
            return new String(jar.getInputStream(entry).readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /** @return the file's lines, each ending with a line break, or "" if there is no file */
    private static String read(Path file) throws IOException {
        if (!Files.exists(file)) {
            return "";
        }
        String text = Files.readString(file, StandardCharsets.UTF_8);
        return text.isEmpty() || text.endsWith("\n") ? text : text + "\n";
    }
}
