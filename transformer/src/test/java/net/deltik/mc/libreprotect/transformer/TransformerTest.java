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

package net.deltik.mc.libreprotect.transformer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TransformerTest {

    @TempDir
    Path directory;

    private TransformReport transform(SyntheticUpstream upstream, Path output) throws IOException {
        SyntheticUpstream.Jars jars = upstream.write(directory);
        Transformer.Options options = new Transformer.Options(
            jars.shaded(), jars.original(), TestClasses.runtimeJar(directory), jars.lang(), output,
            "24.1-libre1", "Privacy-hardened build of CoreProtect", "https://github.com/Deltik/LibreProtect",
            "v24.1", "0af209a0a05135216599113c0b5e2638ad3c704b", "abc1234", 1_700_000_000L,
            List.of("com/example/jdbc/"));
        Transformer transformer = new Transformer(options);
        TransformReport report = transformer.run();
        transformer.write(null);
        return report;
    }

    private ContractViolation violation(Consumer<SyntheticUpstream> change) {
        SyntheticUpstream upstream = new SyntheticUpstream();
        change.accept(upstream);
        return assertThrows(ContractViolation.class, () -> transform(upstream, directory.resolve("out.jar")));
    }

    private static ClassNode node(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    @Nested
    @DisplayName("A compatible upstream")
    class Compatible {

        @Test
        @DisplayName("is transformed as described in the report")
        void transforms() throws IOException {
            Path output = directory.resolve("out.jar");
            TransformReport report = transform(new SyntheticUpstream(), output);
            JarContents jar = JarContents.read(output);

            PluginYml pluginYml = new PluginYml(new String(jar.get("plugin.yml"), StandardCharsets.UTF_8));
            assertEquals("net.deltik.mc.libreprotect.LibreProtectPlugin", pluginYml.getString("main"));
            assertEquals("24.1-libre1", pluginYml.getString("version"));
            assertEquals("CoreProtect", pluginYml.getString("name"));
            assertEquals("libre", pluginYml.getString("branch"));

            ClassNode main = node(jar.get(SyntheticUpstream.MAIN + ".class"));
            assertEquals(0, main.access & Opcodes.ACC_FINAL, "main class is no longer final");
            ClassNode generated = node(jar.get(SubclassGenerator.CLASS_NAME + ".class"));
            assertEquals(SyntheticUpstream.MAIN, generated.superName);

            assertFalse(ClassScan.of(jar.get(SyntheticUpstream.NETWORK + ".class")).hasRawEgress());
            assertFalse(ClassScan.of(jar.get(SyntheticUpstream.BSTATS + ".class")).hasRawEgress(),
                "bundled libraries are rewritten too");
            assertTrue(ClassScan.of(jar.get(SyntheticUpstream.DRIVER + ".class")).hasRawEgress(),
                "exempt libraries are left alone");

            assertEquals(2, report.egressSites.size());
            assertTrue(report.egressSites.stream().anyMatch(site ->
                site.className().equals(SyntheticUpstream.NETWORK) && site.origin() == Origin.UPSTREAM));
            assertTrue(report.egressSites.stream().anyMatch(site ->
                site.className().equals(SyntheticUpstream.BSTATS) && site.origin() == Origin.LIBRARY));
            assertEquals(1, report.exemptLibraryClassCount);
            assertEquals(2, report.editionGates.size());
            assertEquals(List.of(new TransformReport.PluginVersionRead(SyntheticUpstream.VERSION_UTILS + ".class",
                SyntheticUpstream.VERSION_UTILS, "getPluginVersion()Ljava/lang/String;", "24.1")),
                report.pluginVersionReads);
            TestClasses.verify(jar.get(SyntheticUpstream.VERSION_UTILS + ".class"), false);
            assertEquals(2, report.extensionPoints.size());

            assertEquals(List.of(SyntheticUpstream.PHRASE + ".build(L" + SyntheticUpstream.PHRASE
                + ";[Ljava/lang/String;)Ljava/lang/String;"), report.phraseRenderers);
            assertEquals(1, report.countBranding(BrandingRewriter.KIND_PHRASE));
            assertEquals(1, report.countBranding(BrandingRewriter.KIND_OUTPUT));
            assertEquals(List.of("LibreProtect - "), report.brandingSites.stream()
                .filter(site -> site.kind().equals(BrandingRewriter.KIND_TEXT)).map(TransformReport.BrandingSite::after)
                .toList());
            TestClasses.verify(jar.get(SyntheticUpstream.CHAT + ".class"), false);

            assertTrue(jar.contains("net/deltik/mc/libreprotect/Egress.class"));
            assertTrue(jar.contains("net/coreprotect/utility/extensions/DatabaseMigration.class"));
            assertTrue(jar.contains("META-INF/libreprotect/DIFFERENCES.md"));
            assertEquals("fork.version=24.1-libre1\nfork.commit=abc1234\nupstream.ref=v24.1\n"
                    + "upstream.commit=0af209a0a05135216599113c0b5e2638ad3c704b\nupstream.version=24.1\n",
                new String(jar.get("libreprotect-build.properties"), StandardCharsets.UTF_8));
            assertEquals(JarContents.MANIFEST, jar.names().get(0), "manifest must come first");
        }

        @Test
        @DisplayName("keeps upstream's exact bytes for classes with nothing to change")
        void keepsUntouchedClasses() throws IOException {
            SyntheticUpstream upstream = new SyntheticUpstream();
            Path output = directory.resolve("out.jar");
            transform(upstream, output);
            assertArrayEquals(SyntheticUpstream.plainClass(SyntheticUpstream.PLAIN),
                JarContents.read(output).get(SyntheticUpstream.PLAIN + ".class"));
        }

        @Test
        @DisplayName("produces byte-identical output from the same input")
        void reproducible() throws IOException {
            Path first = directory.resolve("first.jar");
            Path second = directory.resolve("second.jar");
            transform(new SyntheticUpstream(), first);
            transform(new SyntheticUpstream(), second);
            assertArrayEquals(Files.readAllBytes(first), Files.readAllBytes(second));
        }

        @Test
        @DisplayName("records, without failing, an extension point that upstream dropped")
        void extensionDropped() throws IOException {
            SyntheticUpstream upstream = new SyntheticUpstream();
            upstream.extensionStrings.remove("net.coreprotect.utility.extensions.BackgroundService");
            TransformReport report = transform(upstream, directory.resolve("out.jar"));
            assertEquals(List.of("net.coreprotect.utility.extensions.BackgroundService"), report.unrequestedExtensions);
        }

        @Test
        @DisplayName("records, without failing, an extension method that upstream renamed")
        void extensionMethodRenamed() throws IOException {
            SyntheticUpstream upstream = new SyntheticUpstream();
            upstream.extensionStrings.remove("stop");
            upstream.extensionStrings.add("shutdown");
            TransformReport report = transform(upstream, directory.resolve("out.jar"));
            assertEquals(List.of("net.coreprotect.utility.extensions.BackgroundService#stop"),
                report.unrequestedExtensions);
        }

        @Test
        @DisplayName("bundles upstream's translations unchanged and reports what each translates")
        void translations() throws IOException {
            SyntheticUpstream upstream = new SyntheticUpstream();
            upstream.lang.put("zh_CN.yml", "HELP_HEADER: \"{0} 帮助\"\nNO_PERMISSION: \"\"\nOBSOLETE: \"x\"\n");
            upstream.lang.put("README.md", "Not a language file");
            Path output = directory.resolve("out.jar");
            TransformReport report = transform(upstream, output);
            JarContents jar = JarContents.read(output);

            for (String file : List.of("de", "en", "zh_CN")) {
                String entry = "META-INF/libreprotect/lang/" + file.toLowerCase(Locale.ROOT).replace('_', '-') + ".yml";
                assertArrayEquals(upstream.lang.get(file + ".yml").getBytes(StandardCharsets.UTF_8), jar.get(entry),
                    entry);
                assertTrue(report.injectedEntries.contains(entry), entry);
            }
            assertEquals(List.of(), jar.names().stream().filter(name -> name.contains("README")).toList());

            assertEquals(3, report.phraseCount);
            assertEquals(List.of(
                new TransformReport.Translation("de", 2, List.of("NO_PERMISSION"), List.of()),
                new TransformReport.Translation("en", 3, List.of(), List.of()),
                new TransformReport.Translation("zh-cn", 1, List.of("LINK_DOWNLOAD", "NO_PERMISSION"),
                    List.of("OBSOLETE"))), report.translations);

            String differences = new String(jar.get("META-INF/libreprotect/DIFFERENCES.md"), StandardCharsets.UTF_8);
            assertTrue(differences.contains("## Translations"), differences);
            assertTrue(differences.contains("Of CoreProtect's 3 phrases"), differences);
            assertTrue(differences.contains("| `de` | 2 | 1 |\n| `en` | 3 | 0 |\n| `zh-cn` | 1 | 2 |\n"), differences);
            assertTrue(differences.contains("never used: `zh-cn`: `OBSOLETE`"), differences);
            assertFalse(differences.contains("differs from the built-in English"), differences);
            assertTrue(report.injectedEntries.contains(Translations.DEFAULTS));
        }

        @Test
        @DisplayName("bundles the built-in English from upstream's code, exactly, and reports where en.yml differs")
        void builtInEnglish() throws IOException {
            SyntheticUpstream upstream = new SyntheticUpstream();
            upstream.defaults.set(0, Map.entry("HELP_HEADER", " {0} \"Help\" \\ C:\\path\n\ttab ü ☃ 😀 # = : !"));
            for (int i = 1; i <= 8; i++) {
                upstream.phrases.add("EXTRA_" + i);
                upstream.defaults.add(Map.entry("EXTRA_" + i, "Extra " + i));
            }
            upstream.phrases.add("COMPUTED");
            Path output = directory.resolve("out.jar");
            TransformReport report = transform(upstream, output);

            Properties bundled = new Properties();
            bundled.load(new InputStreamReader(new ByteArrayInputStream(JarContents.read(output)
                .get(Translations.DEFAULTS)), StandardCharsets.UTF_8));
            Map<String, String> expected = new TreeMap<>();
            upstream.defaults.forEach(phrase -> expected.put(phrase.getKey(), phrase.getValue()));
            Map<String, String> actual = new TreeMap<>();
            bundled.stringPropertyNames().forEach(name -> actual.put(name, bundled.getProperty(name)));
            assertEquals(expected, actual);

            assertEquals(List.of("COMPUTED"), report.phrasesWithoutDefault);
            assertEquals(List.of("HELP_HEADER"), report.englishDifferences);
            String differences = Differences.render(report);
            assertTrue(differences.contains("no plain English text for `COMPUTED`, so these phrases stay in English"),
                differences);
            assertTrue(differences.contains("`en.yml` differs from the built-in English for `HELP_HEADER`"),
                differences);
        }

        @Test
        @DisplayName("keeps any built-in English exactly in defaults.properties")
        void defaultsFileEscaping() throws IOException {
            String[] values = {"", " ", "  lead", "\tlead", "\flead", "trail  ", "=x", ":x", "#x", "!x", "a=b:c",
                "back\\slash", "\\", "end\\", "\\u0041", "\\n", "new\nline", "cr\rx", "\u0000\u0001\u001f\u007f",
                "\u0085  ", "Déjà ≈ 😀 下载：", "{0} {block|blocks}", "\"quoted\"", "'single'", " \\ ", "x\\\ny"};
            Map<String, String> tricky = new TreeMap<>();
            for (int i = 0; i < values.length; i++) {
                tricky.put("P" + i, values[i]);
            }
            assertEquals(tricky, loadProperties(Translations.defaultsFile(tricky)));
        }

        @Test
        @DisplayName("rewrites multi-release copies of classes")
        void multiRelease() throws IOException {
            SyntheticUpstream upstream = new SyntheticUpstream();
            upstream.libraries.put("META-INF/versions/17/" + SyntheticUpstream.BSTATS + ".class",
                SyntheticUpstream.classWithEgress(SyntheticUpstream.BSTATS));
            Path output = directory.resolve("out.jar");
            transform(upstream, output);
            assertFalse(ClassScan.of(JarContents.read(output)
                .get("META-INF/versions/17/" + SyntheticUpstream.BSTATS + ".class")).hasRawEgress());
        }
    }

    /**
     * Checks on the upstream that {@code scripts/lp build} builds, whose JAR
     * it passes as {@code -Dupstream.jar}, next to upstream's {@code lang/}.
     */
    @Nested
    @DisplayName("The upstream that scripts/lp builds")
    @EnabledIfSystemProperty(named = "upstream.jar", matches = ".+")
    class RealUpstream {

        @Test
        @DisplayName("has built-in English for every phrase, so every bundled translation can be answered")
        void builtInEnglish() throws IOException {
            Path jar = Path.of(System.getProperty("upstream.jar"));
            JarContents upstream = JarContents.read(jar);
            Set<String> phraseEnums = new TreeSet<>();
            for (String name : upstream.names()) {
                if (JarContents.isClass(name) && name.startsWith("net/coreprotect/") && !JarContents.isVersioned(name)) {
                    BrandingRules.phraseRenderers(upstream.get(name))
                        .forEach(renderer -> phraseEnums.add(renderer.substring(0, renderer.indexOf('.'))));
                }
            }
            Set<String> phrases = Translations.phrases(upstream, phraseEnums);

            Map<String, String> defaults = Translations.defaults(upstream, phraseEnums, phrases);
            assertEquals(phrases, defaults.keySet());
            List<TransformReport.Translation> translations = new ArrayList<>();
            Translations.read(jar.getParent().getParent().resolve("lang"), phrases, translations);
            assertTrue(translations.size() > 1, translations::toString);
        }

        @Test
        @DisplayName("has exactly the built-in English of its source, and defaults.properties keeps it")
        void builtInEnglishMatchesSource() throws IOException {
            Path jar = Path.of(System.getProperty("upstream.jar"));
            Path source = jar.getParent().getParent().resolve("src/main/java/net/coreprotect/language/Language.java");
            Map<String, String> expected = new TreeMap<>();
            Matcher put = Pattern.compile("phrases\\.put\\(Phrase\\.(\\w+),\\s*\"((?:[^\"\\\\]|\\\\.)*)\"\\);")
                .matcher(Files.readString(source));
            while (put.find()) {
                expected.put(put.group(1), put.group(2).replaceAll("\\\\(.)", "$1"));
            }

            JarContents upstream = JarContents.read(jar);
            Set<String> phraseEnums = Set.of("net/coreprotect/language/Phrase");
            Map<String, String> extracted = Translations.defaults(upstream, phraseEnums,
                Translations.phrases(upstream, phraseEnums));

            assertEquals(expected, extracted);
            assertEquals(expected, loadProperties(Translations.defaultsFile(extracted)));
        }
    }

    private static Map<String, String> loadProperties(byte[] file) throws IOException {
        Properties properties = new Properties();
        properties.load(new InputStreamReader(new ByteArrayInputStream(file), StandardCharsets.UTF_8));
        Map<String, String> loaded = new TreeMap<>();
        properties.stringPropertyNames().forEach(name -> loaded.put(name, properties.getProperty(name)));
        return loaded;
    }

    @Nested
    @DisplayName("An upstream change that breaks an assumption")
    class Incompatible {

        @Test
        @DisplayName("sealed main class")
        void sealedMain() {
            assertTrue(violation(upstream -> upstream.mainSealed = true).getMessage().contains("sealed"));
        }

        @Test
        @DisplayName("final onEnable")
        void finalOnEnable() {
            assertTrue(violation(upstream -> upstream.onEnableFinal = true).getMessage().contains("onEnable"));
        }

        @Test
        @DisplayName("renamed edition check")
        void missingGate() {
            String message = violation(upstream -> upstream.gates.remove("isCommunityEdition")).getMessage();
            assertTrue(message.contains("isCommunityEdition"), message);
        }

        @Test
        @DisplayName("duplicated edition check")
        void duplicateGate() {
            String message = violation(upstream -> upstream.upstreamExtra.put("net/coreprotect/Other.class",
                SyntheticUpstream.gateClass("net/coreprotect/Other", List.of("validDonationKey")))).getMessage();
            assertTrue(message.contains("found 2"), message);
        }

        @Test
        @DisplayName("shows in DIFFERENCES.md which version CoreProtect compares")
        void pluginVersion() throws IOException {
            String differences = Differences.render(transform(new SyntheticUpstream(), directory.resolve("out.jar")));

            assertTrue(differences.contains("## CoreProtect's Own Version\n\n"), differences);
            assertTrue(differences.contains("It now compares the version that upstream's build gave it, `24.1`,"),
                differences);
            assertTrue(differences.contains("| `net.coreprotect.utility.VersionUtils` | `getPluginVersion()` | `24.1` |\n"),
                differences);
        }

        @Test
        @DisplayName("own version read some other way")
        void noPluginVersionRead() {
            String message = violation(upstream -> upstream.pluginVersion = false).getMessage();
            assertTrue(message.contains("getPluginVersion") && message.contains("found 0"), message);
        }

        @Test
        @DisplayName("own version read in two places")
        void duplicatePluginVersionRead() {
            String message = violation(upstream -> upstream.upstreamExtra.put("net/coreprotect/Other.class",
                SyntheticUpstream.gateClass("net/coreprotect/Other", List.of(), true))).getMessage();
            assertTrue(message.contains("getPluginVersion") && message.contains("found 2"), message);
        }

        @Test
        @DisplayName("no version in plugin.yml")
        void noPluginYmlVersion() {
            String message = violation(upstream -> upstream.pluginYml = upstream.pluginYml
                .replace("version: 24.1\n", "version: ${project.version}\n")).getMessage();
            assertTrue(message.contains("plugin.yml version is '${project.version}'"), message);
        }

        @Test
        @DisplayName("no URL connections left to redirect")
        void noEgress() {
            String message = violation(upstream -> {
                upstream.networkEgress = false;
                upstream.libraries.clear();
            }).getMessage();
            assertTrue(message.contains("no java.net.URL connection calls"), message);
        }

        @Test
        @DisplayName("no phrase renderer")
        void noPhraseRenderer() {
            String message = violation(upstream -> upstream.phraseRenderer = false).getMessage();
            assertTrue(message.contains("phrase renderer"), message);
        }

        @Test
        @DisplayName("messages printed some other way")
        void noMessageOutput() {
            String message = violation(upstream -> upstream.messageOutput = false).getMessage();
            assertTrue(message.contains("sendMessage"), message);
        }

        @Test
        @DisplayName("missing branch")
        void missingBranch() {
            String message = violation(upstream ->
                upstream.pluginYml = upstream.pluginYml.replace("branch: libre", "branch: ${project.branch}")).getMessage();
            assertTrue(message.contains("branch"), message);
        }

        @Test
        @DisplayName("renamed plugin")
        void renamedPlugin() {
            String message = violation(upstream ->
                upstream.pluginYml = upstream.pluginYml.replace("name: CoreProtect", "name: CoreProtectPlus")).getMessage();
            assertTrue(message.contains("CoreProtectPlus"), message);
        }

        @Test
        @DisplayName("paper-plugin.yml")
        void paperPluginYml() {
            String message = violation(upstream ->
                upstream.upstreamExtra.put("paper-plugin.yml", "name: CoreProtect\n".getBytes(StandardCharsets.UTF_8)))
                .getMessage();
            assertTrue(message.contains("paper-plugin.yml"), message);
        }

        @Test
        @DisplayName("no language directory")
        void noLanguageDirectory() {
            String message = violation(upstream -> upstream.lang.clear()).getMessage();
            assertTrue(message.contains("lang doesn't exist"), message);
        }

        @Test
        @DisplayName("no language files")
        void noLanguageFiles() {
            String message = violation(upstream -> {
                upstream.lang.clear();
                upstream.lang.put("README.md", "Translations moved elsewhere");
            }).getMessage();
            assertTrue(message.contains("has no *.yml files"), message);
        }

        @Test
        @DisplayName("no English language file")
        void noEnglish() {
            String message = violation(upstream -> upstream.lang.remove("en.yml")).getMessage();
            assertTrue(message.contains("has no en.yml"), message);
        }

        @Test
        @DisplayName("language file in another format")
        void languageFormat() {
            String message = violation(upstream -> upstream.lang.put("fr.yml", "phrases:\n  - aide\n")).getMessage();
            assertTrue(message.contains("fr.yml translates none of the 3 phrases"), message);
        }

        @Test
        @DisplayName("language file not named like a language")
        void languageFileName() {
            String message = violation(upstream -> upstream.lang.put("de.old.yml", "HELP_HEADER: \"x\"\n"))
                .getMessage();
            assertTrue(message.contains("de.old.yml isn't named like a language code"), message);
        }

        @Test
        @DisplayName("two language files for one language")
        void languageTwice() {
            String message = violation(upstream -> upstream.lang.put("DE.yml", "HELP_HEADER: \"x\"\n")).getMessage();
            assertTrue(message.contains("two language files for 'de'"), message);
        }

        @Test
        @DisplayName("no built-in English in upstream's code")
        void noBuiltInEnglish() {
            String message = violation(upstream -> upstream.defaults.clear()).getMessage();
            assertTrue(message.contains("Found built-in English in upstream's code for 0 of its 3 phrases"), message);
        }

        @Test
        @DisplayName("built-in English for too few phrases")
        void tooLittleBuiltInEnglish() {
            String message = violation(upstream -> upstream.defaults.remove(2)).getMessage();
            assertTrue(message.contains("for 2 of its 3 phrases"), message);
        }

        @Test
        @DisplayName("two built-in texts for one phrase")
        void conflictingBuiltInEnglish() {
            String message = violation(upstream -> upstream.defaults.add(Map.entry("HELP_HEADER", "{0} Manual")))
                .getMessage();
            assertTrue(message.contains("gives the phrase HELP_HEADER two built-in texts"), message);
        }

        @Test
        @DisplayName("translation cache renamed")
        void cacheRenamed() {
            String message = violation(upstream -> upstream.languageCache = ".translations").getMessage();
            assertTrue(message.contains("no longer names its translation cache '.language'"), message);
        }

        @Test
        @DisplayName("upstream ships a translation LibreProtect would overwrite")
        void translationCollision() {
            String message = violation(upstream -> upstream.upstreamExtra.put("META-INF/libreprotect/lang/de.yml",
                new byte[0])).getMessage();
            assertTrue(message.contains("META-INF/libreprotect/lang/de.yml would overwrite"), message);
        }

        @Test
        @DisplayName("upstream ships a class LibreProtect would overwrite")
        void collision() {
            String message = violation(upstream -> upstream.upstreamExtra.put(
                "net/deltik/mc/libreprotect/Egress.class",
                SyntheticUpstream.plainClass("net/deltik/mc/libreprotect/Egress"))).getMessage();
            assertTrue(message.contains("Egress"), message);
        }
    }
}
