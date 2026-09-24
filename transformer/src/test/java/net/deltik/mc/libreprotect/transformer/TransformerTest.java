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
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;

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
            jars.shaded(), jars.original(), TestClasses.runtimeJar(directory), output,
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
        @DisplayName("upstream ships a class LibreProtect would overwrite")
        void collision() {
            String message = violation(upstream -> upstream.upstreamExtra.put(
                "net/deltik/mc/libreprotect/Egress.class",
                SyntheticUpstream.plainClass("net/deltik/mc/libreprotect/Egress"))).getMessage();
            assertTrue(message.contains("Egress"), message);
        }
    }
}
