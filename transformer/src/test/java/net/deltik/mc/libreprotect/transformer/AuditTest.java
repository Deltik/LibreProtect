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

import net.deltik.mc.libreprotect.transformer.AuditReport.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditTest {

    private static final String POM = """
        <project>
          <modelVersion>4.0.0</modelVersion>
          <groupId>net.coreprotect</groupId>
          <artifactId>CoreProtect</artifactId>
          <version>24.1</version>
          <repositories>
            <repository><id>papermc</id><url>https://repo.papermc.io/repository/maven-public/</url></repository>
          </repositories>
          <dependencies>
            <dependency><groupId>org.bstats</groupId><artifactId>bstats-bukkit</artifactId><version>3.2.1</version></dependency>
          </dependencies>
          <build><plugins><plugin><artifactId>maven-shade-plugin</artifactId></plugin></plugins></build>
        </project>
        """;

    @TempDir
    Path directory;
    Path upstreamDirectory;

    @BeforeEach
    void writeUpstreamSources() throws IOException {
        upstreamDirectory = Files.createDirectories(directory.resolve("upstream"));
        Files.writeString(upstreamDirectory.resolve("pom.xml"), POM);
        Files.writeString(upstreamDirectory.resolve("LICENSE"), "The Artistic License 2.0\n");
    }

    private AuditReport audit(Consumer<SyntheticUpstream> change, AuditBaseline baseline) throws Exception {
        return audit(change, extensions -> { }, baseline);
    }

    private AuditReport audit(Consumer<SyntheticUpstream> change, Consumer<SyntheticExtensions> extensionsChange,
                              AuditBaseline baseline) throws Exception {
        SyntheticUpstream upstream = new SyntheticUpstream();
        change.accept(upstream);
        SyntheticExtensions extensions = new SyntheticExtensions();
        extensionsChange.accept(extensions);
        SyntheticUpstream.Jars jars = upstream.write(directory);
        Transformer transformer = new Transformer(new Transformer.Options(
            jars.shaded(), jars.original(), TestClasses.runtimeJar(directory), extensions.write(directory),
            extensions.writeReport(directory, jars.shaded()), jars.source(), jars.lang(), directory.resolve("out.jar"),
            "24.1-libre1", "description", "https://example.invalid", "v24.1", "0000000", "0000000", 0L,
            List.copyOf(baseline.egressExemptPrefixes)));
        TransformReport report = transformer.run();
        return new Audit(transformer.upstream(), transformer.origins(), report, upstreamDirectory, baseline).run();
    }

    /** @return a baseline that accepts the unchanged synthetic upstream */
    private AuditBaseline cleanBaseline() throws Exception {
        AuditBaseline exempt = new AuditBaseline();
        exempt.egressExemptPrefixes.add("com/example/jdbc/");
        AuditReport first = audit(upstream -> { }, exempt);
        return first.observed;
    }

    private static boolean has(AuditReport report, Severity severity, String rule, String siteFragment) {
        return report.findings.stream().anyMatch(finding -> finding.severity() == severity
            && finding.rule().equals(rule) && finding.site().contains(siteFragment));
    }

    private static byte[] method(String className, Consumer<MethodVisitor> body) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, className, null, "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
        method.visitCode();
        body.accept(method);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] socketClass(String className) {
        return method(className, code -> {
            code.visitTypeInsn(Opcodes.NEW, "java/net/Socket");
            code.visitInsn(Opcodes.DUP);
            code.visitLdcInsn("example.com");
            code.visitIntInsn(Opcodes.SIPUSH, 80);
            code.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/net/Socket", "<init>", "(Ljava/lang/String;I)V", false);
            code.visitInsn(Opcodes.POP);
        });
    }

    private static byte[] forNameClass(String className, String target) {
        return method(className, code -> {
            code.visitLdcInsn(target);
            code.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;", false);
            code.visitInsn(Opcodes.POP);
        });
    }

    private static byte[] stringClass(String className, String value) {
        return method(className, code -> {
            code.visitLdcInsn(value);
            code.visitInsn(Opcodes.POP);
        });
    }

    @Test
    @DisplayName("an upstream that matches the baseline needs no review")
    void clean() throws Exception {
        AuditBaseline baseline = cleanBaseline();
        AuditReport report = audit(upstream -> { }, baseline);
        assertFalse(report.failed, report.findings.toString());
        assertFalse(report.reviewRequired, report.findings.toString());
    }

    @Test
    @DisplayName("never asks about the reviewed upstream JARs, whichever upstream it audits, and carries them over")
    void reviewedUpstreams() throws Exception {
        AuditBaseline baseline = cleanBaseline();
        baseline.reviewedUpstreams.add("0".repeat(64));

        AuditReport report = audit(upstream -> { }, baseline);

        assertFalse(report.reviewRequired, report.findings.toString());
        assertTrue(report.findings.stream().noneMatch(finding -> finding.site().contains("0".repeat(64))),
            report.findings::toString);
        assertEquals(baseline.reviewedUpstreams, report.observed.reviewedUpstreams);
    }

    @Nested
    @DisplayName("FAIL")
    class Fail {

        @Test
        @DisplayName("upstream opens a socket directly")
        void socket() throws Exception {
            AuditReport report = audit(upstream -> upstream.upstreamExtra.put("net/coreprotect/Beacon.class",
                socketClass("net/coreprotect/Beacon")), cleanBaseline());
            assertTrue(report.failed);
            assertTrue(has(report, Severity.FAIL, Audit.RULE_NETWORK, "net/coreprotect/Beacon#run()V"));
        }

        @Test
        @DisplayName("a bundled library opens a socket directly")
        void librarySocket() throws Exception {
            AuditReport report = audit(upstream -> upstream.libraries.put("org/tracker/Client.class",
                socketClass("org/tracker/Client")), cleanBaseline());
            assertTrue(has(report, Severity.FAIL, Audit.RULE_NETWORK, "org/tracker/Client#run()V"));
            assertTrue(has(report, Severity.REVIEW, "new-library-package", "org/tracker/"));
        }

        @Test
        @DisplayName("upstream reflectively looks up URL.openConnection")
        void reflectiveEgress() throws Exception {
            byte[] reflective = method("net/coreprotect/Sneaky", code -> {
                code.visitLdcInsn(Type.getObjectType("java/net/URL"));
                code.visitLdcInsn("openConnection");
                code.visitInsn(Opcodes.ICONST_0);
                code.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
                code.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                    "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
                code.visitInsn(Opcodes.POP);
            });
            AuditReport report = audit(upstream -> upstream.upstreamExtra.put("net/coreprotect/Sneaky.class",
                reflective), cleanBaseline());
            assertTrue(has(report, Severity.FAIL, Audit.RULE_REFLECTION_NETWORK, "net/coreprotect/Sneaky"));
        }

        @Test
        @DisplayName("upstream loads a network class by name")
        void forNameNetwork() throws Exception {
            AuditReport report = audit(upstream -> upstream.upstreamExtra.put("net/coreprotect/Loader.class",
                forNameClass("net/coreprotect/Loader", "java.net.http.HttpClient")), cleanBaseline());
            assertTrue(has(report, Severity.FAIL, Audit.RULE_REFLECTION_NETWORK, "net/coreprotect/Loader"));
        }

        @Test
        @DisplayName("an allowance downgrades exactly its site to INFO")
        void allowance() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            baseline.allow.add(new AuditBaseline.Allowance(Audit.RULE_NETWORK, "net/coreprotect/Beacon#run()V", "test"));
            AuditReport report = audit(upstream -> {
                upstream.upstreamExtra.put("net/coreprotect/Beacon.class", socketClass("net/coreprotect/Beacon"));
                upstream.upstreamExtra.put("net/coreprotect/Other.class", socketClass("net/coreprotect/Other"));
            }, baseline);
            assertTrue(has(report, Severity.INFO, Audit.RULE_NETWORK, "net/coreprotect/Beacon#run()V"));
            assertTrue(has(report, Severity.FAIL, Audit.RULE_NETWORK, "net/coreprotect/Other#run()V"));
        }

        @Test
        @DisplayName("an exempt library is inventoried but not failed")
        void exemptLibrary() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            baseline.egressExemptPrefixes.add("org/database/");
            AuditReport report = audit(upstream -> {
                upstream.libraries.put("org/database/Driver.class", socketClass("org/database/Driver"));
                upstream.libraries.put("org/database/net/Transport.class", socketClass("org/database/net/Transport"));
            }, baseline);
            assertFalse(report.failed, report.findings.toString());
            assertTrue(has(report, Severity.REVIEW, "new-library-package", "org/database/"));
            assertTrue(report.observed.libraryPackages.contains("org/database/"));
            assertFalse(report.observed.libraryPackages.contains("org/database/net/"),
                "an exempt library is inventoried by its prefix, not package by package");
        }
    }

    @Nested
    @DisplayName("REVIEW")
    class Review {

        @Test
        @DisplayName("a new closed-source extension point")
        void newExtensionPoint() throws Exception {
            AuditReport report = audit(upstream -> upstream.upstreamExtra.put("net/coreprotect/Ext.class",
                forNameClass("net/coreprotect/Ext", "net.coreprotect.utility.extensions.NewThing")), cleanBaseline());
            assertFalse(report.failed);
            assertTrue(has(report, Severity.REVIEW, "new-extension-point", "NewThing"));
        }

        @Test
        @DisplayName("a new host")
        void newHost() throws Exception {
            AuditReport report = audit(upstream -> upstream.upstreamExtra.put("net/coreprotect/Phone.class",
                stringClass("net/coreprotect/Phone", "https://telemetry.example/collect?id=")), cleanBaseline());
            assertTrue(has(report, Severity.REVIEW, "new-host", "telemetry.example"));
        }

        @Test
        @DisplayName("a new read of a plugin's version, which the transformer doesn't have read upstream's")
        void newVersionRead() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            assertEquals(Set.of(SyntheticUpstream.VERSION_UTILS + "#getPluginVersion()Ljava/lang/String;"),
                baseline.versionReads, "the read that the transformer rewrites is inventoried too");

            AuditReport report = audit(upstream -> upstream.upstreamExtra.put("net/coreprotect/Compare.class",
                method("net/coreprotect/Compare", code -> {
                    code.visitInsn(Opcodes.ACONST_NULL);
                    code.visitTypeInsn(Opcodes.CHECKCAST, "org/bukkit/plugin/PluginDescriptionFile");
                    code.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "org/bukkit/plugin/PluginDescriptionFile",
                        "getVersion", "()Ljava/lang/String;", false);
                    code.visitInsn(Opcodes.POP);
                })), baseline);

            assertFalse(report.failed);
            assertTrue(has(report, Severity.REVIEW, "version-read", "net/coreprotect/Compare#run()V"),
                report.findings::toString);
            assertFalse(has(report, Severity.REVIEW, "version-read", SyntheticUpstream.VERSION_UTILS));
        }

        @Test
        @DisplayName("a new read of a plugin's full name, which ends in its version")
        void newFullNameRead() throws Exception {
            AuditReport report = audit(upstream -> upstream.upstreamExtra.put("net/coreprotect/Name.class",
                method("net/coreprotect/Name", code -> {
                    code.visitInsn(Opcodes.ACONST_NULL);
                    code.visitTypeInsn(Opcodes.CHECKCAST, "org/bukkit/plugin/PluginDescriptionFile");
                    code.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "org/bukkit/plugin/PluginDescriptionFile",
                        "getFullName", "()Ljava/lang/String;", false);
                    code.visitInsn(Opcodes.POP);
                })), cleanBaseline());

            assertTrue(has(report, Severity.REVIEW, "version-read", "net/coreprotect/Name#run()V"),
                report.findings::toString);
        }

        @Test
        @DisplayName("new code that reads plugin.yml itself, which has the version, as with YamlConfiguration")
        void newPluginYmlRead() throws Exception {
            AuditReport report = audit(upstream -> upstream.upstreamExtra.put("net/coreprotect/Yaml.class",
                stringClass("net/coreprotect/Yaml", "/plugin.yml")), cleanBaseline());

            assertTrue(has(report, Severity.REVIEW, "version-read", "net/coreprotect/Yaml#run()V"),
                report.findings::toString);
        }

        @Test
        @DisplayName("upstream mentions LibreProtect")
        void forkDetection() throws Exception {
            AuditReport report = audit(upstream -> upstream.upstreamExtra.put("net/coreprotect/Check.class",
                stringClass("net/coreprotect/Check", "net.deltik.mc.libreprotect.Egress")), cleanBaseline());
            assertTrue(has(report, Severity.REVIEW, Audit.RULE_FORK_DETECTION, "net/coreprotect/Check"));
        }

        @Test
        @DisplayName("an obfuscated class name")
        void obfuscatedName() throws Exception {
            AuditReport report = audit(upstream -> upstream.upstreamExtra.put("net/coreprotect/a.class",
                SyntheticUpstream.plainClass("net/coreprotect/a")), cleanBaseline());
            assertTrue(has(report, Severity.REVIEW, Audit.RULE_OBFUSCATION, "net/coreprotect/a"));
        }

        @Test
        @DisplayName("a class name computed at run time")
        void dynamicClassLoading() throws Exception {
            byte[] dynamic = method("net/coreprotect/Dyn", code -> {
                code.visitLdcInsn("net.coreprotect.");
                code.visitLdcInsn("X");
                code.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "concat",
                    "(Ljava/lang/String;)Ljava/lang/String;", false);
                code.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                    "(Ljava/lang/String;)Ljava/lang/Class;", false);
                code.visitInsn(Opcodes.POP);
            });
            AuditReport report = audit(upstream -> upstream.upstreamExtra.put("net/coreprotect/Dyn.class", dynamic),
                cleanBaseline());
            assertTrue(has(report, Severity.REVIEW, Audit.RULE_DYNAMIC_CLASS, "net/coreprotect/Dyn"));
        }

        @Test
        @DisplayName("a new Maven repository")
        void repository() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            Files.writeString(upstreamDirectory.resolve("pom.xml"), POM.replace("</repositories>",
                "<repository><id>x</id><url>https://repo.example/</url></repository></repositories>"));
            AuditReport report = audit(upstream -> { }, baseline);
            assertTrue(has(report, Severity.REVIEW, "repository-change", "https://repo.example/"));
        }

        @Test
        @DisplayName("an extension point that upstream stopped loading")
        void unrequestedExtension() throws Exception {
            AuditReport report = audit(upstream ->
                upstream.extensionStrings.remove("net.coreprotect.utility.extensions.BackgroundService"), cleanBaseline());
            assertFalse(report.failed);
            assertTrue(has(report, Severity.REVIEW, "extension-not-requested", "BackgroundService"));
        }

        @Test
        @DisplayName("a pom with a DOCTYPE is rejected rather than parsed")
        void pomDoctype() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            Files.writeString(upstreamDirectory.resolve("pom.xml"),
                "<?xml version=\"1.0\"?><!DOCTYPE project [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>" + POM);
            Exception thrown = org.junit.jupiter.api.Assertions.assertThrows(Exception.class,
                () -> audit(upstream -> { }, baseline));
            assertTrue(thrown.getMessage().contains("DOCTYPE"), thrown.getMessage());
        }
    }

    @Nested
    @DisplayName("FAIL on a change to upstream's license")
    class License {

        private static final String HEADER = """
            /*
             * Copyright (C) 2024 Intelli
             * All rights reserved.
             */
            package net.coreprotect;

            """;

        private void write(String path, String content) throws IOException {
            Path file = upstreamDirectory.resolve(path);
            Files.createDirectories(file.getParent());
            Files.writeString(file, content);
        }

        private static boolean fails(AuditReport report, String site, String detailFragment) {
            return report.findings.stream().anyMatch(finding -> finding.severity() == Severity.FAIL
                && finding.rule().equals(Audit.RULE_LICENSE) && finding.site().equals(site)
                && finding.detail().contains(detailFragment));
        }

        private static String sha256(String text) throws Exception {
            return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        }

        @Test
        @DisplayName("a changed LICENSE")
        void changed() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            Files.writeString(upstreamDirectory.resolve("LICENSE"), "All rights reserved\n");
            AuditReport report = audit(upstream -> { }, baseline);
            assertTrue(report.failed, report.findings.toString());
            assertTrue(fails(report, "LICENSE", "license file changed from "
                + sha256("The Artistic License 2.0\n") + " to " + sha256("All rights reserved\n")));
        }

        @Test
        @DisplayName("an upstream without a license file at its root")
        void deleted() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            Files.delete(upstreamDirectory.resolve("LICENSE"));
            AuditReport report = audit(upstream -> { }, baseline);
            assertTrue(fails(report, "LICENSE", "at its root"));
        }

        @Test
        @DisplayName("a LICENSE renamed, even with the same text, but not as a missing license")
        void renamed() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            Files.move(upstreamDirectory.resolve("LICENSE"), upstreamDirectory.resolve("LICENSE.md"));
            AuditReport report = audit(upstream -> { }, baseline);
            assertTrue(fails(report, "LICENSE.md", "new license file"));
            assertFalse(fails(report, "LICENSE", "at its root"));
        }

        @Test
        @DisplayName("a LICENSE replaced by other license files, which don't license the whole of upstream")
        void rootReplaced() throws Exception {
            write("LICENSES/CC0-1.0.txt", "CC0\n");
            AuditBaseline baseline = cleanBaseline();
            Files.delete(upstreamDirectory.resolve("LICENSE"));
            write("license-header.txt", "Copyright Intelli\n");
            AuditReport report = audit(upstream -> { }, baseline);
            assertTrue(fails(report, "LICENSE", "at its root"));
            assertTrue(fails(report, "license-header.txt", "new license file"));
        }

        @Test
        @DisplayName("a new license file anywhere in upstream's source, or at any depth in a LICENSES directory")
        void newFile() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            List<String> paths = List.of("lang/COPYING.txt", "LICENSING.md", "MIT-LICENSE", "COPYING3",
                "docs/THIRD_PARTY_NOTICES.md", "TERMS_OF_USE.md", "EULA.txt", "src/main/resources/target/eula.yml",
                "LICENSES/LicenseRef-Proprietary.txt", "LICENSES/extra/Proprietary.txt");
            for (String path : paths) {
                write(path, "All rights reserved\n");
            }
            write("src/main/resources/illegal-blocks.yml", "- bedrock\n");
            AuditReport report = audit(upstream -> { }, baseline);
            for (String path : paths) {
                assertTrue(fails(report, path, "new license file"), path + ": " + report.findings);
            }
            assertEquals(paths.size(), report.count(Severity.FAIL), report.findings.toString());
        }

        @Test
        @DisplayName("a change to the file that a license's symbolic link points to")
        void symlink() throws Exception {
            write("legal-texts/artistic.txt", "The Artistic License 2.0\n");
            Files.delete(upstreamDirectory.resolve("LICENSE"));
            Files.createSymbolicLink(upstreamDirectory.resolve("LICENSE"), Path.of("legal-texts/artistic.txt"));
            AuditBaseline baseline = cleanBaseline();
            assertFalse(audit(upstream -> { }, baseline).failed);
            write("legal-texts/artistic.txt", "All rights reserved\n");
            AuditReport report = audit(upstream -> { }, baseline);
            assertTrue(fails(report, "LICENSE", "symlink to legal-texts/artistic.txt, " + sha256("All rights reserved\n")));
        }

        @Test
        @DisplayName("licenses that upstream's pom declares")
        void pom() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            Files.writeString(upstreamDirectory.resolve("pom.xml"), POM.replace("<repositories>",
                "<licenses><license><name>Proprietary</name><url>https://example.invalid/terms</url></license>"
                    + "</licenses><repositories>"));
            AuditReport report = audit(upstream -> { }, baseline);
            assertTrue(fails(report, "pom.xml",
                "changed from absent to name: Proprietary, url: https://example.invalid/terms"));
            Files.writeString(upstreamDirectory.resolve("pom.xml"), POM.replace("<repositories>",
                "<licenses><license><name>Proprietary</name><url>https://example.invalid/terms</url>"
                    + "<comments>Noncommercial use only</comments></license></licenses><repositories>"));
            baseline.licenses.addAll(report.observed.licenses);
            assertTrue(fails(audit(upstream -> { }, baseline), "pom.xml", "comments: Noncommercial use only"));
        }

        @Test
        @DisplayName("a new comment at the start of upstream's Java files")
        void header() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            write("src/main/java/net/coreprotect/A.java", HEADER + "class A {}\n");
            write("src/main/java/net/coreprotect/B.java", HEADER + "class B {}\n");
            write("src/main/java/net/coreprotect/C.java", "package net.coreprotect;\n\n/* All rights reserved */\n");
            AuditReport report = audit(upstream -> { }, baseline);
            assertTrue(fails(report, "src/main/java/net/coreprotect/A.java",
                "2 Java files, such as this one, which may state a license: Copyright (C) # Intelli All rights reserved."));
            assertEquals(1, report.count(Severity.FAIL), report.findings.toString());
        }

        @Test
        @DisplayName("needs nothing for an accepted comment with other copyright years")
        void headerYears() throws Exception {
            write("src/main/java/net/coreprotect/A.java", HEADER + "class A {}\n");
            AuditBaseline baseline = cleanBaseline();
            write("src/main/java/net/coreprotect/A.java", HEADER.replace("2024", "2019-2026") + "class A {}\n");
            write("src/main/java/net/coreprotect/B.java", HEADER.replace("2024", "2021, 2026") + "class B {}\n");
            AuditReport report = audit(upstream -> { }, baseline);
            assertFalse(report.failed, report.findings.toString());
        }

        @Test
        @DisplayName("ignores Git's files and the build's output")
        void notSource() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            write(".git/COPYING", "x\n");
            write("target/classes/LICENSE", "x\n");
            write("target/generated-sources/A.java", "// All rights reserved\nclass A {}\n");
            AuditReport report = audit(upstream -> { }, baseline);
            assertFalse(report.failed, report.findings.toString());
        }

        @Test
        @DisplayName("accepts a value for each upstream line")
        void valuesOfEachLine() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            Files.writeString(upstreamDirectory.resolve("LICENSE"), "The Artistic License 2.0, revised\n");
            baseline.licenses.addAll(audit(upstream -> { }, baseline).observed.licenses);
            assertFalse(audit(upstream -> { }, baseline).failed);
            Files.writeString(upstreamDirectory.resolve("LICENSE"), "The Artistic License 2.0\n");
            assertFalse(audit(upstream -> { }, baseline).failed);
        }

        @Test
        @DisplayName("needs nothing for an accepted license file that this line doesn't have")
        void keysOfAnotherLine() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            baseline.licenses.add(Audit.LICENSE_FILE_KEY + "lang/LICENSE=" + "0".repeat(64));
            AuditReport report = audit(upstream -> { }, baseline);
            assertFalse(report.failed, report.findings.toString());
        }

        @Test
        @DisplayName("an allowance accepts exactly the license that it names")
        void allowance() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            baseline.allow.add(new AuditBaseline.Allowance(Audit.RULE_LICENSE,
                Audit.LICENSE_FILE_KEY + "LICENSE=" + sha256("Revised\n"), "test"));
            Files.writeString(upstreamDirectory.resolve("LICENSE"), "Revised\n");
            assertFalse(audit(upstream -> { }, baseline).failed);
            Files.writeString(upstreamDirectory.resolve("LICENSE"), "Revised again\n");
            assertTrue(audit(upstream -> { }, baseline).failed);
        }

        @Test
        @DisplayName("records what it observed, so that it can be copied into the baseline")
        void observed() throws Exception {
            write("src/main/java/net/coreprotect/A.java", HEADER + "class A {}\n");
            assertEquals(Set.of(
                    Audit.LICENSE_FILE_KEY + "LICENSE=" + sha256("The Artistic License 2.0\n"),
                    Audit.POM_LICENSES_KEY + "=absent",
                    Audit.HEADER_KEY + "=" + sha256("Copyright (C) # Intelli All rights reserved.")),
                cleanBaseline().licenses);
        }

        @Test
        @DisplayName("reads the comments before a Java file's code and among its imports, whatever their markers")
        void headerText() {
            assertEquals("", Audit.header("package net.coreprotect;\nimport java.util.List;\n/** The class */\nclass A {}\n"));
            assertEquals("SPDX-License-Identifier: Artistic-2.0 Copyright # Intelli",
                Audit.header("\uFEFF// SPDX-License-Identifier: Artistic-2.0\n/**\n * Copyright 2024 Intelli\n **/\n"
                    + "package net.coreprotect;\n"));
            assertEquals("Proprietary All rights reserved", Audit.header("package net.coreprotect;\n// Proprietary\n"
                + "import java.util.List;\n/* All rights reserved */\nimport java.util.Map;\n/** The class */\nclass A {}\n"));
            assertEquals("unterminated", Audit.header("/* unterminated"));
            assertEquals("All rights reserved", Audit.header("// All rights reserved\rclass A {\r}\r"));
        }

        @Test
        @DisplayName("reads a header written in Unicode escapes, as the Java compiler does")
        void headerUnicodeEscapes() {
            String slash = "\\" + "u002f";
            String star = "\\" + "u002a";
            assertEquals("All rights reserved", Audit.header(slash + star + " All rights reserved " + star + slash
                + " package net.coreprotect;"));
        }

        @Test
        @DisplayName("tells a license's versions and dates apart, though not copyright years")
        void headerVersions() {
            assertNotEquals(Audit.header("// GPL-2.0-or-later\n"), Audit.header("// GPL-3.0-or-later\n"));
            assertNotEquals(Audit.header("// Artistic License 1.0\n"), Audit.header("// Artistic License 2.0\n"));
            assertNotEquals(Audit.header("// Business Source License 1.1, Change Date: 2030-01-01\n"),
                Audit.header("// Business Source License 1.1, Change Date: 2099-01-01\n"));
            assertNotEquals(Audit.header("// Licensed under https://example.invalid/terms/2024\n"),
                Audit.header("// Licensed under https://example.invalid/terms/2026\n"));
            assertEquals(Audit.header("// (C) 2024 Intelli\n"), Audit.header("// (C) 2019\u20132026 Intelli\n"));
            assertEquals(Audit.header("// Copyright 2024 Intelli\n"), Audit.header("// Copyright 2021, 2024 Intelli\n"));
        }
    }

    @Nested
    @DisplayName("REVIEW of how the extensions work with upstream")
    class Capabilities {

        private static final String CONFIG_HANDLER = SyntheticUpstream.CONFIG_HANDLER;

        /**
         * @return the only finding at the site, which must be a capability change that needs review
         */
        private static AuditReport.Finding change(AuditReport report, String site) {
            List<AuditReport.Finding> findings = report.findings.stream()
                .filter(finding -> finding.site().equals(site)).toList();
            assertEquals(1, findings.size(), report.findings::toString);
            assertEquals(Severity.REVIEW, findings.get(0).severity());
            assertEquals(Audit.RULE_CAPABILITY, findings.get(0).rule());
            return findings.get(0);
        }

        private static long changes(AuditReport report) {
            return changes(report, Severity.REVIEW);
        }

        private static long changes(AuditReport report, Severity severity) {
            return report.findings.stream().filter(finding -> finding.rule().equals(Audit.RULE_CAPABILITY)
                && finding.severity() == severity).count();
        }

        @Test
        @DisplayName("none when nothing changed")
        void unchanged() throws Exception {
            AuditReport report = audit(upstream -> { }, cleanBaseline());
            assertEquals(0, changes(report), report.findings::toString);
        }

        @Test
        @DisplayName("a capability whose strategy changed")
        void changedStrategy() throws Exception {
            AuditReport report = audit(upstream -> { }, extensions -> extensions.report.replaceAll(line ->
                line.replace("\tuse-mysql\tReads CoreProtect's use-mysql setting",
                    "\tdatabase-type\tReads CoreProtect's database type")), cleanBaseline());
            assertEquals("changed from use-mysql to database-type. Reads CoreProtect's database type",
                change(report, "capability database.selector").detail());
            // What the new way uses is new too, whatever the old way used
            assertEquals("new: SQLITE,MYSQL. database.selector uses its constants: Reads CoreProtect's database type",
                change(report, "enum database.selector/database-type " + SyntheticUpstream.DATABASE_TYPE).detail());
            assertEquals(2, changes(report), report.findings::toString);
        }

        @Test
        @DisplayName("a new capability")
        void newCapability() throws Exception {
            AuditReport report = audit(upstream -> { }, extensions -> extensions.report.add(
                "capability\tauto-purge.tables\tschema-tables\tPurges every table with a time column"), cleanBaseline());
            assertEquals("new: schema-tables. Purges every table with a time column",
                change(report, "capability auto-purge.tables").detail());
        }

        @Test
        @DisplayName("a capability no longer reported")
        void missingCapability() throws Exception {
            AuditReport report = audit(upstream -> { }, extensions -> extensions.report.removeIf(line ->
                line.contains("\tclickhouse.writes\t")), cleanBaseline());
            assertEquals("no longer in the capability report; was absent",
                change(report, "capability clickhouse.writes").detail());
        }

        @Test
        @DisplayName("accepts each value that the baseline accepts for a key, one per upstream line, and no other")
        void valuesOfEachLine() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            baseline.capabilities.add("capability database.selector=database-type");
            AuditReport report = audit(upstream -> { }, baseline);
            assertEquals(0, changes(report), report.findings::toString);

            AuditReport changed = audit(upstream -> { }, extensions -> extensions.report.replaceAll(line ->
                line.replace("\tuse-mysql\tReads CoreProtect's use-mysql setting", "\tpostgres\tReads another setting")),
                baseline);
            assertEquals("changed from database-type or use-mysql to postgres. Reads another setting",
                change(changed, "capability database.selector").detail());
            change(changed, "enum database.selector/postgres " + SyntheticUpstream.DATABASE_TYPE);
            assertEquals(2, changes(changed), changed.findings::toString);
        }

        @Test
        @DisplayName("asks nothing about keys that only another upstream line has, but about a capability gone")
        void keysOfAnotherLine() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            baseline.capabilities.addAll(List.of("code consumer.gate/cooperative-flags net/coreprotect/Other#run()V"
                + "=0123456789ab", "optional other.thing/some-way net/coreprotect/Other#flag:Z=present",
                "enum database.selector/database-type net/coreprotect/OtherType=ONE,TWO",
                "doc migrate-db.target.duckdb/jdbc docs/other.md=0123456789ab"));
            AuditReport report = audit(upstream -> { }, baseline);
            assertEquals(0, changes(report), report.findings::toString);

            baseline.capabilities.add("capability something.gone=some-way");
            report = audit(upstream -> { }, baseline);
            assertEquals("no longer in the capability report; was some-way",
                change(report, "capability something.gone").detail());
            assertEquals(1, changes(report), report.findings::toString);
        }

        @Test
        @DisplayName("accepts code and documents only under the way that relies on them, not another line's way")
        void codeOfAnotherWay() throws Exception {
            // The other upstream line: other ways, whose code and documents differ
            Consumer<SyntheticUpstream> otherLine = upstream -> {
                upstream.loadDatabaseClearsPurge = true;
                upstream.sources.put("docs/database-migration.md", "# The reload lifecycle\n");
            };
            Consumer<SyntheticExtensions> otherWays = extensions -> extensions.report.replaceAll(line -> line
                .replace("\tconsumer.gate\tbackground-claims\t", "\tconsumer.gate\tcooperative-flags\t")
                .replace("\tmigrate-db.target.duckdb\tunavailable\t", "\tmigrate-db.target.duckdb\tjdbc\t"));
            AuditBaseline baseline = cleanBaseline();
            baseline.capabilities.addAll(audit(otherLine, otherWays, baseline).observed.capabilities);
            AuditReport other = audit(otherLine, otherWays, baseline);
            assertEquals(0, changes(other), other.findings::toString);
            AuditReport same = audit(upstream -> { }, baseline);
            assertEquals(0, changes(same), same.findings::toString);

            // This line's ways, with the other line's code and documents, as if upstream reverted a class
            AuditReport reverted = audit(otherLine, baseline);
            String code = change(reverted, "code consumer.gate/background-claims " + CONFIG_HANDLER
                + "#loadDatabase()V").detail();
            assertTrue(code.matches("changed from [0-9a-f]{12} to [0-9a-f]{12}\\. consumer\\.gate relies on it: "
                + "Reloading the database leaves purgeRunning alone"), code);
            String doc = change(reverted, "doc migrate-db.target.duckdb/unavailable docs/database-migration.md")
                .detail();
            assertTrue(doc.endsWith("migrate-db.target.duckdb follows it: The flag protocol for migration tools"), doc);
            assertEquals(2, changes(reverted), reverted.findings::toString);
        }

        @Test
        @DisplayName("accepts exactly the capability change that an allowance names with its value")
        void allowance() throws Exception {
            Consumer<SyntheticExtensions> change = extensions -> extensions.report.replaceAll(line ->
                line.replace("\tuse-mysql\t", "\tdatabase-type\t"));
            for (String site : List.of("capability database.selector", "capability database.selector=use-mysql",
                "capability database.selector=database")) {
                AuditBaseline baseline = cleanBaseline();
                baseline.allow.add(new AuditBaseline.Allowance(Audit.RULE_CAPABILITY, site, "test"));
                change(audit(upstream -> { }, change, baseline), "capability database.selector");
            }

            for (String site : List.of("capability database.selector=database-type", "capability database.*")) {
                AuditBaseline baseline = cleanBaseline();
                baseline.allow.add(new AuditBaseline.Allowance(Audit.RULE_CAPABILITY, site, "test"));
                AuditReport report = audit(upstream -> { }, change, baseline);
                assertFalse(has(report, Severity.REVIEW, Audit.RULE_CAPABILITY, "capability database.selector"),
                    report.findings::toString);
                assertTrue(has(report, Severity.INFO, Audit.RULE_CAPABILITY, "capability database.selector"));
                // The new way's enum is another key, which the allowance doesn't name
                change(report, "enum database.selector/database-type " + SyntheticUpstream.DATABASE_TYPE);
            }
        }

        @Test
        @DisplayName("an optional member that upstream removed")
        void optionalMember() throws Exception {
            AuditReport report = audit(upstream -> upstream.purgeRunning = false, extensions -> extensions.report
                .replaceAll(line -> line.startsWith("optional\t") ? line.replace("\tpresent", "\tabsent") : line),
                cleanBaseline());
            assertTrue(change(report, "optional consumer.gate/background-claims " + CONFIG_HANDLER
                + "#purgeRunning:Z").detail().startsWith(
                "changed from present to absent. consumer.gate uses it if it exists: Pauses CoreProtect's consumer"));
        }

        @Test
        @DisplayName("upstream changed code that the extensions rely on")
        void changedCode() throws Exception {
            AuditReport report = audit(upstream -> upstream.loadDatabaseClearsPurge = true, cleanBaseline());
            String detail = change(report, "code consumer.gate/background-claims " + CONFIG_HANDLER
                + "#loadDatabase()V").detail();
            assertTrue(detail.matches("changed from [0-9a-f]{12} to [0-9a-f]{12}\\. consumer\\.gate relies on it: "
                + "Reloading the database leaves purgeRunning alone"), detail);
        }

        @Test
        @DisplayName("upstream removed code that the extensions rely on")
        void removedCode() throws Exception {
            AuditReport report = audit(upstream -> upstream.loadDatabase = false, cleanBaseline());
            assertTrue(change(report, "code consumer.gate/background-claims " + CONFIG_HANDLER + "#loadDatabase()V")
                .detail().matches("changed from [0-9a-f]{12} to absent\\..*"));
        }

        @Test
        @DisplayName("upstream changed documentation that the extensions follow")
        void changedDocumentation() throws Exception {
            AuditReport report = audit(upstream -> upstream.sources.put("docs/database-migration.md", "# Moved\n"),
                cleanBaseline());
            assertTrue(change(report, "doc migrate-db.target.duckdb/unavailable docs/database-migration.md").detail()
                .endsWith("migrate-db.target.duckdb follows it: The flag protocol for migration tools"));
        }

        @Test
        @DisplayName("upstream changed an enum's constants")
        void changedEnum() throws Exception {
            AuditReport report = audit(upstream -> upstream.databaseTypes.add("DUCKDB"), extensions -> extensions.report
                .replaceAll(line -> line.replace("\tSQLITE,MYSQL", "\tSQLITE,MYSQL,DUCKDB")), cleanBaseline());
            assertEquals("changed from SQLITE,MYSQL to SQLITE,MYSQL,DUCKDB. database.selector uses its constants: "
                + "Reads CoreProtect's use-mysql setting", change(report, "enum database.selector/use-mysql "
                + SyntheticUpstream.DATABASE_TYPE).detail());
        }

        @Test
        @DisplayName("everything, with a baseline that has no capabilities")
        void noBaselineCapabilities() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            baseline.capabilities = null;
            AuditReport report = audit(upstream -> { }, baseline);
            assertEquals(report.observed.capabilities.size(), changes(report), report.findings::toString);
            assertTrue(report.reviewRequired);
        }

        @Test
        @DisplayName("records what it observed, so that it can be copied into the baseline")
        void observed() throws Exception {
            AuditBaseline observed = cleanBaseline();
            List<String> keys = observed.capabilities.stream()
                .map(entry -> entry.replaceAll("=[0-9a-f]{12}$", "=<hash>")).toList();
            assertEquals(List.of(
                "capability clickhouse.writes=absent",
                "capability consumer.gate=background-claims",
                "capability database.selector=use-mysql",
                "capability migrate-db.target.duckdb=unavailable",
                "code consumer.gate/background-claims " + CONFIG_HANDLER + "#loadDatabase()V=<hash>",
                "doc migrate-db.target.duckdb/unavailable docs/database-migration.md=<hash>",
                "enum database.selector/use-mysql " + SyntheticUpstream.DATABASE_TYPE + "=SQLITE,MYSQL",
                "optional consumer.gate/background-claims " + CONFIG_HANDLER + "#purgeRunning:Z=present"), keys);
        }
    }

    @Test
    @DisplayName("writes the observed state as a baseline, which reads back unchanged")
    void observedRoundTrips() throws Exception {
        AuditBaseline baseline = cleanBaseline();
        String json = Reports.toJson(baseline);
        AuditBaseline parsed = Reports.fromJson(json, AuditBaseline.class);
        assertEquals(json, Reports.toJson(parsed));
    }
}
