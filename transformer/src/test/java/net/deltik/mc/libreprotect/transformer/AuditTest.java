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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
        SyntheticUpstream upstream = new SyntheticUpstream();
        change.accept(upstream);
        SyntheticUpstream.Jars jars = upstream.write(directory);
        Transformer transformer = new Transformer(new Transformer.Options(
            jars.shaded(), jars.original(), TestClasses.runtimeJar(directory), jars.lang(), directory.resolve("out.jar"),
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
        @DisplayName("a changed LICENSE")
        void license() throws Exception {
            AuditBaseline baseline = cleanBaseline();
            Files.writeString(upstreamDirectory.resolve("LICENSE"), "All rights reserved\n");
            AuditReport report = audit(upstream -> { }, baseline);
            assertTrue(has(report, Severity.REVIEW, "license-change", "LICENSE"));
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

    @Test
    @DisplayName("the observed state can replace the baseline as is")
    void observedRoundTrips() throws Exception {
        AuditBaseline baseline = cleanBaseline();
        String json = Reports.toJson(baseline);
        AuditBaseline parsed = Reports.fromJson(json, AuditBaseline.class);
        assertEquals(json, Reports.toJson(parsed));
    }
}
