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
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CapabilityReportTest {

    private static final String SHA = "ab".repeat(32);
    private static final String UPSTREAM = "upstream\tsha256\t" + SHA;
    private static final String CONSUMER = "net/coreprotect/consumer/Consumer";
    private static final String DATABASE_TYPE = "net/coreprotect/database/DatabaseType";

    @TempDir
    Path directory;

    /**
     * @param members fields as {@code name:descriptor} and methods as {@code name(descriptor)}, which are
     *                protected, or private with a leading {@code -}
     * @return a class with the given members
     */
    private static byte[] type(String name, String superName, List<String> members, String... interfaces) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, name, null, superName, interfaces);
        for (String member : members) {
            int access = member.startsWith("-") ? Opcodes.ACC_PRIVATE : Opcodes.ACC_PROTECTED;
            String signature = member.startsWith("-") ? member.substring(1) : member;
            int colon = signature.indexOf(':');
            if (colon >= 0) {
                writer.visitField(access | Opcodes.ACC_STATIC, signature.substring(0, colon),
                    signature.substring(colon + 1), null, null).visitEnd();
            } else {
                int parenthesis = signature.indexOf('(');
                writer.visitMethod(access, signature.substring(0, parenthesis), signature.substring(parenthesis),
                    null, null).visitEnd();
            }
        }
        writer.visitEnd();
        return writer.toByteArray();
    }

    /**
     * @return an upstream JAR with the members that the tests' reports name
     */
    private static JarContents upstream() {
        JarContents jar = new JarContents();
        jar.put(CONSUMER + ".class", type(CONSUMER, "java/lang/Object",
            List.of("isPaused:[[Ljava/lang/String;", "<init>()V", "lockDatabaseReload(J)Z")));
        jar.put(CONSUMER + "$Queue.class", type(CONSUMER + "$Queue", "java/lang/Object", List.of()));
        jar.put(DATABASE_TYPE + ".class", SyntheticUpstream.enumClass(DATABASE_TYPE, List.of("SQLITE", "MYSQL")));
        jar.put("net/coreprotect/A.class", type("net/coreprotect/A", "java/lang/Object",
            List.of("x:I", "-secret:J", "-hidden()V")));
        jar.put("net/coreprotect/Sub.class", type("net/coreprotect/Sub", "net/coreprotect/A", List.of()));
        jar.put("net/coreprotect/Task.class", type("net/coreprotect/Task", "java/lang/Object", List.of(),
            "java/lang/Runnable"));
        jar.put("net/coreprotect/Plugin.class", type("net/coreprotect/Plugin", "org/bukkit/plugin/java/JavaPlugin",
            List.of()));
        return jar;
    }

    private CapabilityReport read(String... lines) throws IOException {
        return CapabilityReport.read(String.join("\n", lines) + "\n", upstream(), directory);
    }

    private String violation(String... lines) {
        return assertThrows(ContractViolation.class, () -> read(lines)).getMessage();
    }

    @Test
    @DisplayName("reads every kind of line")
    void reads() throws IOException {
        Files.createDirectories(directory.resolve("docs"));
        Files.writeString(directory.resolve("docs/api.md"), "# API\n");
        CapabilityReport report = read(UPSTREAM,
            "capability\tauto-purge.tables\tabsent\tNo purgeable tables",
            "capability\tconsumer.gate\tbackground-claims\tPauses the consumer",
            "doc\tconsumer.gate\tdocs/api.md\tThe consumer's pause",
            "enum\tconsumer.gate\t" + DATABASE_TYPE + "\tSQLITE,MYSQL",
            "member\tconsumer.gate\t" + CONSUMER,
            "member\tconsumer.gate\t" + CONSUMER + "#<init>()V",
            "member\tconsumer.gate\t" + CONSUMER + "#isPaused:[[Ljava/lang/String;",
            "member\tconsumer.gate\t" + CONSUMER + "#lockDatabaseReload(J)Z",
            "optional\tconsumer.gate\t" + CONSUMER + "$Queue#size()I\tabsent",
            "rejected\tconsumer.gate\tcooperative-flags\tNo flags",
            "relies\tconsumer.gate\t" + CONSUMER + "#run()V\tChecks the pause flag");

        assertEquals(SHA, report.upstreamSha256);
        assertEquals(List.of(
            new TransformReport.Capability("auto-purge.tables", "absent", null, "No purgeable tables", List.of(),
                List.of(), List.of(), List.of(), List.of(), List.of()),
            new TransformReport.Capability("consumer.gate", "background-claims", "Pauses the consumer", null,
                List.of(CONSUMER, CONSUMER + "#<init>()V", CONSUMER + "#isPaused:[[Ljava/lang/String;",
                    CONSUMER + "#lockDatabaseReload(J)Z"),
                List.of(new TransformReport.OptionalMember(CONSUMER + "$Queue#size()I", "absent")),
                List.of(new TransformReport.Reliance(CONSUMER + "#run()V", "Checks the pause flag", "absent")),
                List.of(new TransformReport.EnumConstants(DATABASE_TYPE, List.of("SQLITE", "MYSQL"))),
                List.of(new TransformReport.Doc("docs/api.md", "The consumer's pause",
                    CapabilityReport.sha256("# API\n".getBytes(StandardCharsets.UTF_8)).substring(0, 12))),
                List.of(new TransformReport.Rejected("cooperative-flags", "No flags")))), report.capabilities);
        assertEquals(4, CapabilityReport.memberCount(report.capabilities));
    }

    @Test
    @DisplayName("counts the distinct members of available capabilities, and their optional members that are present")
    void memberCount() throws IOException {
        CapabilityReport report = read(UPSTREAM,
            "capability\ta\tstrategy\tA",
            "capability\tb\tstrategy\tB",
            "capability\tc\tunavailable\tC",
            "member\ta\tnet/coreprotect/A",
            "member\tb\tnet/coreprotect/A",
            "member\tc\tnet/coreprotect/C",
            "optional\ta\tnet/coreprotect/A#x:I\tpresent",
            "optional\tb\tnet/coreprotect/A#y:I\tabsent");
        assertEquals(2, CapabilityReport.memberCount(report.capabilities));
    }

    @Test
    @DisplayName("gives the audit a key per capability, and one per member, method, enum and document of its way")
    void observations() throws IOException {
        CapabilityReport report = read(UPSTREAM,
            "capability\ta\tone\tA",
            "capability\tb\tunavailable\tB",
            "optional\ta\tnet/coreprotect/A#x:I\tpresent",
            "optional\tb\tnet/coreprotect/A#x:I\tpresent",
            "relies\ta\tnet/coreprotect/A#run()V\tRuns");
        Map<String, CapabilityReport.Observation> observations = CapabilityReport.observations(report.capabilities);
        assertEquals(List.of("capability a", "capability b", "code a/one net/coreprotect/A#run()V",
            "optional a/one net/coreprotect/A#x:I", "optional b/unavailable net/coreprotect/A#x:I"),
            List.copyOf(observations.keySet()));
        assertEquals(List.of("a uses it if it exists: A"), observations.get("optional a/one net/coreprotect/A#x:I")
            .contexts());
        assertEquals("present", observations.get("optional b/unavailable net/coreprotect/A#x:I").value());
    }

    @Test
    @DisplayName("keeps lines in the order the extensions' build sorted them")
    void order() throws IOException {
        assertEquals(List.of("b", "b.c", "bc"), read(UPSTREAM, "capability\tb\tone\tB", "capability\tb.c\tone\tC",
            "capability\tbc\tone\tD").capabilities.stream().map(TransformReport.Capability::id).toList());
    }

    @Nested
    @DisplayName("checks against the upstream JAR")
    class Upstream {

        @Test
        @DisplayName("members that a class declares or inherits, in the JAR or from the JDK")
        void inherited() throws IOException {
            read(UPSTREAM, "capability\ta\tone\tA",
                "member\ta\tnet/coreprotect/A#hidden()V",
                "member\ta\tnet/coreprotect/A#secret:J",
                "member\ta\tnet/coreprotect/Sub#hashCode()I",
                "member\ta\tnet/coreprotect/Sub#x:I",
                "member\ta\tnet/coreprotect/Task#run()V",
                "optional\ta\tnet/coreprotect/Sub#toString()Ljava/lang/String;\tpresent",
                "optional\ta\tnet/coreprotect/Sub#y:I\tabsent");
        }

        @Test
        @DisplayName("but not the private members of a superclass, which aren't inherited")
        void privateOfSuperclass() {
            for (String member : List.of("net/coreprotect/Sub#secret:J", "net/coreprotect/Sub#hidden()V")) {
                String message = violation(UPSTREAM, "capability\ta\tone\tA", "member\ta\t" + member);
                assertTrue(message.contains("which uses " + member + ", but the upstream JAR doesn't have it"), message);
            }
        }

        @Test
        @DisplayName("rejects a method missing from a class that implements a JDK interface")
        void jdkInterface() {
            String message = violation(UPSTREAM, "capability\ta\tone\tA", "member\ta\tnet/coreprotect/Task#stop()V");
            assertTrue(message.contains("which uses net/coreprotect/Task#stop()V, but the upstream JAR doesn't have it"),
                message);
        }

        @Test
        @DisplayName("but not members inherited from outside the JAR, which it can't see")
        void outsideTheJar() throws IOException {
            read(UPSTREAM, "capability\ta\tone\tA",
                "member\ta\tnet/coreprotect/Plugin#getDataFolder()Ljava/io/File;",
                "optional\ta\tnet/coreprotect/Plugin#getLogger()Ljava/util/logging/Logger;\tpresent",
                "optional\ta\tnet/coreprotect/Plugin#getServer()Lorg/bukkit/Server;\tabsent");
        }

        @Test
        @DisplayName("rejects a member of an available capability that the JAR doesn't have")
        void missingMember() {
            for (String member : List.of("net/coreprotect/NoSuchClass", CONSUMER + "#isPaused:Z",
                CONSUMER + "#lockDatabaseReload()Z", CONSUMER + "#noSuchField:Z", "net/coreprotect/Sub#z:I",
                "net/coreprotect/Sub#wait(Z)V", "java/lang/String")) {
                String message = violation(UPSTREAM, "capability\ta\tone\tA", "member\ta\t" + member);
                assertTrue(message.contains("says that a works with one, which uses " + member
                    + ", but the upstream JAR doesn't have it"), message);
            }
        }

        @Test
        @DisplayName("rejects an optional member said to be present that the JAR doesn't have")
        void missingOptional() {
            String message = violation(UPSTREAM, "capability\ta\tone\tA",
                "optional\ta\tnet/coreprotect/NoSuchClass#alsoMissing:Z\tpresent");
            assertTrue(message.contains("says that net/coreprotect/NoSuchClass#alsoMissing:Z is present, but the "
                + "upstream JAR doesn't have it"), message);
        }

        @Test
        @DisplayName("rejects an optional member said to be absent that the JAR has, even for an unavailable capability")
        void presentOptional() {
            String message = violation(UPSTREAM, "capability\ta\tunavailable\tA",
                "optional\ta\tnet/coreprotect/A#x:I\tabsent");
            assertTrue(message.contains("says that net/coreprotect/A#x:I is absent, but the upstream JAR has it"),
                message);
        }

        @Test
        @DisplayName("rejects enum constants other than the JAR's, in the JAR's order")
        void enumConstants() {
            for (String constants : List.of("SQLITE", "MYSQL,SQLITE", "SQLITE,MYSQL,DUCKDB")) {
                String message = violation(UPSTREAM, "capability\ta\tone\tA", "enum\ta\t" + DATABASE_TYPE + "\t"
                    + constants);
                assertTrue(message.contains("lists the constants of " + DATABASE_TYPE + " as " + constants
                    + ", but the upstream JAR has SQLITE,MYSQL"), message);
            }
            for (String owner : List.of("net/coreprotect/NoSuchEnum", "net/coreprotect/A")) {
                String message = violation(UPSTREAM, "capability\ta\tone\tA", "enum\ta\t" + owner + "\tA,B");
                assertTrue(message.contains("but the upstream JAR has no such enum"), message);
            }
        }

        @Test
        @DisplayName("accepts members of a capability that isn't available, which the JAR doesn't have")
        void unavailable() throws IOException {
            read(UPSTREAM, "capability\ta\tabsent\tA", "capability\tb\tunavailable\tB",
                "member\ta\tnet/coreprotect/NoSuchClass", "member\tb\t" + CONSUMER + "#noSuchMethod()V");
        }
    }

    @Nested
    @DisplayName("hashes documentation")
    class Documentation {

        private String hash() throws IOException {
            return read(UPSTREAM, "capability\ta\tone\tA", "doc\ta\tdocs/a.md\tA").capabilities.get(0).docs().get(0)
                .hash();
        }

        @Test
        @DisplayName("by content")
        void present() throws IOException {
            Files.createDirectories(directory.resolve("docs"));
            Files.writeString(directory.resolve("docs/a.md"), "# A\n");
            assertEquals(CapabilityReport.sha256("# A\n".getBytes(StandardCharsets.UTF_8)).substring(0, 12), hash());
        }

        @Test
        @DisplayName("as absent when upstream doesn't have it")
        void absent() throws IOException {
            assertEquals("absent", hash());
        }

        @Test
        @DisplayName("only with upstream's source tree")
        void noSourceTree() {
            String message = assertThrows(ContractViolation.class, () -> CapabilityReport.read(
                UPSTREAM + "\ncapability\ta\tone\tA\ndoc\ta\tdocs/a.md\tA\n", upstream(), null)).getMessage();
            assertTrue(message.contains("names upstream's docs/a.md, but the transformer wasn't given upstream's "
                + "source tree (--upstream-dir)"), message);
        }

        @Test
        @DisplayName("but not through a link out of upstream's source tree")
        void escapingLink() throws IOException {
            Path outside = Files.writeString(Files.createDirectories(directory.resolve("outside")).resolve("x"), "x");
            Path source = Files.createDirectories(directory.resolve("source/docs")).getParent();
            Files.createSymbolicLink(source.resolve("docs/a.md"), outside);
            String message = assertThrows(ContractViolation.class, () -> CapabilityReport.read(
                UPSTREAM + "\ncapability\ta\tone\tA\ndoc\ta\tdocs/a.md\tA\n", upstream(), source)).getMessage();
            assertTrue(message.contains("docs/a.md leads outside its source tree"), message);
        }
    }

    @Nested
    @DisplayName("rejects a report")
    class Rejects {

        @Test
        @DisplayName("that doesn't start with the upstream JAR's SHA-256")
        void firstLine() {
            assertTrue(violation("capability\ta\tone\tA").contains("Line 1 "));
            assertTrue(violation("upstream\tsha256\t" + SHA.toUpperCase()).contains("Line 1 "));
            assertTrue(violation("upstream\tsha1\t" + SHA).contains("Line 1 "));
            assertTrue(assertThrows(ContractViolation.class, () -> CapabilityReport.read("", upstream(), null))
                .getMessage().contains("is empty"));
        }

        @Test
        @DisplayName("that starts with a byte order mark")
        void byteOrderMark() {
            assertTrue(violation("\uFEFF" + UPSTREAM, "capability\ta\tone\tA").contains("byte order mark"));
        }

        @Test
        @DisplayName("that isn't valid UTF-8")
        void encoding() {
            byte[] bytes = (UPSTREAM + "\ncapability\ta\tone\tA\n").getBytes(StandardCharsets.UTF_8);
            bytes[bytes.length - 2] = (byte) 0xFF;
            assertEquals("The capability report isn't valid UTF-8",
                assertThrows(ContractViolation.class, () -> CapabilityReport.decode(bytes)).getMessage());
        }

        @Test
        @DisplayName("with a second upstream line")
        void secondUpstream() {
            String message = violation(UPSTREAM, "capability\ta\tone\tA", "upstream\tsha256\t" + SHA);
            assertTrue(message.contains("Line 3 ") && message.contains("only the first line may be the 'upstream' "
                + "line"), message);
        }

        @Test
        @DisplayName("with a line type that the transformer doesn't know")
        void unknownType() {
            String message = violation(UPSTREAM, "capability\ta\tone\tA", "requires\ta\tsomething\telse");
            assertTrue(message.contains("Line 3 of the capability report doesn't follow its format: unknown line "
                + "type 'requires'"), message);
        }

        @Test
        @DisplayName("with an empty line")
        void emptyLine() {
            assertTrue(violation(UPSTREAM, "", "capability\ta\tone\tA").contains("Line 2 "));
            String message = violation(UPSTREAM, "capability\ta\tone\tA", "", "member\ta\tnet/coreprotect/A");
            assertTrue(message.contains("Line 3 of the capability report doesn't follow its format: it is empty"),
                message);
        }

        @Test
        @DisplayName("whose lines aren't sorted")
        void unsorted() {
            String message = violation(UPSTREAM, "member\ta\tnet/coreprotect/A", "capability\ta\tone\tA");
            assertTrue(message.contains("Line 3 ") && message.contains("sorted"), message);
        }

        @Test
        @DisplayName("with a line twice")
        void duplicateLine() {
            assertTrue(violation(UPSTREAM, "capability\ta\tone\tA", "member\ta\tnet/coreprotect/A",
                "member\ta\tnet/coreprotect/A").contains("sorted"));
        }

        @Test
        @DisplayName("with a capability twice")
        void duplicateCapability() {
            assertTrue(violation(UPSTREAM, "capability\ta\tone\tA", "capability\ta\ttwo\tB").contains("appears twice"));
        }

        @Test
        @DisplayName("with too few or too many fields")
        void fieldCount() {
            assertTrue(violation(UPSTREAM, "capability\ta\tone").contains("has 4 fields, found 3"));
            assertTrue(violation(UPSTREAM, "capability\ta\tone\tA", "member\ta\tnet/coreprotect/A\textra")
                .contains("has 3 fields, found 4"));
        }

        @Test
        @DisplayName("with an empty field")
        void emptyField() {
            assertTrue(violation(UPSTREAM, "capability\ta\tone\t").contains("empty field"));
        }

        @Test
        @DisplayName("with Windows line ends")
        void carriageReturn() {
            assertTrue(assertThrows(ContractViolation.class, () -> CapabilityReport.read(UPSTREAM
                + "\r\ncapability\ta\tone\tA\r\n", upstream(), null)).getMessage().contains("carriage return"));
        }

        @Test
        @DisplayName("with a control character")
        void controlCharacter() {
            for (String line : List.of("capability\ta\tone\tA\u0000", "capability\ta\tone\tA\u001B[31m",
                "capability\ta\tone\tA\u007F")) {
                assertTrue(violation(UPSTREAM, line).contains("control character"), line);
            }
            assertTrue(violation(UPSTREAM, "capability\ta\tone\tA", "doc\ta\tdocs/a\u0000b.md\tx")
                .contains("control character"));
        }

        @Test
        @DisplayName("with a line about a capability that it doesn't have")
        void undeclaredCapability() {
            String message = violation(UPSTREAM, "capability\ta\tone\tA", "member\tb\tnet/coreprotect/B");
            assertTrue(message.contains("a 'member' line for b, but no 'capability' line for it"), message);
        }

        @Test
        @DisplayName("with a capability ID or strategy that isn't lowercase letters, digits, '.' and '-'")
        void names() {
            for (String id : List.of("a=b", "clickhouse|reads", "Consumer.gate", "a b", "-a", ".a", "a_b", "`a`",
                "a<b>")) {
                assertTrue(violation(UPSTREAM, "capability\t" + id + "\tone\tA").contains("capability ID '" + id
                    + "' isn't made of lowercase letters, digits, '.' and '-'"), id);
            }
            for (String strategy : List.of("Use-MySQL", "use mysql", "use|mysql", "-use")) {
                assertTrue(violation(UPSTREAM, "capability\ta\t" + strategy + "\tA").contains("strategy '" + strategy
                    + "' isn't made of"), strategy);
                assertTrue(violation(UPSTREAM, "capability\ta\tone\tA", "rejected\ta\t" + strategy + "\tWhy")
                    .contains("names strategy '" + strategy + "', which isn't made of"), strategy);
            }
        }

        @Test
        @DisplayName("naming a member in another syntax")
        void memberSyntax() {
            for (String member : List.of("net.coreprotect.A", "net/coreprotect/A.run()V", "net/coreprotect/A#run",
                "net/coreprotect/A#run()", "net/coreprotect/A#x:Q", "net/coreprotect/A#run(Lnet/coreprotect/B)V",
                "net/coreprotect/A#x=1:I", "net/coreprotect//A", "net/coreprotect/A|B", "net/coreprotect/`A`",
                "net/coreprotect/Ä", "net/coreprotect/1A", "net/coreprotect/A#<b>()V")) {
                String message = violation(UPSTREAM, "capability\ta\tone\tA", "member\ta\t" + member);
                assertTrue(message.contains("names '" + member + "', expected owner#name(descriptor)"), message);
            }
        }

        @Test
        @DisplayName("relying on something other than a method")
        void reliesOnField() {
            String message = violation(UPSTREAM, "capability\ta\tone\tA", "relies\ta\tnet/coreprotect/A#x:I\tWhy");
            assertTrue(message.contains("expected a method"), message);
        }

        @Test
        @DisplayName("with an optional member that is neither present nor absent")
        void optionalState() {
            String message = violation(UPSTREAM, "capability\ta\tone\tA", "optional\ta\tnet/coreprotect/A\tmissing");
            assertTrue(message.contains("says 'missing', expected present or absent"), message);
        }

        @Test
        @DisplayName("with an optional member both present and absent")
        void conflictingOptional() {
            // The JAR can't tell, because the member would be inherited from outside it
            String member = "net/coreprotect/Plugin#getServer()Lorg/bukkit/Server;";
            String message = violation(UPSTREAM, "capability\ta\tone\tA", "capability\tb\tone\tB",
                "optional\ta\t" + member + "\tpresent", "optional\tb\t" + member + "\tabsent");
            assertTrue(message.contains("gives optional " + member + " two values"), message);
        }

        @Test
        @DisplayName("with enum constants that aren't a list of names")
        void enumSyntax() {
            for (String constants : List.of("A,,B", "A,", "A B", "A|B", "1A")) {
                String message = violation(UPSTREAM, "capability\ta\tone\tA", "enum\ta\tnet/coreprotect/E\t"
                    + constants);
                assertTrue(message.contains("expected names separated by commas"), message);
            }
        }

        @Test
        @DisplayName("with documentation outside upstream's source tree, or an odd path")
        void documentationPath() {
            for (String path : List.of("/etc/passwd", "../secrets.md", "docs/../../x.md", "docs\\x.md", "./docs/x.md",
                "docs//x.md", "docs/a b.md", "docs/x.md:stream", "C:/x.md")) {
                String message = violation(UPSTREAM, "capability\ta\tone\tA", "doc\ta\t" + path + "\tWhat");
                assertTrue(message.contains("expected a relative path in upstream's source tree"), message);
            }
        }
    }
}
