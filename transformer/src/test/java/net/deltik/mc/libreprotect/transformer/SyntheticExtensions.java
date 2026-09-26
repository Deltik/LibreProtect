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

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Builds a small fake extensions JAR, shaped like LibreProtect's: the two
 * extension classes that upstream loads by name, and a class that finds
 * upstream's internals by name, the way the extensions' upstream package
 * does. Also builds the capability report that the extensions' build would
 * write for it.
 */
final class SyntheticExtensions {

    static final String MIGRATION = "net/coreprotect/utility/extensions/DatabaseMigration";
    static final String SERVICE = "net/coreprotect/utility/extensions/BackgroundService";
    static final String REFLECTOR = "net/deltik/mc/libreprotect/extension/upstream/Reflector";

    /** Classes to add, by entry name */
    final Map<String, byte[]> extra = new LinkedHashMap<>();

    /** The capability report's lines after the first, sorted by their UTF-8 bytes when written */
    final List<String> report = new ArrayList<>(List.of(
        "capability\tclickhouse.writes\tabsent\tThis CoreProtect has no ClickHouse support",
        "capability\tconsumer.gate\tbackground-claims\tPauses CoreProtect's consumer while a purge claims the database",
        "member\tconsumer.gate\t" + SyntheticUpstream.CONSUMER,
        "member\tconsumer.gate\t" + SyntheticUpstream.CONSUMER + "#pausedSuccess:Z",
        "optional\tconsumer.gate\t" + SyntheticUpstream.CONFIG_HANDLER + "#purgeRunning:Z\tpresent",
        "relies\tconsumer.gate\t" + SyntheticUpstream.CONFIG_HANDLER + "#loadDatabase()V\t"
            + "Reloading the database leaves purgeRunning alone",
        "rejected\tconsumer.gate\tcooperative-flags\tThis CoreProtect has no cooperative flags",
        "capability\tdatabase.selector\tuse-mysql\tReads CoreProtect's use-mysql setting",
        "member\tdatabase.selector\t" + SyntheticUpstream.CONFIG_HANDLER,
        "enum\tdatabase.selector\t" + SyntheticUpstream.DATABASE_TYPE + "\tSQLITE,MYSQL",
        "capability\tmigrate-db.target.duckdb\tunavailable\tDuckDB's driver isn't among plugin.yml's libraries",
        "doc\tmigrate-db.target.duckdb\tdocs/database-migration.md\tThe flag protocol for migration tools"));

    /** The SHA-256 that the report says was probed, or {@code null} for the upstream JAR's */
    String reportSha256;

    Path write(Path directory) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put(MIGRATION + ".class", extensionClass(MIGRATION, Map.of(
            "runCommand", "(Lorg/bukkit/command/CommandSender;[Ljava/lang/String;)V")));
        entries.put(SERVICE + ".class", extensionClass(SERVICE, Map.of("start", "()V", "stop", "()V")));
        entries.put(REFLECTOR + ".class", reflectorClass());
        entries.putAll(extra);
        return TestClasses.writeJar(directory.resolve("extensions.jar"), entries);
    }

    /**
     * @param upstreamJar the upstream JAR that the report says was probed
     */
    Path writeReport(Path directory, Path upstreamJar) throws IOException {
        String sha256 = reportSha256 != null ? reportSha256
            : CapabilityReport.sha256(Files.readAllBytes(upstreamJar));
        StringBuilder text = new StringBuilder("upstream\tsha256\t").append(sha256).append('\n');
        report.stream().sorted(SyntheticExtensions::compareBytes).forEach(line -> text.append(line).append('\n'));
        return Files.writeString(directory.resolve("capabilities.tsv"), text, StandardCharsets.UTF_8);
    }

    static int compareBytes(String first, String second) {
        return Arrays.compareUnsigned(first.getBytes(StandardCharsets.UTF_8), second.getBytes(StandardCharsets.UTF_8));
    }

    static byte[] extensionClass(String name, Map<String, String> methods) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER | Opcodes.ACC_FINAL, name, null,
            "java/lang/Object", null);
        methods.forEach((methodName, descriptor) -> {
            MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, methodName, descriptor,
                null, null);
            method.visitCode();
            method.visitInsn(Opcodes.RETURN);
            method.visitMaxs(0, 0);
            method.visitEnd();
        });
        writer.visitEnd();
        return writer.toByteArray();
    }

    /**
     * @return a class whose method {@code run()} consists of the given instructions
     */
    static byte[] codeClass(String name, String superName, List<Consumer<MethodVisitor>> instructions) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, name, null, superName, null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
        method.visitCode();
        instructions.forEach(instruction -> instruction.accept(method));
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    /**
     * @return a class that finds upstream's consumer and its flag by name
     */
    static byte[] reflectorClass() {
        return codeClass(REFLECTOR, "java/lang/Object", List.of(method -> {
            method.visitLdcInsn(SyntheticUpstream.CONSUMER.replace('/', '.'));
            method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;", false);
            method.visitLdcInsn("pausedSuccess");
            method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getDeclaredField",
                "(Ljava/lang/String;)Ljava/lang/reflect/Field;", false);
            method.visitInsn(Opcodes.POP);
        }));
    }
}
