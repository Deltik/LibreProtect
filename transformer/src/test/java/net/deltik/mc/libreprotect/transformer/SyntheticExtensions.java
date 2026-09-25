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
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Builds a small fake extensions JAR, shaped like LibreProtect's: the two
 * extension classes that upstream loads by name, and a class that finds
 * upstream's internals by name, the way the extensions' upstream package
 * does.
 */
final class SyntheticExtensions {

    static final String MIGRATION = "net/coreprotect/utility/extensions/DatabaseMigration";
    static final String SERVICE = "net/coreprotect/utility/extensions/BackgroundService";
    static final String REFLECTOR = "net/deltik/mc/libreprotect/extension/upstream/Reflector";

    /** Classes to add, by entry name */
    final Map<String, byte[]> extra = new LinkedHashMap<>();

    Path write(Path directory) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put(MIGRATION + ".class", extensionClass(MIGRATION, Map.of(
            "runCommand", "(Lorg/bukkit/command/CommandSender;[Ljava/lang/String;)V")));
        entries.put(SERVICE + ".class", extensionClass(SERVICE, Map.of("start", "()V", "stop", "()V")));
        entries.put(REFLECTOR + ".class", reflectorClass());
        entries.putAll(extra);
        return TestClasses.writeJar(directory.resolve("extensions.jar"), entries);
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
