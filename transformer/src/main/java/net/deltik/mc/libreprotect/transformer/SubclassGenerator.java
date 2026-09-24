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

/**
 * Generates LibreProtect's plugin main class, a subclass of upstream's main
 * class:
 *
 * <pre>
 * public class LibreProtectPlugin extends &lt;upstream main&gt; {
 *     public LibreProtectPlugin() { super(); Bootstrap.init(this); }
 *     public void onEnable() { super.onEnable(); Bootstrap.enabled(this); }
 * }
 * </pre>
 *
 * <p>Generating it instead of compiling it means LibreProtect's own source
 * never names upstream's main class, so a renamed main class needs no source
 * change. It also avoids javac, which won't compile a subclass of a class
 * that is {@code final} before the transformer runs.
 */
final class SubclassGenerator {

    static final String CLASS_NAME = "net/deltik/mc/libreprotect/LibreProtectPlugin";
    static final String BOOTSTRAP = "net/deltik/mc/libreprotect/Bootstrap";
    static final String JAVA_PLUGIN = "org/bukkit/plugin/java/JavaPlugin";
    static final String HOOK_DESCRIPTOR = "(L" + JAVA_PLUGIN + ";)V";

    private SubclassGenerator() {
    }

    /**
     * @param superName internal name of upstream's main class
     * @param classVersion class file version to emit, matching upstream's main class
     */
    static byte[] generate(String superName, int classVersion) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(classVersion, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, CLASS_NAME, null, superName, null);
        writer.visitSource("LibreProtectPlugin.java", null);

        // Straight-line code needs no stack map frames
        MethodVisitor constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        constructor.visitCode();
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, superName, "<init>", "()V", false);
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(Opcodes.INVOKESTATIC, BOOTSTRAP, "init", HOOK_DESCRIPTOR, false);
        constructor.visitInsn(Opcodes.RETURN);
        constructor.visitMaxs(1, 1);
        constructor.visitEnd();

        MethodVisitor onEnable = writer.visitMethod(Opcodes.ACC_PUBLIC, "onEnable", "()V", null, null);
        onEnable.visitCode();
        onEnable.visitVarInsn(Opcodes.ALOAD, 0);
        onEnable.visitMethodInsn(Opcodes.INVOKESPECIAL, superName, "onEnable", "()V", false);
        onEnable.visitVarInsn(Opcodes.ALOAD, 0);
        onEnable.visitMethodInsn(Opcodes.INVOKESTATIC, BOOTSTRAP, "enabled", HOOK_DESCRIPTOR, false);
        onEnable.visitInsn(Opcodes.RETURN);
        onEnable.visitMaxs(1, 1);
        onEnable.visitEnd();

        writer.visitEnd();
        return writer.toByteArray();
    }
}
