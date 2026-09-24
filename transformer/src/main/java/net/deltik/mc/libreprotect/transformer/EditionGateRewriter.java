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

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.List;
import java.util.Map;

/**
 * Replaces the bodies of CoreProtect's edition checks with constants, so
 * every feature that upstream gates behind a donation key is available.
 *
 * <p>These are matched by name because upstream exposes them as named
 * checks. {@link Transformer} requires exactly one match per gate, so a
 * rename or a duplicate fails the build instead of silently doing nothing.
 */
final class EditionGateRewriter extends ClassVisitor {

    /** Gate name to the value it should always return. Each gate is {@code static boolean name()}. */
    static final Map<String, Boolean> GATES = Map.of(
        "validDonationKey", true,
        "isCommunityEdition", false
    );

    private static final String DESCRIPTOR = "()Z";

    private final String entry;
    private final List<TransformReport.EditionGate> gates;
    private String className;

    EditionGateRewriter(ClassVisitor next, String entry, List<TransformReport.EditionGate> gates) {
        super(Opcodes.ASM9, next);
        this.entry = entry;
        this.gates = gates;
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        className = name;
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        boolean concreteStatic = (access & Opcodes.ACC_STATIC) != 0
            && (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) == 0;
        if (!concreteStatic || !DESCRIPTOR.equals(descriptor) || !GATES.containsKey(name)) {
            return super.visitMethod(access, name, descriptor, signature, exceptions);
        }

        boolean value = GATES.get(name);
        MethodVisitor replacement = super.visitMethod(access, name, descriptor, signature, exceptions);
        replacement.visitCode();
        replacement.visitInsn(value ? Opcodes.ICONST_1 : Opcodes.ICONST_0);
        replacement.visitInsn(Opcodes.IRETURN);
        replacement.visitMaxs(1, 0);
        replacement.visitEnd();
        gates.add(new TransformReport.EditionGate(entry, className, name + descriptor, value));
        // Returning null makes the reader skip the original body
        return null;
    }
}
