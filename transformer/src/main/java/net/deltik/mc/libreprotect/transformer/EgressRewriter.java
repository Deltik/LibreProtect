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
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.List;

/**
 * Redirects every {@link EgressRules} call site in a class to the
 * {@code Egress} gate. This covers direct calls, method references
 * ({@code url::openStream}, compiled to an invokedynamic handle argument) and
 * method-handle constants.
 */
final class EgressRewriter extends ClassVisitor {

    private final String entry;
    private final Origin origin;
    private final List<TransformReport.EgressSite> sites;
    private String className;

    EgressRewriter(ClassVisitor next, String entry, Origin origin, List<TransformReport.EgressSite> sites) {
        super(Opcodes.ASM9, next);
        this.entry = entry;
        this.origin = origin;
        this.sites = sites;
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        className = name;
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        String method = name + descriptor;
        return new MethodVisitor(Opcodes.ASM9, super.visitMethod(access, name, descriptor, signature, exceptions)) {
            @Override
            public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                if (opcode == Opcodes.INVOKEVIRTUAL && EgressRules.isEgress(owner, name, descriptor)) {
                    record(method, name + descriptor, "call");
                    super.visitMethodInsn(Opcodes.INVOKESTATIC, EgressRules.EGRESS, name,
                        EgressRules.staticDescriptor(descriptor), false);
                    return;
                }
                super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
            }

            @Override
            public void visitInvokeDynamicInsn(String name, String descriptor, Handle bootstrapMethodHandle,
                                               Object... bootstrapMethodArguments) {
                super.visitInvokeDynamicInsn(name, descriptor, bootstrapMethodHandle,
                    rewriteConstants(method, bootstrapMethodArguments));
            }

            @Override
            public void visitLdcInsn(Object value) {
                super.visitLdcInsn(rewriteConstant(method, value));
            }
        };
    }

    private Object[] rewriteConstants(String method, Object[] values) {
        Object[] rewritten = values.clone();
        for (int i = 0; i < rewritten.length; i++) {
            rewritten[i] = rewriteConstant(method, rewritten[i]);
        }
        return rewritten;
    }

    private Object rewriteConstant(String method, Object value) {
        if (value instanceof Handle handle && EgressRules.isEgress(handle)) {
            record(method, handle.getName() + handle.getDesc(), "method handle");
            return EgressRules.rewrite(handle);
        }
        if (value instanceof ConstantDynamic constant) {
            Object[] arguments = new Object[constant.getBootstrapMethodArgumentCount()];
            for (int i = 0; i < arguments.length; i++) {
                arguments[i] = constant.getBootstrapMethodArgument(i);
            }
            return new ConstantDynamic(constant.getName(), constant.getDescriptor(),
                constant.getBootstrapMethod(), rewriteConstants(method, arguments));
        }
        return value;
    }

    private void record(String method, String api, String kind) {
        sites.add(new TransformReport.EgressSite(entry, className, method, api, kind, origin));
    }
}
