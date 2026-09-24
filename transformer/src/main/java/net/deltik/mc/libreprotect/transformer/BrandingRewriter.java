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
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.List;
import java.util.Set;

/**
 * Applies {@link BrandingRules} to one of CoreProtect's classes:
 * <ul>
 *   <li>rebrands text constants: {@code ldc} strings, string concatenation
 *       recipes and constant field values;</li>
 *   <li>passes each phrase renderer result, with the phrase and its
 *       parameters, through {@code Branding.phrase};</li>
 *   <li>sends Bukkit {@code sendMessage(String)} and {@code Logger} message
 *       calls through {@code Branding}, which leaves out dropped phrases.</li>
 * </ul>
 */
final class BrandingRewriter extends ClassVisitor {

    static final String KIND_TEXT = "text";
    static final String KIND_PHRASE = "phrase";
    static final String KIND_OUTPUT = "output";

    private static final String STRING_CONCAT_FACTORY = "java/lang/invoke/StringConcatFactory";

    private final String entry;
    private final Set<String> phraseRenderers;
    private final List<TransformReport.BrandingSite> sites;
    private String className;

    /**
     * @param phraseRenderers {@link BrandingRules#key keys} of the phrase renderers to hook
     */
    BrandingRewriter(ClassVisitor next, String entry, Set<String> phraseRenderers,
                     List<TransformReport.BrandingSite> sites) {
        super(Opcodes.ASM9, next);
        this.entry = entry;
        this.phraseRenderers = phraseRenderers;
        this.sites = sites;
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        className = name;
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public FieldVisitor visitField(int access, String name, String descriptor, String signature, Object value) {
        return super.visitField(access, name, descriptor, signature, rebrand(name, value));
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        String member = name + descriptor;
        return new MethodVisitor(Opcodes.ASM9, super.visitMethod(access, name, descriptor, signature, exceptions)) {
            private boolean duplicatedArguments;

            @Override
            public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                if (opcode == Opcodes.INVOKESTATIC && phraseRenderers.contains(BrandingRules.key(owner, name, descriptor))) {
                    // Keep the phrase and its parameters for the hook: phrase, params -> phrase, params, rendered
                    super.visitInsn(Opcodes.DUP2);
                    super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
                    super.visitMethodInsn(Opcodes.INVOKESTATIC, BrandingRules.BRANDING, BrandingRules.PHRASE_HOOK,
                        BrandingRules.PHRASE_HOOK_DESCRIPTOR, false);
                    duplicatedArguments = true;
                    record(member, KIND_PHRASE, owner.replace('/', '.') + "." + name, null);
                    return;
                }
                if (BrandingRules.isSendMessage(opcode, owner, name, descriptor)) {
                    super.visitMethodInsn(Opcodes.INVOKESTATIC, BrandingRules.BRANDING, name,
                        BrandingRules.SEND_MESSAGE_HOOK_DESCRIPTOR, false);
                    record(member, KIND_OUTPUT, owner.replace('/', '.') + "." + name, null);
                    return;
                }
                String loggerHook = BrandingRules.loggerHook(opcode, owner, name, descriptor);
                if (loggerHook != null) {
                    super.visitMethodInsn(Opcodes.INVOKESTATIC, BrandingRules.BRANDING, name, loggerHook, false);
                    record(member, KIND_OUTPUT, owner.replace('/', '.') + "." + name, null);
                    return;
                }
                super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
            }

            @Override
            public void visitLdcInsn(Object value) {
                super.visitLdcInsn(rebrand(member, value));
            }

            @Override
            public void visitInvokeDynamicInsn(String name, String descriptor, Handle bootstrapMethodHandle,
                                               Object... bootstrapMethodArguments) {
                Object[] arguments = bootstrapMethodArguments;
                if (STRING_CONCAT_FACTORY.equals(bootstrapMethodHandle.getOwner())) {
                    arguments = bootstrapMethodArguments.clone();
                    for (int i = 0; i < arguments.length; i++) {
                        arguments[i] = rebrand(member, arguments[i]);
                    }
                }
                super.visitInvokeDynamicInsn(name, descriptor, bootstrapMethodHandle, arguments);
            }

            @Override
            public void visitMaxs(int maxStack, int maxLocals) {
                super.visitMaxs(duplicatedArguments ? maxStack + 2 : maxStack, maxLocals);
            }
        };
    }

    private Object rebrand(String member, Object value) {
        if (!(value instanceof String text)) {
            return value;
        }
        String rebranded = BrandingRules.rebrand(text);
        if (rebranded != text) {
            record(member, KIND_TEXT, text, rebranded);
        }
        return rebranded;
    }

    private void record(String member, String kind, String before, String after) {
        sites.add(new TransformReport.BrandingSite(entry, className, member, kind, before, after));
    }
}
