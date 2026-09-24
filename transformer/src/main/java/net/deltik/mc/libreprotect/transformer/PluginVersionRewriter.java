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

/**
 * Has CoreProtect compare the version that upstream's build gave it, rather
 * than LibreProtect's version.
 *
 * <p>CoreProtect reads its own version from plugin.yml, whose version is
 * LibreProtect's, and takes the part before the first dash in
 * {@code VersionUtils.getPluginVersion()}. It compares that with the versions
 * in its database and patches, and with the versions where features begin,
 * such as storing skull texture signatures from 24.1 on. LibreProtect's
 * development builds are named after upstream's nearest release tag, which
 * can be older than the version in upstream's pom, since upstream sometimes
 * tags a release on a branch of its own. So in that method, the plugin.yml
 * version that it reads becomes the version that upstream's plugin.yml
 * declares, and the method does with it what it does. Everything else that
 * reads the version, such as {@code /co status}, still shows LibreProtect's.
 *
 * <p>The method is matched by name, like {@link EditionGateRewriter}'s
 * checks, and {@link Transformer} requires exactly one such read.
 */
final class PluginVersionRewriter extends ClassVisitor {

    static final String METHOD = "getPluginVersion";
    static final String DESCRIPTOR = "()Ljava/lang/String;";
    static final String DESCRIPTION = "org/bukkit/plugin/PluginDescriptionFile";
    static final String GET_VERSION = "getVersion";

    private final String entry;
    private final String version;
    private final List<TransformReport.PluginVersionRead> reads;
    private String className;

    /**
     * @param version the version that upstream's plugin.yml declares
     */
    PluginVersionRewriter(ClassVisitor next, String entry, String version,
                          List<TransformReport.PluginVersionRead> reads) {
        super(Opcodes.ASM9, next);
        this.entry = entry;
        this.version = version;
        this.reads = reads;
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        className = name;
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        MethodVisitor next = super.visitMethod(access, name, descriptor, signature, exceptions);
        if ((access & Opcodes.ACC_STATIC) == 0 || !METHOD.equals(name) || !DESCRIPTOR.equals(descriptor)) {
            return next;
        }
        return new MethodVisitor(Opcodes.ASM9, next) {
            @Override
            public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                if (opcode == Opcodes.INVOKEVIRTUAL && DESCRIPTION.equals(owner) && GET_VERSION.equals(name)
                    && DESCRIPTOR.equals(descriptor)) {
                    // The description stays evaluated as before; only the version it gives is replaced
                    super.visitInsn(Opcodes.POP);
                    super.visitLdcInsn(version);
                    reads.add(new TransformReport.PluginVersionRead(entry, className, METHOD + DESCRIPTOR, version));
                    return;
                }
                super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
            }
        };
    }
}
