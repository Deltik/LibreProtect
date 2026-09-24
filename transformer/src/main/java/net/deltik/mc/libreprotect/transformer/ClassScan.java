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

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Read-only facts about one class, collected from its instructions rather
 * than its constant pool, so references left unused by a rewrite don't count.
 */
final class ClassScan {

    /** A method that the class's code calls */
    record Call(int opcode, String owner, String name, String descriptor) {
    }

    final String name;
    final Set<String> strings = new LinkedHashSet<>();
    final List<Call> calls = new ArrayList<>();
    final List<Handle> handles = new ArrayList<>();

    private ClassScan(String name) {
        this.name = name;
    }

    static ClassScan of(byte[] bytes) {
        ClassReader reader = new ClassReader(bytes);
        ClassScan scan = new ClassScan(reader.getClassName());
        reader.accept(scan.new Collector(), ClassReader.SKIP_FRAMES);
        return scan;
    }

    /**
     * @return the class file version from the header, including the minor version
     */
    static int readVersion(byte[] bytes) {
        int minor = ((bytes[4] & 0xFF) << 8) | (bytes[5] & 0xFF);
        int major = ((bytes[6] & 0xFF) << 8) | (bytes[7] & 0xFF);
        return (minor << 16) | major;
    }

    boolean hasRawEgress() {
        for (Call call : calls) {
            if (call.opcode == Opcodes.INVOKEVIRTUAL && EgressRules.isEgress(call.owner, call.name, call.descriptor)) {
                return true;
            }
        }
        for (Handle handle : handles) {
            if (EgressRules.isEgress(handle)) {
                return true;
            }
        }
        return false;
    }

    private final class Collector extends ClassVisitor {

        Collector() {
            super(Opcodes.ASM9);
        }

        @Override
        public MethodVisitor visitMethod(int access, String methodName, String methodDescriptor,
                                         String signature, String[] exceptions) {
            return new MethodVisitor(Opcodes.ASM9) {
                @Override
                public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                    calls.add(new Call(opcode, owner, name, descriptor));
                }

                @Override
                public void visitLdcInsn(Object value) {
                    constant(value);
                }

                @Override
                public void visitInvokeDynamicInsn(String name, String descriptor, Handle bootstrapMethodHandle,
                                                   Object... bootstrapMethodArguments) {
                    handles.add(bootstrapMethodHandle);
                    for (Object argument : bootstrapMethodArguments) {
                        constant(argument);
                    }
                }
            };
        }

        private void constant(Object value) {
            if (value instanceof String string) {
                strings.add(string);
            } else if (value instanceof Handle handle) {
                handles.add(handle);
            } else if (value instanceof ConstantDynamic constant) {
                handles.add(constant.getBootstrapMethod());
                for (int i = 0; i < constant.getBootstrapMethodArgumentCount(); i++) {
                    constant(constant.getBootstrapMethodArgument(i));
                }
            }
        }
    }
}
