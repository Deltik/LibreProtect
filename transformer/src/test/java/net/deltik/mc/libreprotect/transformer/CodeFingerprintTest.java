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

import net.deltik.mc.libreprotect.transformer.fixture.BrandingFixture;
import net.deltik.mc.libreprotect.transformer.fixture.EgressFixture;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CodeFingerprintTest {

    private static final String OWNER = "net/coreprotect/Counter";

    /**
     * How to write {@code static int count(int n)}, which sums the numbers below n.
     *
     * @param firstLine   the line number of its first statement, or 0 for no debug information
     * @param totalName   the name of its local variable for the sum
     * @param step        how much the loop counter goes up by
     * @param access      its access flags
     * @param paddedPool  whether to put unrelated constants first in the constant pool
     */
    private record Counter(int firstLine, String totalName, int step, int access, boolean paddedPool) {

        static Counter plain() {
            return new Counter(10, "total", 1, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, false);
        }

        Counter withDebug(int line, String name) {
            return new Counter(line, name, step, access, paddedPool);
        }

        Counter withStep(int value) {
            return new Counter(firstLine, totalName, value, access, paddedPool);
        }

        Counter withAccess(int flags) {
            return new Counter(firstLine, totalName, step, flags, paddedPool);
        }

        Counter padded() {
            return new Counter(firstLine, totalName, step, access, true);
        }

        byte[] bytes() {
            ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
            if (paddedPool) {
                writer.newConst("unrelated");
                writer.newConst(42L);
                writer.newClass("java/lang/Thread");
            }
            writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, OWNER, null, "java/lang/Object", null);
            MethodVisitor method = writer.visitMethod(access, "count", "(I)I", null, null);
            method.visitCode();
            Label start = new Label();
            Label loop = new Label();
            Label done = new Label();
            method.visitLabel(start);
            if (firstLine > 0) {
                method.visitLineNumber(firstLine, start);
            }
            method.visitInsn(Opcodes.ICONST_0);
            method.visitVarInsn(Opcodes.ISTORE, 1);
            method.visitInsn(Opcodes.ICONST_0);
            method.visitVarInsn(Opcodes.ISTORE, 2);
            method.visitLabel(loop);
            if (firstLine > 0) {
                method.visitLineNumber(firstLine + 1, loop);
            }
            method.visitVarInsn(Opcodes.ILOAD, 2);
            method.visitVarInsn(Opcodes.ILOAD, 0);
            method.visitJumpInsn(Opcodes.IF_ICMPGE, done);
            method.visitVarInsn(Opcodes.ILOAD, 1);
            method.visitVarInsn(Opcodes.ILOAD, 2);
            method.visitInsn(Opcodes.IADD);
            method.visitVarInsn(Opcodes.ISTORE, 1);
            method.visitIincInsn(2, step);
            method.visitJumpInsn(Opcodes.GOTO, loop);
            method.visitLabel(done);
            method.visitVarInsn(Opcodes.ILOAD, 1);
            method.visitInsn(Opcodes.IRETURN);
            Label end = new Label();
            method.visitLabel(end);
            if (firstLine > 0) {
                method.visitLocalVariable("n", "I", null, start, end, 0);
                method.visitLocalVariable(totalName, "I", null, start, end, 1);
                method.visitLocalVariable("i", "I", null, loop, end, 2);
            }
            method.visitMaxs(0, 0);
            method.visitEnd();
            writer.visitEnd();
            return writer.toByteArray();
        }

        String fingerprint() {
            return CodeFingerprint.of(bytes(), "count", "(I)I");
        }
    }

    @Test
    @DisplayName("is the start of a SHA-256")
    void format() {
        assertTrue(Counter.plain().fingerprint().matches("[0-9a-f]{12}"), Counter.plain().fingerprint());
    }

    @Test
    @DisplayName("ignores line numbers, local variable names and debug information")
    void debugInformation() {
        String fingerprint = Counter.plain().fingerprint();
        assertEquals(fingerprint, Counter.plain().withDebug(250, "sum").fingerprint());
        assertEquals(fingerprint, Counter.plain().withDebug(0, null).fingerprint());
    }

    @Test
    @DisplayName("ignores the order of the constant pool")
    void constantPool() {
        assertEquals(Counter.plain().fingerprint(), Counter.plain().padded().fingerprint());
    }

    @Test
    @DisplayName("keeps the fingerprint of compiled code when its debug information is stripped")
    void compiledCode() {
        for (Class<?> type : List.of(EgressFixture.class, BrandingFixture.class)) {
            byte[] compiled = TestClasses.bytesOf(type);
            ClassNode withDebug = new ClassNode();
            new ClassReader(compiled).accept(withDebug, 0);
            assertTrue(withDebug.methods.stream().anyMatch(method -> method.instructions.size() > 0
                && method.localVariables != null && !method.localVariables.isEmpty()), "compiled with -g");

            ClassWriter writer = new ClassWriter(0);
            new ClassReader(compiled).accept(writer, ClassReader.SKIP_DEBUG);
            byte[] stripped = writer.toByteArray();
            for (MethodNode method : withDebug.methods) {
                String fingerprint = CodeFingerprint.of(compiled, method.name, method.desc);
                assertNotEquals(CodeFingerprint.ABSENT, fingerprint);
                assertEquals(fingerprint, CodeFingerprint.of(stripped, method.name, method.desc),
                    type.getSimpleName() + "#" + method.name + method.desc);
            }
        }
    }

    @Test
    @DisplayName("changes when an instruction changes")
    void instruction() {
        assertNotEquals(Counter.plain().fingerprint(), Counter.plain().withStep(2).fingerprint());
    }

    @Test
    @DisplayName("changes when the method becomes synchronized")
    void accessFlags() {
        assertNotEquals(Counter.plain().fingerprint(), Counter.plain()
            .withAccess(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNCHRONIZED).fingerprint());
    }

    @Test
    @DisplayName("changes when a jump goes elsewhere")
    void jumpTarget() {
        String fingerprint = Counter.plain().fingerprint();
        ClassNode node = new ClassNode();
        new ClassReader(Counter.plain().bytes()).accept(node, 0);
        MethodNode count = node.methods.stream().filter(method -> method.name.equals("count")).findFirst()
            .orElseThrow();
        // Exit the loop to its start instead of its end
        List<JumpInsnNode> jumps = Arrays.stream(count.instructions.toArray())
            .filter(JumpInsnNode.class::isInstance).map(JumpInsnNode.class::cast).toList();
        assertEquals(List.of(Opcodes.IF_ICMPGE, Opcodes.GOTO), jumps.stream().map(JumpInsnNode::getOpcode).toList());
        jumps.get(0).label = jumps.get(1).label;
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        node.accept(writer);
        assertNotEquals(fingerprint, CodeFingerprint.of(writer.toByteArray(), "count", "(I)I"));
    }

    /**
     * @return a class whose {@code run()} calls a lambda, which stores the value
     */
    private static byte[] lambdaClass(int value, String lambdaName) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, OWNER, null, "java/lang/Object", null);
        Handle metafactory = new Handle(Opcodes.H_INVOKESTATIC, "java/lang/invoke/LambdaMetafactory", "metafactory",
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;"
                + "Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)"
                + "Ljava/lang/invoke/CallSite;", false);
        MethodVisitor run = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
        run.visitCode();
        run.visitInvokeDynamicInsn("run", "()Ljava/lang/Runnable;", metafactory, Type.getType("()V"),
            new Handle(Opcodes.H_INVOKESTATIC, OWNER, lambdaName, "()V", false), Type.getType("()V"));
        run.visitMethodInsn(Opcodes.INVOKEINTERFACE, "java/lang/Runnable", "run", "()V", true);
        run.visitInsn(Opcodes.RETURN);
        run.visitMaxs(0, 0);
        run.visitEnd();
        storing(writer, Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC, lambdaName, value, null);
        writer.visitEnd();
        return writer.toByteArray();
    }

    /**
     * Add a static method that stores the value, then calls the next method, if any.
     */
    private static void storing(ClassWriter writer, int access, String name, int value, String next) {
        MethodVisitor method = writer.visitMethod(access, name, "()V", null, null);
        method.visitCode();
        method.visitLdcInsn(value);
        method.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "state", "I");
        if (next != null) {
            method.visitMethodInsn(Opcodes.INVOKESTATIC, OWNER, next, "()V", false);
        }
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
    }

    /**
     * @return a class whose {@code run()} calls {@code step0()}, which calls {@code step1()}, and so on; each
     *         stores its number, or the changed value
     */
    private static byte[] chainClass(int helperAccess, int length, int changed, int value) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, OWNER, null, "java/lang/Object", null);
        storing(writer, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", -1, "step0");
        for (int i = 0; i < length; i++) {
            storing(writer, helperAccess | Opcodes.ACC_STATIC, "step" + i, i == changed ? value : i,
                i + 1 < length ? "step" + (i + 1) : "run");
        }
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static String run(byte[] classBytes) {
        return CodeFingerprint.of(classBytes, "run", "()V");
    }

    @Test
    @DisplayName("covers the bodies of the method's lambdas, whatever they are named")
    void lambda() {
        String fingerprint = run(lambdaClass(1, "lambda$run$0"));
        assertNotEquals(fingerprint, run(lambdaClass(2, "lambda$run$0")));
        assertEquals(fingerprint, run(lambdaClass(1, "lambda$run$3")));
    }

    @Test
    @DisplayName("covers the private methods of its class that it calls, and theirs")
    void privateHelpers() {
        int access = Opcodes.ACC_PRIVATE;
        String fingerprint = run(chainClass(access, 3, -1, 0));
        assertNotEquals(fingerprint, run(chainClass(access, 3, 0, 100)));
        assertNotEquals(fingerprint, run(chainClass(access, 3, 2, 100)), "a helper of a helper");
    }

    @Test
    @DisplayName("doesn't cover methods of its class that subclasses may override")
    void nonPrivateMethods() {
        assertEquals(run(chainClass(Opcodes.ACC_PUBLIC, 3, -1, 0)), run(chainClass(Opcodes.ACC_PUBLIC, 3, 0, 100)));
    }

    @Test
    @DisplayName("covers at most " + CodeFingerprint.MAX_METHODS + " methods, the first ones it refers to")
    void bounded() {
        int access = Opcodes.ACC_PRIVATE;
        String fingerprint = run(chainClass(access, 100, -1, 0));
        assertNotEquals(fingerprint, run(chainClass(access, 100, CodeFingerprint.MAX_METHODS - 2, 1000)));
        assertEquals(fingerprint, run(chainClass(access, 100, CodeFingerprint.MAX_METHODS - 1, 1000)));
        assertEquals(fingerprint, run(chainClass(access, 100, 90, 1000)));
    }

    private static final String NESTED = OWNER + "$1Task";

    /**
     * @param version the class file version: before Java 11, a class file has no nest attributes
     * @return a JAR whose nested class's {@code run()} calls a static method of the target
     *         class, which stores the value
     */
    private static JarContents nestedCall(int version, String target, int access, String name, int value) {
        boolean nests = version >= Opcodes.V11;
        ClassWriter nested = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        nested.visit(version, Opcodes.ACC_SUPER, NESTED, null, "java/lang/Object", null);
        if (nests) {
            nested.visitNestHost(OWNER);
        }
        MethodVisitor run = nested.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
        run.visitCode();
        run.visitMethodInsn(Opcodes.INVOKESTATIC, target, name, "()V", false);
        run.visitInsn(Opcodes.RETURN);
        run.visitMaxs(0, 0);
        run.visitEnd();
        nested.visitEnd();

        ClassWriter outer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        outer.visit(version, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, target, null, "java/lang/Object", null);
        if (nests && target.equals(OWNER)) {
            outer.visitNestMember(NESTED);
        }
        storing(outer, access | Opcodes.ACC_STATIC, name, value, null);
        outer.visitEnd();

        JarContents jar = new JarContents();
        jar.put(NESTED + ".class", nested.toByteArray());
        jar.put(target + ".class", outer.toByteArray());
        return jar;
    }

    private static String nestedRun(JarContents jar) {
        return CodeFingerprint.of(jar, NESTED + "#run()V");
    }

    @Test
    @DisplayName("covers the accessors and private methods of its outer class that a nested class calls")
    void outerClass() {
        int accessor = Opcodes.ACC_SYNTHETIC;
        String fingerprint = nestedRun(nestedCall(Opcodes.V1_8, OWNER, accessor, "access$000", 1));
        assertNotEquals(fingerprint, nestedRun(nestedCall(Opcodes.V1_8, OWNER, accessor, "access$000", 2)),
            "an accessor, which Java 8 class files call");
        assertEquals(fingerprint, nestedRun(nestedCall(Opcodes.V1_8, OWNER, accessor, "access$100", 1)),
            "an accessor that is only renumbered");

        String nestmate = nestedRun(nestedCall(Opcodes.V11, OWNER, Opcodes.ACC_PRIVATE, "helper", 1));
        assertNotEquals(nestmate, nestedRun(nestedCall(Opcodes.V11, OWNER, Opcodes.ACC_PRIVATE, "helper", 2)),
            "a private method, which nestmates call directly");
    }

    @Test
    @DisplayName("doesn't cover methods of another nest, nor the non-private methods of its outer class")
    void otherClasses() {
        String other = "net/coreprotect/Other";
        assertEquals(nestedRun(nestedCall(Opcodes.V1_8, other, Opcodes.ACC_SYNTHETIC, "access$000", 1)),
            nestedRun(nestedCall(Opcodes.V1_8, other, Opcodes.ACC_SYNTHETIC, "access$000", 2)));
        assertEquals(nestedRun(nestedCall(Opcodes.V11, other, Opcodes.ACC_SYNTHETIC, "access$000", 1)),
            nestedRun(nestedCall(Opcodes.V11, other, Opcodes.ACC_SYNTHETIC, "access$000", 2)));
        assertEquals(nestedRun(nestedCall(Opcodes.V1_8, OWNER, Opcodes.ACC_PUBLIC, "helper", 1)),
            nestedRun(nestedCall(Opcodes.V1_8, OWNER, Opcodes.ACC_PUBLIC, "helper", 2)));
    }

    @Test
    @DisplayName("is absent for a class or method that isn't there")
    void absent() {
        assertEquals(CodeFingerprint.ABSENT, CodeFingerprint.of(null, "count", "(I)I"));
        assertEquals(CodeFingerprint.ABSENT, CodeFingerprint.of(Counter.plain().bytes(), "count", "(J)I"));
        assertEquals(CodeFingerprint.ABSENT, CodeFingerprint.of(Counter.plain().bytes(), "total", "(I)I"));

        JarContents jar = new JarContents();
        jar.put(OWNER + ".class", Counter.plain().bytes());
        assertEquals(Counter.plain().fingerprint(), CodeFingerprint.of(jar, OWNER + "#count(I)I"));
        assertEquals(CodeFingerprint.ABSENT, CodeFingerprint.of(jar, "net/coreprotect/Other#count(I)I"));
        assertEquals(CodeFingerprint.ABSENT, CodeFingerprint.of(jar, OWNER + "#hashCode()I"),
            "a method that the class inherits but doesn't declare");
    }
}
