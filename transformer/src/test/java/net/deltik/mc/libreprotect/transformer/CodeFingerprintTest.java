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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

    /**
     * @return a class whose instance method {@code run()} calls its instance method {@code helper()}, which
     *         stores the value
     */
    private static byte[] virtualClass(int classAccess, int helperAccess, int value) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, classAccess | Opcodes.ACC_SUPER, OWNER, null, "java/lang/Object", null);
        MethodVisitor run = writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
        run.visitCode();
        run.visitVarInsn(Opcodes.ALOAD, 0);
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL, OWNER, "helper", "()V", false);
        run.visitInsn(Opcodes.RETURN);
        run.visitMaxs(0, 0);
        run.visitEnd();
        storing(writer, helperAccess, "helper", value, null);
        writer.visitEnd();
        return writer.toByteArray();
    }

    /**
     * @return a class whose {@code run()} creates one of it, with a constructor that stores the value
     */
    private static byte[] constructorClass(int value) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, OWNER, null, "java/lang/Object", null);
        MethodVisitor run = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
        run.visitCode();
        run.visitTypeInsn(Opcodes.NEW, OWNER);
        run.visitInsn(Opcodes.DUP);
        run.visitMethodInsn(Opcodes.INVOKESPECIAL, OWNER, "<init>", "()V", false);
        run.visitInsn(Opcodes.POP);
        run.visitInsn(Opcodes.RETURN);
        run.visitMaxs(0, 0);
        run.visitEnd();
        MethodVisitor constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        constructor.visitCode();
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        constructor.visitLdcInsn(value);
        constructor.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "state", "I");
        constructor.visitInsn(Opcodes.RETURN);
        constructor.visitMaxs(0, 0);
        constructor.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    @Test
    @DisplayName("covers the static methods and constructors of its class, which no subclass overrides, and theirs")
    void staticMethodsAndConstructors() {
        int access = Opcodes.ACC_PUBLIC;
        String fingerprint = run(chainClass(access, 3, -1, 0));
        assertNotEquals(fingerprint, run(chainClass(access, 3, 0, 100)));
        assertNotEquals(fingerprint, run(chainClass(access, 3, 2, 100)), "a helper of a helper");
        assertNotEquals(run(constructorClass(1)), run(constructorClass(2)));
    }

    @Test
    @DisplayName("covers the final methods of its class, and the methods of a final class")
    void finalMethods() {
        assertNotEquals(run(virtualClass(Opcodes.ACC_PUBLIC, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, 1)),
            run(virtualClass(Opcodes.ACC_PUBLIC, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, 2)));
        assertNotEquals(run(virtualClass(Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, Opcodes.ACC_PUBLIC, 1)),
            run(virtualClass(Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, Opcodes.ACC_PUBLIC, 2)));
    }

    @Test
    @DisplayName("doesn't cover methods of its class that subclasses may override")
    void overridableMethods() {
        assertEquals(run(virtualClass(Opcodes.ACC_PUBLIC, Opcodes.ACC_PUBLIC, 1)),
            run(virtualClass(Opcodes.ACC_PUBLIC, Opcodes.ACC_PUBLIC, 2)));
        assertEquals(run(virtualClass(Opcodes.ACC_PUBLIC, Opcodes.ACC_PROTECTED, 1)),
            run(virtualClass(Opcodes.ACC_PUBLIC, Opcodes.ACC_PROTECTED, 2)));
    }

    @Test
    @DisplayName("covers at most " + CodeFingerprint.MAX_METHODS + " methods, the first ones it refers to, and says so")
    void bounded() {
        int access = Opcodes.ACC_PRIVATE;
        int length = CodeFingerprint.MAX_METHODS + 36;
        String fingerprint = run(chainClass(access, length, -1, 0));
        assertTrue(CodeFingerprint.truncated(fingerprint), fingerprint);
        assertNotEquals(fingerprint, run(chainClass(access, length, CodeFingerprint.MAX_METHODS - 2, 1000)));
        assertEquals(fingerprint, run(chainClass(access, length, CodeFingerprint.MAX_METHODS - 1, 1000)));
        assertEquals(fingerprint, run(chainClass(access, length, CodeFingerprint.MAX_METHODS + 26, 1000)));

        String all = run(chainClass(access, CodeFingerprint.MAX_METHODS - 1, -1, 0));
        assertFalse(CodeFingerprint.truncated(all), "the method and " + (CodeFingerprint.MAX_METHODS - 1) + " more");
        assertTrue(all.matches("[0-9a-f]{" + CodeFingerprint.LENGTH + "}"), all);
    }

    /**
     * @return a class whose {@code run()} reads a static field that its static initializer sets to the value
     */
    private static byte[] initializedClass(int value) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, OWNER, null, "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL, "TABLES", "I", null, null)
            .visitEnd();
        MethodVisitor run = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
        run.visitCode();
        run.visitFieldInsn(Opcodes.GETSTATIC, OWNER, "TABLES", "I");
        run.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "state", "I");
        run.visitInsn(Opcodes.RETURN);
        run.visitMaxs(0, 0);
        run.visitEnd();
        MethodVisitor initializer = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        initializer.visitCode();
        initializer.visitLdcInsn(value);
        initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "TABLES", "I");
        initializer.visitInsn(Opcodes.RETURN);
        initializer.visitMaxs(0, 0);
        initializer.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    @Test
    @DisplayName("covers the static initializer that gives the static fields it reads their values")
    void staticInitializer() {
        assertNotEquals(run(initializedClass(1)), run(initializedClass(2)));
    }

    /** A statement of a static initializer, as its instructions */
    private interface Statement {
        void write(MethodVisitor initializer);
    }

    /**
     * @return a statement that stores an int into a static field of the class, from a constant, or with
     *         {@code shared}, from a method of a class outside the JAR, whose code it can't tell
     */
    private static Statement store(String field, int value, boolean shared) {
        return initializer -> {
            initializer.visitLdcInsn(value);
            if (shared) {
                initializer.visitMethodInsn(Opcodes.INVOKESTATIC, "net/coreprotect/Other", "of", "(I)I", false);
            }
            initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, field, "I");
        };
    }

    /**
     * @param read       the int field of the class that {@code run()} reads
     * @param statements the static initializer's statements, each on the line of its position, from line 10
     * @param more       more members of the class
     * @return a class with static int fields A, B and C, and static Object fields M and N
     */
    private static byte[] fieldsClass(String read, List<Statement> statements, boolean tryCatch,
                                      Consumer<ClassWriter> more) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, OWNER, null, "java/lang/Object", null);
        for (String field : List.of("A", "B", "C")) {
            writer.visitField(Opcodes.ACC_STATIC, field, "I", null, null).visitEnd();
        }
        writer.visitField(Opcodes.ACC_STATIC, "M", "Ljava/lang/Object;", null, null).visitEnd();
        writer.visitField(Opcodes.ACC_STATIC, "N", "Ljava/lang/Object;", null, null).visitEnd();
        MethodVisitor run = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
        run.visitCode();
        line(run, 1);
        run.visitFieldInsn(Opcodes.GETSTATIC, OWNER, read, read.equals("M") ? "Ljava/lang/Object;" : "I");
        run.visitInsn(Opcodes.POP);
        run.visitInsn(Opcodes.RETURN);
        run.visitMaxs(0, 0);
        run.visitEnd();
        MethodVisitor initializer = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        initializer.visitCode();
        Label start = new Label();
        Label end = new Label();
        if (tryCatch) {
            initializer.visitTryCatchBlock(start, end, end, "java/lang/RuntimeException");
        }
        initializer.visitLabel(start);
        for (int i = 0; i < statements.size(); i++) {
            line(initializer, 10 + i);
            statements.get(i).write(initializer);
        }
        line(initializer, 10 + statements.size());
        initializer.visitInsn(Opcodes.RETURN);
        if (tryCatch) {
            initializer.visitLabel(end);
            initializer.visitInsn(Opcodes.POP);
            initializer.visitInsn(Opcodes.RETURN);
        }
        initializer.visitMaxs(0, 0);
        initializer.visitEnd();
        more.accept(writer);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] fieldsClass(String read, Statement... statements) {
        return fieldsClass(read, List.of(statements), false, writer -> { });
    }

    @Test
    @DisplayName("covers the statements that only give other fields their values only where it uses those fields")
    void ownInitializers() {
        String fingerprint = run(fieldsClass("A", store("A", 1, false), store("B", 2, false)));
        assertNotEquals(fingerprint, run(fieldsClass("A", store("A", 3, false), store("B", 2, false))));
        assertEquals(fingerprint, run(fieldsClass("A", store("A", 1, false), store("B", 4, false))), "B changed");
        assertEquals(fingerprint, run(fieldsClass("A", store("A", 1, false))), "B removed");
        assertEquals(fingerprint, run(fieldsClass("A", store("C", 5, false), store("A", 1, false),
            store("B", 2, false))), "C added before it");
        assertNotEquals(fingerprint, run(fieldsClass("A", store("A", 1, false), store("A", 6, false))),
            "A given another value after");
    }

    @Test
    @DisplayName("covers every statement that may do more than give one field its value, wherever it uses any")
    void sharedStatements() {
        // Calls a method that the fingerprint can't see
        String fingerprint = run(fieldsClass("A", store("A", 1, false), store("B", 2, true)));
        assertNotEquals(fingerprint, run(fieldsClass("A", store("A", 1, false), store("B", 4, true))));

        // Reads another field
        Statement copy = initializer -> {
            initializer.visitFieldInsn(Opcodes.GETSTATIC, OWNER, "A", "I");
            initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "C", "I");
        };
        assertNotEquals(run(fieldsClass("B", store("A", 1, false), copy)),
            run(fieldsClass("B", store("A", 1, false), store("C", 1, false))));

        // B = C = 7, which leaves a value on the stack for the next putstatic
        Statement chained = initializer -> {
            initializer.visitLdcInsn(7);
            initializer.visitInsn(Opcodes.DUP);
            initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "C", "I");
            initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "B", "I");
        };
        Statement chainedOther = initializer -> {
            initializer.visitLdcInsn(8);
            initializer.visitInsn(Opcodes.DUP);
            initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "C", "I");
            initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "B", "I");
        };
        assertNotEquals(run(fieldsClass("B", store("A", 1, false), chained)),
            run(fieldsClass("B", store("A", 1, false), chainedOther)));

        // A statement that stores nothing, as a static block's call
        Statement call = initializer -> {
            initializer.visitMethodInsn(Opcodes.INVOKESTATIC, "net/coreprotect/Other", "init", "()V", false);
        };
        assertNotEquals(run(fieldsClass("A", store("A", 1, false))),
            run(fieldsClass("A", store("A", 1, false), call)));

        // A jump, which may skip other statements
        Statement jump = initializer -> {
            Label skip = new Label();
            initializer.visitInsn(Opcodes.ICONST_0);
            initializer.visitJumpInsn(Opcodes.IFEQ, skip);
            initializer.visitLabel(skip);
            initializer.visitInsn(Opcodes.ICONST_2);
            initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "B", "I");
        };
        assertNotEquals(run(fieldsClass("A", store("A", 1, false), store("B", 2, false))),
            run(fieldsClass("A", store("A", 1, false), jump)));
    }

    @Test
    @DisplayName("covers all of a static initializer with exception handlers, or the one it fingerprints")
    void wholeInitializer() {
        assertNotEquals(run(fieldsClass("A", List.of(store("A", 1, false), store("B", 2, false)), true, writer -> { })),
            run(fieldsClass("A", List.of(store("A", 1, false), store("B", 4, false)), true, writer -> { })));
        assertNotEquals(CodeFingerprint.of(fieldsClass("A", store("A", 1, false), store("B", 2, false)),
                "<clinit>", "()V"),
            CodeFingerprint.of(fieldsClass("A", store("A", 1, false), store("B", 4, false)), "<clinit>", "()V"));
    }

    /**
     * @return a static method {@code make()} of the class that returns a new object of the given class, after
     *         boxing the value, which only builds a value
     */
    private static Consumer<ClassWriter> maker(String type, int value) {
        return writer -> {
            MethodVisitor make = writer.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "make",
                "()Ljava/lang/Object;", null, null);
            make.visitCode();
            make.visitLdcInsn(value);
            make.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;",
                false);
            make.visitInsn(Opcodes.POP);
            make.visitTypeInsn(Opcodes.NEW, type);
            make.visitInsn(Opcodes.DUP);
            make.visitMethodInsn(Opcodes.INVOKESPECIAL, type, "<init>", "()V", false);
            make.visitInsn(Opcodes.ARETURN);
            make.visitMaxs(0, 0);
            make.visitEnd();
        };
    }

    private static final Statement MAKE_M = initializer -> {
        initializer.visitMethodInsn(Opcodes.INVOKESTATIC, OWNER, "make", "()Ljava/lang/Object;", false);
        initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "M", "Ljava/lang/Object;");
    };

    @Test
    @DisplayName("tells which helpers of the nest only build a value, and covers them only where it uses the field")
    void pureHelpers() {
        List<Statement> statements = List.of(store("A", 1, false), MAKE_M);
        String map = "java/util/HashMap";
        assertEquals(run(fieldsClass("A", statements, false, maker(map, 1))),
            run(fieldsClass("A", statements, false, maker(map, 2))), "a helper that only builds M");
        assertNotEquals(run(fieldsClass("M", statements, false, maker(map, 1))),
            run(fieldsClass("M", statements, false, maker(map, 2))), "where it uses M");

        // Creating an object of a class it can't see may run any code
        String unknown = "net/coreprotect/Unknown";
        assertNotEquals(run(fieldsClass("A", statements, false, maker(unknown, 1))),
            run(fieldsClass("A", statements, false, maker(unknown, 2))), "a helper that may do more");
    }

    private static final Statement COPY_A_TO_B = initializer -> {
        initializer.visitFieldInsn(Opcodes.GETSTATIC, OWNER, "A", "I");
        initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "B", "I");
    };

    /**
     * @return {@code if (Other.flag()) { A = 1; } B = 2;}, or with {@code inside},
     *         {@code if (Other.flag()) { A = 1; B = 2; }}
     */
    private static List<Statement> branch(boolean inside) {
        Label skip = new Label();
        Statement condition = initializer -> {
            initializer.visitMethodInsn(Opcodes.INVOKESTATIC, "net/coreprotect/Other", "flag", "()Z", false);
            initializer.visitJumpInsn(Opcodes.IFEQ, skip);
            initializer.visitInsn(Opcodes.ICONST_1);
            initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "A", "I");
        };
        Statement b = initializer -> {
            if (!inside) {
                initializer.visitLabel(skip);
            }
            initializer.visitInsn(Opcodes.ICONST_2);
            initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "B", "I");
            if (inside) {
                initializer.visitLabel(skip);
            }
        };
        return List.of(condition, b);
    }

    @Test
    @DisplayName("covers where the statements that give a field its value are among the rest")
    void ownPositions() {
        // B = A after A = 1, or before it
        assertNotEquals(run(fieldsClass("B", store("A", 1, false), COPY_A_TO_B)),
            run(fieldsClass("B", COPY_A_TO_B, store("A", 1, false))));
        // A = 1, then A from code it can't see, or the other way around
        assertNotEquals(run(fieldsClass("A", store("A", 1, false), store("A", 2, true))),
            run(fieldsClass("A", store("A", 2, true), store("A", 1, false))));
        // B = 2 after a branch, or in it
        assertNotEquals(run(fieldsClass("B", branch(false), false, writer -> { })),
            run(fieldsClass("B", branch(true), false, writer -> { })));
        // But not where another field's statements are
        assertEquals(run(fieldsClass("B", store("C", 3, false), store("A", 1, false), COPY_A_TO_B)),
            run(fieldsClass("B", store("A", 1, false), store("C", 3, false), COPY_A_TO_B)));
    }

    @Test
    @DisplayName("covers a statement that code jumps into wherever it uses any field")
    void enteredStatement() {
        // C's fingerprint covers B's statement, since code jumps into it, so it changes with B's value
        assertNotEquals(run(fieldsClass("C", entering(new Label(), 3), false, writer -> { })),
            run(fieldsClass("C", entering(new Label(), 4), false, writer -> { })));
        assertEquals(run(fieldsClass("C", store("A", 1, false), store("B", 3, false))),
            run(fieldsClass("C", store("A", 1, false), store("B", 4, false))), "without the jump");
    }

    /**
     * @return {@code if (Other.flag()) A = 1;} jumping past the first instruction of a statement that sets B
     */
    private static List<Statement> entering(Label target, int value) {
        return List.of(initializer -> {
            initializer.visitMethodInsn(Opcodes.INVOKESTATIC, "net/coreprotect/Other", "flag", "()Z", false);
            initializer.visitJumpInsn(Opcodes.IFEQ, target);
            initializer.visitInsn(Opcodes.ICONST_1);
            initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "A", "I");
        }, initializer -> {
            initializer.visitInsn(Opcodes.ICONST_2);
            initializer.visitInsn(Opcodes.POP);
            initializer.visitLabel(target);
            initializer.visitLdcInsn(value);
            initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "B", "I");
        });
    }

    /** {@code N = m2()} */
    private static final Statement N_FROM_M2 = initializer -> {
        initializer.visitMethodInsn(Opcodes.INVOKESTATIC, OWNER, "m2", "()Ljava/lang/Object;", false);
        initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "N", "Ljava/lang/Object;");
    };

    /** {@code N = null} */
    private static final Statement N_NULL = initializer -> {
        initializer.visitInsn(Opcodes.ACONST_NULL);
        initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "N", "Ljava/lang/Object;");
    };

    @Test
    @DisplayName("takes a helper that calls back one being checked as one that may do more")
    void recursiveHelpers() {
        // m1(r) { if (r) m2(); A++; return null; } and m2() { return m1(false); }
        Consumer<ClassWriter> helpers = writer -> {
            MethodVisitor m1 = writer.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "m1",
                "(Z)Ljava/lang/Object;", null, null);
            m1.visitCode();
            Label skip = new Label();
            m1.visitVarInsn(Opcodes.ILOAD, 0);
            m1.visitJumpInsn(Opcodes.IFEQ, skip);
            m1.visitMethodInsn(Opcodes.INVOKESTATIC, OWNER, "m2", "()Ljava/lang/Object;", false);
            m1.visitInsn(Opcodes.POP);
            m1.visitLabel(skip);
            m1.visitFieldInsn(Opcodes.GETSTATIC, OWNER, "A", "I");
            m1.visitInsn(Opcodes.ICONST_1);
            m1.visitInsn(Opcodes.IADD);
            m1.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "A", "I");
            m1.visitInsn(Opcodes.ACONST_NULL);
            m1.visitInsn(Opcodes.ARETURN);
            m1.visitMaxs(0, 0);
            m1.visitEnd();
            MethodVisitor m2 = writer.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "m2",
                "()Ljava/lang/Object;", null, null);
            m2.visitCode();
            m2.visitInsn(Opcodes.ICONST_0);
            m2.visitMethodInsn(Opcodes.INVOKESTATIC, OWNER, "m1", "(Z)Ljava/lang/Object;", false);
            m2.visitInsn(Opcodes.ARETURN);
            m2.visitMaxs(0, 0);
            m2.visitEnd();
        };
        Statement mFromM1 = initializer -> {
            initializer.visitInsn(Opcodes.ICONST_1);
            initializer.visitMethodInsn(Opcodes.INVOKESTATIC, OWNER, "m1", "(Z)Ljava/lang/Object;", false);
            initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "M", "Ljava/lang/Object;");
        };
        assertNotEquals(run(fieldsClass("A", List.of(store("A", 1, false), mFromM1, N_FROM_M2), false, helpers)),
            run(fieldsClass("A", List.of(store("A", 1, false), mFromM1, N_NULL), false, helpers)));
    }

    @Test
    @DisplayName("takes a native helper, whose code it can't see, as one that may do more")
    void nativeHelper() {
        Consumer<ClassWriter> helper = writer -> writer.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC
            | Opcodes.ACC_NATIVE, "m2", "()Ljava/lang/Object;", null, null).visitEnd();
        assertNotEquals(run(fieldsClass("A", List.of(store("A", 1, false), N_FROM_M2), false, helper)),
            run(fieldsClass("A", List.of(store("A", 1, false), N_NULL), false, helper)));
    }

    @Test
    @DisplayName("takes a call that initializes a class whose superclass may do more as one that may too")
    void initializedSuperclass() {
        String helper = OWNER + "$Helper";
        String base = OWNER + "$Base";
        ClassWriter baseWriter = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        baseWriter.visit(Opcodes.V17, Opcodes.ACC_SUPER, base, null, "java/lang/Object", null);
        baseWriter.visitNestHost(OWNER);
        MethodVisitor initializer = baseWriter.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        initializer.visitCode();
        initializer.visitInsn(Opcodes.ICONST_5);
        initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "A", "I");
        initializer.visitInsn(Opcodes.RETURN);
        initializer.visitMaxs(0, 0);
        initializer.visitEnd();
        baseWriter.visitEnd();
        ClassWriter helperWriter = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        helperWriter.visit(Opcodes.V17, Opcodes.ACC_SUPER, helper, null, base, null);
        helperWriter.visitNestHost(OWNER);
        MethodVisitor make = helperWriter.visitMethod(Opcodes.ACC_STATIC, "make", "()Ljava/lang/Object;", null,
            null);
        make.visitCode();
        make.visitInsn(Opcodes.ACONST_NULL);
        make.visitInsn(Opcodes.ARETURN);
        make.visitMaxs(0, 0);
        make.visitEnd();
        helperWriter.visitEnd();
        Map<String, byte[]> classes = Map.of(base, baseWriter.toByteArray(), helper, helperWriter.toByteArray());
        Statement nFromHelper = writer -> {
            writer.visitMethodInsn(Opcodes.INVOKESTATIC, helper, "make", "()Ljava/lang/Object;", false);
            writer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "N", "Ljava/lang/Object;");
        };
        assertNotEquals(CodeFingerprint.of(fieldsClass("A", store("A", 1, false), nFromHelper), "run", "()V",
                classes::get),
            CodeFingerprint.of(fieldsClass("A", store("A", 1, false), N_NULL), "run", "()V", classes::get));
    }

    @Test
    @DisplayName("takes a call that initializes a class whose superclasses loop as one that may do more")
    void loopingSuperclasses() {
        String x = OWNER + "$X";
        String y = OWNER + "$Y";
        Map<String, byte[]> classes = new HashMap<>();
        for (String[] type : new String[][] {{x, y}, {y, x}}) {
            ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
            writer.visit(Opcodes.V17, Opcodes.ACC_SUPER, type[0], null, type[1], null);
            writer.visitNestHost(OWNER);
            MethodVisitor make = writer.visitMethod(Opcodes.ACC_STATIC, "make", "()Ljava/lang/Object;", null, null);
            make.visitCode();
            make.visitInsn(Opcodes.ACONST_NULL);
            make.visitInsn(Opcodes.ARETURN);
            make.visitMaxs(0, 0);
            make.visitEnd();
            writer.visitEnd();
            classes.put(type[0], writer.toByteArray());
        }
        Statement nFromX = initializer -> {
            initializer.visitMethodInsn(Opcodes.INVOKESTATIC, x, "make", "()Ljava/lang/Object;", false);
            initializer.visitFieldInsn(Opcodes.PUTSTATIC, OWNER, "N", "Ljava/lang/Object;");
        };
        assertNotEquals(CodeFingerprint.of(fieldsClass("A", store("A", 1, false), nFromX), "run", "()V",
                classes::get),
            CodeFingerprint.of(fieldsClass("A", store("A", 1, false), N_NULL), "run", "()V", classes::get));
    }

    @Test
    @DisplayName("traces the lines of the statements of a static initializer that it covers")
    void initializerLines() {
        byte[] type = fieldsClass("A", store("B", 2, false), store("A", 1, false), store("C", 3, true),
            store("B", 4, false));
        Map<String, List<List<Integer>>> lines = CodeFingerprint.trace(type, "run", "()V", className -> null)
            .lines();
        // A's own statement, then C's, which may do more, then the return
        assertEquals(List.of(List.of(11, 14)), lines.get(OWNER + "#<clinit>()V"));
        byte[] spaced = fieldsClass("A", store("A", 1, false), store("B", 2, false), store("B", 2, false),
            store("B", 2, false), store("B", 2, false), store("C", 3, true));
        assertEquals(List.of(List.of(10, 10), List.of(15, 16)), CodeFingerprint.trace(spaced, "run", "()V",
            className -> null).lines().get(OWNER + "#<clinit>()V"));
    }

    private static final String BASE = OWNER + "$Base";
    private static final String SUB = OWNER + "$Sub";

    /**
     * @param helperAccess the access of the base class's {@code helper()}, which stores the value
     * @param opcode       how the subclass's {@code run()} calls it: {@code invokestatic} or
     *                     {@code invokevirtual} naming the subclass, or {@code invokespecial} naming the base
     *                     class, as {@code super.helper()} does
     * @return a JAR with a base class and a subclass of it, of one nest
     */
    private static JarContents inherited(int helperAccess, int opcode, int value) {
        ClassWriter base = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        base.visit(Opcodes.V1_8, Opcodes.ACC_SUPER, BASE, null, "java/lang/Object", null);
        storing(base, helperAccess, "helper", value, null);
        base.visitEnd();

        ClassWriter sub = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        sub.visit(Opcodes.V1_8, Opcodes.ACC_SUPER, SUB, null, BASE, null);
        MethodVisitor run = sub.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
        run.visitCode();
        if (opcode != Opcodes.INVOKESTATIC) {
            run.visitVarInsn(Opcodes.ALOAD, 0);
        }
        run.visitMethodInsn(opcode, opcode == Opcodes.INVOKESPECIAL ? BASE : SUB, "helper", "()V", false);
        run.visitInsn(Opcodes.RETURN);
        run.visitMaxs(0, 0);
        run.visitEnd();
        sub.visitEnd();

        JarContents jar = new JarContents();
        jar.put(BASE + ".class", base.toByteArray());
        jar.put(SUB + ".class", sub.toByteArray());
        return jar;
    }

    @Test
    @DisplayName("covers the inherited static and final methods that it calls, and those that super calls")
    void inheritedMethods() {
        for (int[] call : new int[][] {{Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, Opcodes.INVOKESTATIC},
            {Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, Opcodes.INVOKEVIRTUAL}, {Opcodes.ACC_PUBLIC, Opcodes.INVOKESPECIAL}}) {
            assertNotEquals(CodeFingerprint.of(inherited(call[0], call[1], 1), SUB + "#run()V"),
                CodeFingerprint.of(inherited(call[0], call[1], 2), SUB + "#run()V"), Integer.toString(call[1]));
        }
        assertEquals(CodeFingerprint.of(inherited(Opcodes.ACC_PUBLIC, Opcodes.INVOKEVIRTUAL, 1), SUB + "#run()V"),
            CodeFingerprint.of(inherited(Opcodes.ACC_PUBLIC, Opcodes.INVOKEVIRTUAL, 2), SUB + "#run()V"),
            "a method that another subclass may override");
    }

    @Test
    @DisplayName("tells which method of which class it runs, though not how the compiler numbered lambdas and accessors")
    void names() {
        int access = Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNCHRONIZED;
        String helper = nestedRun(nestedCall(Opcodes.V1_8, OWNER, access, "helper", 1));
        assertNotEquals(helper, nestedRun(nestedCall(Opcodes.V1_8, OWNER, access, "other", 1)), "renamed");
        assertNotEquals(helper, nestedRun(nestedCall(Opcodes.V1_8, OWNER + "$Other", access, "helper", 1)),
            "moved to another class of the nest, whose lock it takes");
    }

    @Test
    @DisplayName("doesn't cover a bridge method, which a subclass may override")
    void bridgeMethods() {
        int bridge = Opcodes.ACC_PUBLIC | Opcodes.ACC_BRIDGE | Opcodes.ACC_SYNTHETIC;
        assertEquals(run(virtualClass(Opcodes.ACC_PUBLIC, bridge, 1)), run(virtualClass(Opcodes.ACC_PUBLIC, bridge, 2)));
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
    @DisplayName("covers the accessors and the private and static methods of its outer class that a nested class calls")
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
        assertNotEquals(nestedRun(nestedCall(Opcodes.V1_8, OWNER, Opcodes.ACC_PUBLIC, "helper", 1)),
            nestedRun(nestedCall(Opcodes.V1_8, OWNER, Opcodes.ACC_PUBLIC, "helper", 2)), "a static method");
    }

    @Test
    @DisplayName("doesn't cover methods of another nest")
    void otherClasses() {
        String other = "net/coreprotect/Other";
        assertEquals(nestedRun(nestedCall(Opcodes.V1_8, other, Opcodes.ACC_SYNTHETIC, "access$000", 1)),
            nestedRun(nestedCall(Opcodes.V1_8, other, Opcodes.ACC_SYNTHETIC, "access$000", 2)));
        assertEquals(nestedRun(nestedCall(Opcodes.V11, other, Opcodes.ACC_SYNTHETIC, "access$000", 1)),
            nestedRun(nestedCall(Opcodes.V11, other, Opcodes.ACC_SYNTHETIC, "access$000", 2)));
        assertEquals(nestedRun(nestedCall(Opcodes.V11, other, Opcodes.ACC_PUBLIC, "helper", 1)),
            nestedRun(nestedCall(Opcodes.V11, other, Opcodes.ACC_PUBLIC, "helper", 2)), "a static method");
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

    @Test
    @DisplayName("traces the methods it covers, and the methods of the JAR that their code calls without covering them")
    void trace() {
        byte[] chain = chainClass(Opcodes.ACC_PRIVATE, 2, -1, 0);
        CodeFingerprint.Trace chained = CodeFingerprint.trace(chain, "run", "()V", className -> null);
        assertEquals(run(chain), chained.fingerprint());
        // In the order they are first referred to; the last step calls run() again
        assertEquals(List.of(OWNER + "#run()V", OWNER + "#step0()V", OWNER + "#step1()V"), chained.covers());
        assertEquals(List.of(), chained.calls());

        CodeFingerprint.Trace created = CodeFingerprint.trace(constructorClass(1), "run", "()V", className -> null);
        assertEquals(List.of(OWNER + "#run()V", OWNER + "#<init>()V"), created.covers());
        assertEquals(List.of(), created.calls(), "not Object's constructor, which the JAR hasn't");

        assertEquals(List.of(OWNER + "#helper()V"), CodeFingerprint.trace(virtualClass(Opcodes.ACC_PUBLIC,
            Opcodes.ACC_PUBLIC, 1), "run", "()V", className -> null).calls(), "a method that subclasses may override");
        String other = "net/coreprotect/Other";
        CodeFingerprint.Trace nested = CodeFingerprint.trace(nestedCall(Opcodes.V11, other, Opcodes.ACC_PUBLIC,
            "helper", 1), NESTED + "#run()V");
        assertEquals(List.of(NESTED + "#run()V"), nested.covers());
        assertEquals(List.of(other + "#helper()V"), nested.calls(), "a method of another nest");
        assertEquals(List.of(BASE + "#helper()V"), CodeFingerprint.trace(inherited(Opcodes.ACC_PUBLIC,
            Opcodes.INVOKEVIRTUAL, 1), SUB + "#run()V").calls(), "named by the class that declares it");

        assertEquals(new CodeFingerprint.Trace(CodeFingerprint.ABSENT, List.of(), List.of(), Map.of()),
            CodeFingerprint.trace(new JarContents(), OWNER + "#run()V"));
    }

    @Test
    @DisplayName("traces the lines of each method's code, from its first line to its last")
    void traceLines() {
        assertEquals(Map.of(OWNER + "#count(I)I", List.of(List.of(10, 11))),
            CodeFingerprint.trace(Counter.plain().bytes(), "count", "(I)I", className -> null).lines());
        assertEquals(Map.of(), CodeFingerprint.trace(Counter.plain().withDebug(0, null).bytes(), "count", "(I)I",
            className -> null).lines(), "without line numbers");

        // A constructor, with field initializers far from its body
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, OWNER, null, "java/lang/Object", null);
        MethodVisitor run = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
        run.visitCode();
        line(run, 50);
        run.visitTypeInsn(Opcodes.NEW, OWNER);
        run.visitInsn(Opcodes.DUP);
        run.visitMethodInsn(Opcodes.INVOKESPECIAL, OWNER, "<init>", "()V", false);
        run.visitInsn(Opcodes.POP);
        run.visitInsn(Opcodes.RETURN);
        run.visitMaxs(0, 0);
        run.visitEnd();
        MethodVisitor constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        constructor.visitCode();
        line(constructor, 40);
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        for (int number : new int[] {5, 6, 9, 41}) {
            line(constructor, number);
            constructor.visitInsn(Opcodes.NOP);
        }
        constructor.visitInsn(Opcodes.RETURN);
        constructor.visitMaxs(0, 0);
        constructor.visitEnd();
        writer.visitEnd();
        Map<String, List<List<Integer>>> lines = CodeFingerprint.trace(writer.toByteArray(), "run", "()V",
            className -> null).lines();
        assertEquals(List.of(List.of(50, 50)), lines.get(OWNER + "#run()V"));
        assertEquals(List.of(List.of(5, 9), List.of(40, 41)), lines.get(OWNER + "#<init>()V"));
    }

    private static void line(MethodVisitor method, int number) {
        Label label = new Label();
        method.visitLabel(label);
        method.visitLineNumber(number, label);
    }

    @Test
    @DisplayName("traces calls of methods that only an interface declares, which the code calls with dispatch")
    void traceInterfaceCalls() {
        String superInterface = "net/coreprotect/Super";
        String subInterface = "net/coreprotect/Sub";
        String implementation = "net/coreprotect/Impl";
        JarContents jar = new JarContents();
        ClassWriter declaring = new ClassWriter(0);
        declaring.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT, superInterface,
            null, "java/lang/Object", null);
        declaring.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, "foo", "()V", null, null).visitEnd();
        declaring.visitEnd();
        jar.put(superInterface + ".class", declaring.toByteArray());
        ClassWriter extending = new ClassWriter(0);
        extending.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT, subInterface,
            null, "java/lang/Object", new String[] {superInterface});
        extending.visitEnd();
        jar.put(subInterface + ".class", extending.toByteArray());
        ClassWriter implementing = new ClassWriter(0);
        implementing.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, implementation, null,
            "java/lang/Object", new String[] {superInterface});
        implementing.visitEnd();
        jar.put(implementation + ".class", implementing.toByteArray());

        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, OWNER, null, "java/lang/Object", null);
        MethodVisitor run = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run",
            "(L" + subInterface + ";L" + implementation + ";)V", null, null);
        run.visitCode();
        run.visitVarInsn(Opcodes.ALOAD, 0);
        run.visitMethodInsn(Opcodes.INVOKEINTERFACE, subInterface, "foo", "()V", true);
        run.visitVarInsn(Opcodes.ALOAD, 1);
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL, implementation, "foo", "()V", false);
        run.visitInsn(Opcodes.RETURN);
        run.visitMaxs(0, 0);
        run.visitEnd();
        writer.visitEnd();
        jar.put(OWNER + ".class", writer.toByteArray());

        String member = OWNER + "#run(L" + subInterface + ";L" + implementation + ";)V";
        assertEquals(List.of(superInterface + "#foo()V"), CodeFingerprint.trace(jar, member).calls());
    }

    @Test
    @DisplayName("doesn't trace a method as called that it covers, though it calls it with dispatch first")
    void traceCoveredLater() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, OWNER, null, "java/lang/Object", null);
        MethodVisitor run = writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
        run.visitCode();
        run.visitVarInsn(Opcodes.ALOAD, 0);
        run.visitMethodInsn(Opcodes.INVOKEVIRTUAL, OWNER, "helper", "()V", false);
        run.visitVarInsn(Opcodes.ALOAD, 0);
        run.visitMethodInsn(Opcodes.INVOKESPECIAL, OWNER, "helper", "()V", false);
        run.visitInsn(Opcodes.RETURN);
        run.visitMaxs(0, 0);
        run.visitEnd();
        storing(writer, Opcodes.ACC_PUBLIC, "helper", 1, null);
        writer.visitEnd();

        CodeFingerprint.Trace trace = CodeFingerprint.trace(writer.toByteArray(), "run", "()V", className -> null);
        assertEquals(List.of(OWNER + "#run()V", OWNER + "#helper()V"), trace.covers());
        assertEquals(List.of(), trace.calls());
    }

    @Test
    @DisplayName("traces each method that capabilities rely on, once, by method")
    void traces() {
        JarContents jar = nestedCall(Opcodes.V11, "net/coreprotect/Other", Opcodes.ACC_PUBLIC, "helper", 1);
        String member = NESTED + "#run()V";
        TransformReport report = new TransformReport();
        for (String id : List.of("a", "b")) {
            report.capabilities.add(new TransformReport.Capability(id, "way", "Does it", null, List.of(), List.of(),
                List.of(new TransformReport.Reliance(member, "Runs", CodeFingerprint.of(jar, member))), List.of(),
                List.of(), List.of()));
        }
        assertEquals(Map.of(member, CodeFingerprint.trace(jar, member)), Main.traces(jar, report));
    }
}
