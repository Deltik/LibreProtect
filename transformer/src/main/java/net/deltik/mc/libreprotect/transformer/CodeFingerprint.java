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
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * Fingerprints the code of an upstream method whose behavior LibreProtect's
 * extensions rely on, so that the audit asks for a review when it changes.
 *
 * <p>The fingerprint covers the method's access flags, each instruction's
 * opcode and operands (types, owners, names and descriptors, constants,
 * local variable indexes, jump and switch targets) and its exception
 * handlers. Jump targets count by the order of their first appearance, not by
 * offset. Debug information, stack map frames and the order of the constant
 * pool don't count, so recompiling unchanged code, or changing only its
 * line numbers or local variable names, keeps the fingerprint.
 *
 * <p>It also covers the code that the method runs in its nest without
 * dispatch, and in turn the code that that runs, up to
 * {@value #MAX_METHODS} methods in all, in the order they are first referred
 * to: the methods of its own class, or of another class of the JAR in the
 * same nest (its outer class, or a class nested in the same outermost
 * class), that it calls or refers to and that no subclass can override.
 * Those are private, static and final methods and constructors, the methods
 * of final classes, and the methods that {@code super} calls, found in the
 * class named or the nearest superclass that declares them, as the JVM
 * resolves them. The bodies of lambdas are private, and the synthetic
 * {@code access$...} methods through which a nested class compiled for Java
 * 8 reaches its outer class's private members are static. It covers the
 * static initializer of each class of the nest whose static fields they use
 * too, which gives those fields their values. So a method that builds its
 * result with its class's constructor or static helpers, as
 * {@code ClickHouseJdbcConfig.forMigrationReads()} does, or that returns a
 * list that its class builds when it's initialized, as
 * {@code PurgePolicy.getPurgeableTables()} does, changes with them. Each
 * method is written with its class and, unless the compiler named it, its
 * name, and references count it by that order, so renumbering lambdas or
 * accessors elsewhere in the nest keeps the fingerprint. A class's nest is
 * its {@code NestHost}, or for a class file without one, the class named
 * before the first {@code $} of its name.
 *
 * <p>It doesn't cover the other methods of the nested and anonymous classes
 * that the method creates, nor methods that subclasses may override, such as
 * bridge methods, nor methods of other nests. The author of the capability
 * report lists those as their own {@code relies} lines where their behavior
 * matters. A fingerprint that would cover more than {@value #MAX_METHODS}
 * methods ends with {@value #TRUNCATED}, and the audit reports it.
 */
final class CodeFingerprint {

    static final String ABSENT = "absent";

    /** How many hex digits of the SHA-256 to keep */
    static final int LENGTH = 12;

    /**
     * How many methods a fingerprint covers at most, counting the method
     * itself. EntityDataCodec's canonicalize covered 63 on CoreProtect 25's
     * development branch, with its conversions of each kind of entity data.
     */
    static final int MAX_METHODS = 128;

    /**
     * Ends a fingerprint that covers only the first {@value #MAX_METHODS}
     * methods that the method runs, so that the audit can say so
     */
    static final String TRUNCATED = "+";

    /** How many superclasses to look through for a member, which a class file whose superclasses loop can't exhaust */
    private static final int MAX_DEPTH = 64;

    /** Markers that separate the parts of the encoding */
    private static final int METHOD = -1;
    private static final int LABEL = -2;
    private static final int TRY_CATCH = -3;

    private CodeFingerprint() {
    }

    /**
     * @param member a method as {@code owner#name(descriptor)}, with internal names
     * @return the fingerprint of the method that the JAR's class declares, or
     *         {@value #ABSENT} if the JAR has no such class or the class no such method
     */
    static String of(JarContents jar, String member) {
        int hash = member.indexOf('#');
        int parenthesis = member.indexOf('(', hash);
        return of(jar.get(member.substring(0, hash) + ".class"), member.substring(hash + 1, parenthesis),
            member.substring(parenthesis), className -> jar.get(className + ".class"));
    }

    /**
     * @param classBytes the class, or {@code null} if there is none
     * @return the fingerprint of the method that the class declares, or
     *         {@value #ABSENT}, with no other class of its nest at hand
     */
    static String of(byte[] classBytes, String name, String descriptor) {
        return of(classBytes, name, descriptor, className -> null);
    }

    /**
     * @param classBytes the class, or {@code null} if there is none
     * @param classes    the other classes of the JAR, by internal name, or {@code null} for one it hasn't
     * @return the fingerprint of the method that the class declares, or {@value #ABSENT}
     */
    static String of(byte[] classBytes, String name, String descriptor, Function<String, byte[]> classes) {
        if (classBytes == null) {
            return ABSENT;
        }
        ClassNode node = read(classBytes);
        MethodNode method = declared(node, name, descriptor);
        return method == null ? ABSENT : of(node, method, classes);
    }

    private static ClassNode read(byte[] classBytes) {
        ClassNode node = new ClassNode();
        new ClassReader(classBytes).accept(node, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return node;
    }

    private static String of(ClassNode owner, MethodNode method, Function<String, byte[]> classes) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        Encoder encoder;
        try (DataOutputStream out = new DataOutputStream(new DigestOutputStream(OutputStream.nullOutputStream(),
            digest))) {
            encoder = new Encoder(out, owner, method, classes);
            encoder.write();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return HexFormat.of().formatHex(digest.digest()).substring(0, LENGTH) + (encoder.truncated ? TRUNCATED : "");
    }

    /**
     * @return whether a fingerprint covers only the first {@value #MAX_METHODS} methods that the method runs
     */
    static boolean truncated(String fingerprint) {
        return fingerprint.endsWith(TRUNCATED);
    }

    /**
     * @return the class that heads a class's nest: its nest host, or for a
     *         class file from before nests, the outermost class that javac
     *         named it after
     */
    private static String nest(ClassNode node) {
        if (node.nestHostClass != null) {
            return node.nestHostClass;
        }
        int dollar = node.name.indexOf('$');
        return dollar < 0 ? node.name : node.name.substring(0, dollar);
    }

    private static MethodNode declared(ClassNode owner, String name, String descriptor) {
        for (MethodNode method : owner.methods) {
            if (method.name.equals(name) && method.desc.equals(descriptor)) {
                return method;
            }
        }
        return null;
    }

    /**
     * Writes the code of a method and of the methods of its nest that it
     * runs without dispatch, unambiguously: every value has a fixed size or
     * a length prefix.
     */
    private static final class Encoder {
        /** A method to write, with the class that declares it */
        private record Followed(ClassNode owner, MethodNode method) {
        }

        private final DataOutputStream out;
        /** The nest of the method's class, whose methods that it runs without dispatch it covers */
        private final String nest;
        private final Function<String, byte[]> classes;
        /** The classes of the JAR read so far, by internal name; {@code null} for one the JAR hasn't */
        private final Map<String, ClassNode> jarClasses = new HashMap<>();
        /** The methods to write, in the order they were first referred to */
        private final List<Followed> methods = new ArrayList<>();
        private final Map<MethodNode, Integer> numbers = new HashMap<>();
        /** Jump targets of the method being written */
        private final Map<LabelNode, Integer> ordinals = new HashMap<>();
        /** Whether the method runs more methods of its nest without dispatch than the fingerprint covers */
        boolean truncated;

        Encoder(DataOutputStream out, ClassNode owner, MethodNode method, Function<String, byte[]> classes) {
            this.out = out;
            this.nest = nest(owner);
            this.classes = classes;
            jarClasses.put(owner.name, owner);
            methods.add(new Followed(owner, method));
            numbers.put(method, 0);
        }

        void write() throws IOException {
            // Writing a method adds the methods it refers to
            for (int i = 0; i < methods.size(); i++) {
                write(methods.get(i));
            }
        }

        private void write(Followed followed) throws IOException {
            MethodNode method = followed.method();
            out.writeInt(METHOD);
            // Which method it is, unless the compiler named it, as it numbers lambdas and accessors: a static method
            // moved to another class locks and initializes that one
            string(followed.owner().name);
            string((method.access & Opcodes.ACC_SYNTHETIC) != 0 ? "" : method.name);
            // Ignore ASM's pseudo-flags, such as ACC_DEPRECATED, which come from attributes
            out.writeInt(method.access & 0xFFFF);
            string(method.desc);

            // Only labels that something refers to matter, numbered in the order they appear
            Set<LabelNode> targets = new HashSet<>();
            for (AbstractInsnNode instruction : method.instructions) {
                if (instruction instanceof JumpInsnNode jump) {
                    targets.add(jump.label);
                } else if (instruction instanceof TableSwitchInsnNode table) {
                    targets.add(table.dflt);
                    targets.addAll(table.labels);
                } else if (instruction instanceof LookupSwitchInsnNode lookup) {
                    targets.add(lookup.dflt);
                    targets.addAll(lookup.labels);
                }
            }
            for (TryCatchBlockNode block : method.tryCatchBlocks) {
                targets.addAll(List.of(block.start, block.end, block.handler));
            }
            ordinals.clear();
            for (AbstractInsnNode instruction : method.instructions) {
                if (instruction instanceof LabelNode label && targets.contains(label)) {
                    ordinals.put(label, ordinals.size());
                }
            }

            for (AbstractInsnNode instruction : method.instructions) {
                instruction(instruction);
            }
            for (TryCatchBlockNode block : method.tryCatchBlocks) {
                out.writeInt(TRY_CATCH);
                label(block.start);
                label(block.end);
                label(block.handler);
                string(block.type == null ? "" : block.type);
            }
        }

        /**
         * @param special whether the reference runs exactly the method that it
         *                resolves to, as {@code invokespecial} does for a
         *                constructor, a private method or {@code super}'s
         * @return the number of the method of the nest that a reference runs
         *         without dispatch, such as a static helper, a lambda of the
         *         class or an accessor of its outer class, added to the
         *         methods to write if it is new; or -1 if it is another
         *         method, or there are too many
         */
        private int local(String methodOwner, String name, String descriptor, boolean special) {
            // Resolved as the JVM resolves it: in the class named, or the nearest superclass that declares it
            ClassNode named = jarClass(methodOwner);
            ClassNode declaring = named;
            MethodNode target = declaring == null ? null : declared(declaring, name, descriptor);
            for (int depth = 0; target == null && declaring != null && depth < MAX_DEPTH; depth++) {
                declaring = superclass(declaring);
                target = declaring == null ? null : declared(declaring, name, descriptor);
            }
            if (target == null || !nest(declaring).equals(nest)) {
                return -1;
            }
            // Of a final class named, a call runs what the class resolves, which no subclass overrides
            boolean fixed = special || withoutDispatch(declaring, target) || (named.access & Opcodes.ACC_FINAL) != 0;
            return fixed ? follow(declaring, target) : numbers.getOrDefault(target, -1);
        }

        /**
         * @return the method's number, added to the methods to write if it is
         *         new; or -1 if there are too many
         */
        private int follow(ClassNode owner, MethodNode method) {
            Integer number = numbers.get(method);
            if (number == null) {
                if (methods.size() >= MAX_METHODS) {
                    truncated = true;
                    return -1;
                }
                number = methods.size();
                methods.add(new Followed(owner, method));
                numbers.put(method, number);
            }
            return number;
        }

        /**
         * Covers the static initializer of the nest's class whose static
         * field an instruction reads or writes, which gives the field its
         * value, as a list of tables that a method returns.
         */
        private void initializer(FieldInsnNode field) {
            if (field.getOpcode() != Opcodes.GETSTATIC && field.getOpcode() != Opcodes.PUTSTATIC) {
                return;
            }
            // The class that declares the field, which the JVM initializes: the class named, or a superclass
            ClassNode declaring = jarClass(field.owner);
            for (int depth = 0; declaring != null && declaring.fields.stream().noneMatch(declared ->
                declared.name.equals(field.name) && declared.desc.equals(field.desc)); depth++) {
                declaring = depth < MAX_DEPTH ? superclass(declaring) : null;
            }
            if (declaring != null && nest(declaring).equals(nest)) {
                MethodNode initializer = declared(declaring, "<clinit>", "()V");
                if (initializer != null) {
                    follow(declaring, initializer);
                }
            }
        }

        /**
         * @return whether a call runs this very method, since no subclass can
         *         override it: a private, static or final method, a
         *         constructor, or a method of a final class. Lambdas' bodies
         *         and accessors are private or static; a bridge method, which
         *         the compiler writes too, may be overridden.
         */
        private static boolean withoutDispatch(ClassNode owner, MethodNode method) {
            return (method.access & (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL)) != 0
                || method.name.equals("<init>") || (owner.access & Opcodes.ACC_FINAL) != 0;
        }

        /**
         * @return a class's superclass, if the JAR has it
         */
        private ClassNode superclass(ClassNode node) {
            return node.superName == null ? null : jarClass(node.superName);
        }

        /**
         * @return a class of the JAR, of any nest, or {@code null} if the JAR hasn't it
         */
        private ClassNode jarClass(String className) {
            if (jarClasses.containsKey(className)) {
                return jarClasses.get(className);
            }
            byte[] bytes = classes.apply(className);
            ClassNode node = bytes == null ? null : read(bytes);
            jarClasses.put(className, node);
            return node;
        }

        private void instruction(AbstractInsnNode instruction) throws IOException {
            if (instruction instanceof LabelNode label) {
                if (ordinals.containsKey(label)) {
                    out.writeInt(LABEL);
                    label(label);
                }
                return;
            }
            if (instruction.getOpcode() < 0) {
                return; // a line number or frame, which ClassReader skipped anyway
            }
            out.writeInt(instruction.getOpcode());
            switch (instruction) {
                case IntInsnNode operand -> out.writeInt(operand.operand);
                case VarInsnNode variable -> out.writeInt(variable.var);
                case TypeInsnNode type -> string(type.desc);
                case FieldInsnNode field -> {
                    initializer(field);
                    string(field.owner);
                    string(field.name);
                    string(field.desc);
                }
                case MethodInsnNode call -> {
                    int local = local(call.owner, call.name, call.desc, call.getOpcode() == Opcodes.INVOKESPECIAL);
                    if (local >= 0) {
                        out.writeByte('L');
                        out.writeInt(local);
                    } else {
                        out.writeByte('M');
                        string(call.owner);
                        string(call.name);
                        string(call.desc);
                    }
                    out.writeBoolean(call.itf);
                }
                case InvokeDynamicInsnNode indy -> {
                    string(indy.name);
                    string(indy.desc);
                    constant(indy.bsm);
                    arguments(indy.bsmArgs);
                }
                case JumpInsnNode jump -> label(jump.label);
                case LdcInsnNode ldc -> constant(ldc.cst);
                case IincInsnNode increment -> {
                    out.writeInt(increment.var);
                    out.writeInt(increment.incr);
                }
                case TableSwitchInsnNode table -> {
                    out.writeInt(table.min);
                    out.writeInt(table.max);
                    label(table.dflt);
                    out.writeInt(table.labels.size());
                    for (LabelNode label : table.labels) {
                        label(label);
                    }
                }
                case LookupSwitchInsnNode lookup -> {
                    label(lookup.dflt);
                    out.writeInt(lookup.keys.size());
                    for (int i = 0; i < lookup.keys.size(); i++) {
                        out.writeInt(lookup.keys.get(i));
                        label(lookup.labels.get(i));
                    }
                }
                case MultiANewArrayInsnNode array -> {
                    string(array.desc);
                    out.writeInt(array.dims);
                }
                default -> {
                    // An instruction without operands
                }
            }
        }

        private void label(LabelNode label) throws IOException {
            out.writeInt(ordinals.get(label));
        }

        private void arguments(Object[] arguments) throws IOException {
            out.writeInt(arguments.length);
            for (Object argument : arguments) {
                constant(argument);
            }
        }

        private void constant(Object value) throws IOException {
            switch (value) {
                case Integer integer -> {
                    out.writeByte('I');
                    out.writeInt(integer);
                }
                case Float number -> {
                    out.writeByte('F');
                    out.writeInt(Float.floatToRawIntBits(number));
                }
                case Long number -> {
                    out.writeByte('J');
                    out.writeLong(number);
                }
                case Double number -> {
                    out.writeByte('D');
                    out.writeLong(Double.doubleToRawLongBits(number));
                }
                case String string -> {
                    out.writeByte('S');
                    string(string);
                }
                case Type type -> {
                    out.writeByte('T');
                    string(type.getDescriptor());
                }
                case Handle handle -> {
                    // Field handles and methods of other classes count by name
                    int local = handle.getTag() >= Opcodes.H_INVOKEVIRTUAL
                        ? local(handle.getOwner(), handle.getName(), handle.getDesc(),
                            handle.getTag() == Opcodes.H_INVOKESPECIAL || handle.getTag() == Opcodes.H_NEWINVOKESPECIAL)
                        : -1;
                    if (local >= 0) {
                        out.writeByte('h');
                        out.writeInt(handle.getTag());
                        out.writeInt(local);
                    } else {
                        out.writeByte('H');
                        out.writeInt(handle.getTag());
                        string(handle.getOwner());
                        string(handle.getName());
                        string(handle.getDesc());
                    }
                    out.writeBoolean(handle.isInterface());
                }
                case ConstantDynamic dynamic -> {
                    out.writeByte('C');
                    string(dynamic.getName());
                    string(dynamic.getDescriptor());
                    constant(dynamic.getBootstrapMethod());
                    out.writeInt(dynamic.getBootstrapMethodArgumentCount());
                    for (int i = 0; i < dynamic.getBootstrapMethodArgumentCount(); i++) {
                        constant(dynamic.getBootstrapMethodArgument(i));
                    }
                }
                default -> throw new IllegalArgumentException("Unexpected constant " + value);
            }
        }

        private void string(String value) throws IOException {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            out.writeInt(bytes.length);
            out.write(bytes);
        }
    }
}
