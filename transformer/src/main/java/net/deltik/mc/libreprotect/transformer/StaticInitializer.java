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

import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * A class's static initializer, split into the statements that only give one
 * of its static fields its value, which matter only to code that uses that
 * field, and everything else, which may matter to any of them.
 *
 * <p>A statement gives only one field its value when its instructions, from
 * the one after the last {@code putstatic} before it, store a value into a
 * static field that the class declares, with that {@code putstatic}, and
 * otherwise only build the value, leaving the operand stack as they found it:
 * constants, new objects and arrays, and calls without dispatch of
 * {@linkplain #JDK the JDK's methods} that run no code but the JDK's and what
 * they are given, or of methods of the class's nest that read and write no
 * static field of the JAR and call nothing else. Such a statement can't
 * change another field, nor anything that another statement reads; it can
 * only fail, as by throwing, which fails the class's initialization, and so
 * every use of the class. So
 * {@code static Map<String, Integer> lookupPage = syncMap();} matters only
 * to code that uses {@code lookupPage}. Anything else, such as a statement
 * that reads a static field, uses a local variable, jumps, calls a method of
 * the JAR outside the nest or calls a method with dispatch, may matter to
 * every field. What a field's value is also depends on where its statements
 * are among the rest, such as before or after one that reads the field, or
 * in a branch, so each of them comes with its {@linkplain Statement#position
 * position}. A static initializer with exception handlers isn't split.
 */
final class StaticInitializer {

    /**
     * Methods of the JDK that run no code but the JDK's and what they are
     * given, and change nothing but the objects they return: the
     * constructors and static methods of these classes that are named, by
     * class, or {@code *} for all of them
     */
    static final Map<String, Set<String>> JDK = jdk();

    /**
     * A statement that only gives a field its value.
     *
     * @param position     where it is among the rest of the static initializer:
     *                     how many of its other instructions come before it,
     *                     counting the labels that they jump to, as the
     *                     fingerprint writes them
     * @param instructions its instructions, which have no labels
     */
    record Statement(int position, List<AbstractInsnNode> instructions) {
    }

    /** The instructions that may matter to any of the class's static fields */
    final Set<AbstractInsnNode> shared;
    /**
     * The statements that only give each static field its value, by its name
     * and descriptor as {@code name:descriptor}, in order
     */
    final Map<String, List<Statement>> own;

    private StaticInitializer(Set<AbstractInsnNode> shared, Map<String, List<Statement>> own) {
        this.shared = Collections.unmodifiableSet(shared);
        this.own = Collections.unmodifiableMap(own);
    }

    private static Map<String, Set<String>> jdk() {
        Map<String, Set<String>> methods = new HashMap<>();
        Set<String> constructors = Set.of("<init>");
        for (String type : List.of("java/lang/Object", "java/util/HashMap", "java/util/LinkedHashMap",
            "java/util/TreeMap", "java/util/HashSet", "java/util/LinkedHashSet", "java/util/TreeSet",
            "java/util/ArrayList", "java/util/LinkedList", "java/util/ArrayDeque", "java/util/IdentityHashMap",
            "java/util/concurrent/ConcurrentHashMap", "java/util/concurrent/ConcurrentLinkedQueue",
            "java/util/concurrent/ConcurrentLinkedDeque", "java/util/concurrent/CopyOnWriteArrayList",
            "java/util/concurrent/CopyOnWriteArraySet", "java/util/concurrent/ConcurrentSkipListMap",
            "java/util/concurrent/ConcurrentSkipListSet", "java/util/concurrent/LinkedBlockingQueue",
            "java/util/concurrent/LinkedBlockingDeque", "java/util/concurrent/ArrayBlockingQueue",
            "java/util/concurrent/atomic/AtomicBoolean", "java/util/concurrent/atomic/AtomicInteger",
            "java/util/concurrent/atomic/AtomicLong", "java/util/concurrent/atomic/AtomicReference",
            "java/util/concurrent/locks/ReentrantLock", "java/util/concurrent/locks/ReentrantReadWriteLock")) {
            methods.put(type, constructors);
        }
        methods.put("java/util/Collections", Set.of("synchronizedMap", "synchronizedList", "synchronizedSet",
            "synchronizedSortedMap", "synchronizedSortedSet", "unmodifiableMap", "unmodifiableList",
            "unmodifiableSet", "emptyMap", "emptyList", "emptySet", "newSetFromMap", "singleton", "singletonList",
            "singletonMap"));
        methods.put("java/util/List", Set.of("of", "copyOf"));
        methods.put("java/util/Set", Set.of("of", "copyOf"));
        methods.put("java/util/Map", Set.of("of", "copyOf", "entry"));
        methods.put("java/util/Arrays", Set.of("asList"));
        methods.put("java/util/regex/Pattern", Set.of("compile"));
        for (String box : List.of("Boolean", "Byte", "Character", "Short", "Integer", "Long", "Float", "Double")) {
            methods.put("java/lang/" + box, Set.of("valueOf"));
        }
        return Collections.unmodifiableMap(methods);
    }

    /**
     * @param owner     the class whose static initializer it is
     * @param jarClass  the classes of the JAR by internal name, {@code null} for one it hasn't
     * @param nest      the nest of a class of the JAR
     * @return its statements, or {@code null} if it can't be split, as with exception handlers
     */
    static StaticInitializer of(ClassNode owner, MethodNode initializer, Function<String, ClassNode> jarClass,
                                Function<ClassNode, String> nest) {
        if (!initializer.tryCatchBlocks.isEmpty()) {
            return null;
        }
        Purity purity = new Purity(owner, jarClass, nest);
        Set<AbstractInsnNode> shared = Collections.newSetFromMap(new IdentityHashMap<>());
        // Each statement that only gives a field its value, by its first instruction
        Map<AbstractInsnNode, String> fields = new IdentityHashMap<>();
        Map<AbstractInsnNode, List<AbstractInsnNode>> statements = new IdentityHashMap<>();
        List<AbstractInsnNode> statement = new ArrayList<>();
        // Whether code jumps into the statement, past its first instruction: read without debug information, a
        // method has labels only where code jumps to or exception handlers start
        boolean entered = false;
        for (AbstractInsnNode instruction : initializer.instructions) {
            if (instruction.getOpcode() < 0) {
                entered |= instruction instanceof LabelNode && !statement.isEmpty();
                continue;
            }
            statement.add(instruction);
            if (instruction.getOpcode() == Opcodes.PUTSTATIC) {
                String field = entered ? null : purity.ownField(statement);
                entered = false;
                if (field != null) {
                    fields.put(statement.get(0), field);
                    statements.put(statement.get(0), List.copyOf(statement));
                } else {
                    shared.addAll(statement);
                }
                statement.clear();
            }
        }
        shared.addAll(statement);

        // Where each statement is among the rest, as the fingerprint writes the rest: its instructions, and the
        // labels that they jump to
        Set<LabelNode> targets = Collections.newSetFromMap(new IdentityHashMap<>());
        for (AbstractInsnNode instruction : shared) {
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
        Map<String, List<Statement>> own = new LinkedHashMap<>();
        int position = 0;
        for (AbstractInsnNode instruction : initializer.instructions) {
            String field = fields.get(instruction);
            if (field != null) {
                own.computeIfAbsent(field, key -> new ArrayList<>()).add(new Statement(position,
                    statements.get(instruction)));
            }
            if (shared.contains(instruction) || instruction instanceof LabelNode label && targets.contains(label)) {
                position++;
            }
        }
        return new StaticInitializer(shared, own);
    }

    /**
     * What code may do while the class is initialized, besides building values.
     */
    private static final class Purity {
        private final ClassNode owner;
        private final Function<String, ClassNode> jarClass;
        private final Function<ClassNode, String> nest;
        private final String ownerNest;
        /**
         * Whether each method of the nest is pure; {@code false} while it's
         * being checked, so that a method that calls it back is taken as
         * impure rather than cached as pure on what isn't known yet
         */
        private final Map<MethodNode, Boolean> methods = new IdentityHashMap<>();
        /** Whether each class of the nest is, all of its methods, by internal name; {@code false} while checked */
        private final Map<String, Boolean> classes = new HashMap<>();
        /**
         * Whether initializing each class of the nest only builds values, by
         * internal name; {@code false} while checked, as for a class file
         * whose supertypes loop, which the JVM would refuse anyway
         */
        private final Map<String, Boolean> initialized = new HashMap<>();

        Purity(ClassNode owner, Function<String, ClassNode> jarClass, Function<ClassNode, String> nest) {
            this.owner = owner;
            this.jarClass = jarClass;
            this.nest = nest;
            this.ownerNest = nest.apply(owner);
        }

        /**
         * @param statement instructions that end with a {@code putstatic}
         * @return the field, as {@code name:descriptor}, if the statement
         *         only gives that field of the class its value, or {@code null}
         */
        String ownField(List<AbstractInsnNode> statement) {
            FieldInsnNode store = (FieldInsnNode) statement.get(statement.size() - 1);
            if (!store.owner.equals(owner.name) || owner.fields.stream().noneMatch(field ->
                field.name.equals(store.name) && field.desc.equals(store.desc)
                    && (field.access & Opcodes.ACC_STATIC) != 0)) {
                return null;
            }
            int depth = 0;
            for (AbstractInsnNode instruction : statement.subList(0, statement.size() - 1)) {
                int[] effect = effect(instruction);
                if (effect == null || depth < effect[0]) {
                    return null;
                }
                depth += effect[1] - effect[0];
            }
            return depth == Type.getType(store.desc).getSize() ? store.name + ":" + store.desc : null;
        }

        /**
         * @return how many slots of the operand stack a statement's
         *         instruction takes and how many it leaves, if it only builds
         *         a value, or {@code null}
         */
        private int[] effect(AbstractInsnNode instruction) {
            int opcode = instruction.getOpcode();
            switch (opcode) {
                case Opcodes.ACONST_NULL, Opcodes.ICONST_M1, Opcodes.ICONST_0, Opcodes.ICONST_1, Opcodes.ICONST_2,
                     Opcodes.ICONST_3, Opcodes.ICONST_4, Opcodes.ICONST_5, Opcodes.FCONST_0, Opcodes.FCONST_1,
                     Opcodes.FCONST_2, Opcodes.BIPUSH, Opcodes.SIPUSH -> {
                    return new int[] {0, 1};
                }
                case Opcodes.LCONST_0, Opcodes.LCONST_1, Opcodes.DCONST_0, Opcodes.DCONST_1 -> {
                    return new int[] {0, 2};
                }
                case Opcodes.LDC -> {
                    Object constant = ((LdcInsnNode) instruction).cst;
                    if (constant instanceof Handle || constant instanceof ConstantDynamic) {
                        return null;
                    }
                    return new int[] {0, constant instanceof Long || constant instanceof Double ? 2 : 1};
                }
                case Opcodes.DUP -> {
                    return new int[] {1, 2};
                }
                case Opcodes.POP -> {
                    return new int[] {1, 0};
                }
                case Opcodes.POP2 -> {
                    return new int[] {2, 0};
                }
                case Opcodes.NEWARRAY, Opcodes.ANEWARRAY, Opcodes.CHECKCAST -> {
                    return new int[] {1, 1};
                }
                case Opcodes.IASTORE, Opcodes.FASTORE, Opcodes.AASTORE, Opcodes.BASTORE, Opcodes.CASTORE,
                     Opcodes.SASTORE -> {
                    return new int[] {3, 0};
                }
                case Opcodes.LASTORE, Opcodes.DASTORE -> {
                    return new int[] {4, 0};
                }
                case Opcodes.NEW -> {
                    return creates(((TypeInsnNode) instruction).desc) ? new int[] {0, 1} : null;
                }
                case Opcodes.INVOKESTATIC, Opcodes.INVOKESPECIAL -> {
                    MethodInsnNode call = (MethodInsnNode) instruction;
                    if (!calls(call)) {
                        return null;
                    }
                    int arguments = (Type.getArgumentsAndReturnSizes(call.desc) >> 2) - 1
                        + (opcode == Opcodes.INVOKESPECIAL ? 1 : 0);
                    return new int[] {arguments, Type.getReturnType(call.desc).getSize()};
                }
                default -> {
                    return null;
                }
            }
        }

        /**
         * @return whether creating an object of the class runs only code that builds values: one of
         *         {@linkplain #JDK the JDK's classes}, or a class of the nest whose every method does
         */
        private boolean creates(String type) {
            if (JDK.containsKey(type) && JDK.get(type).contains("<init>")) {
                return true;
            }
            ClassNode created = jarClass.apply(type);
            return created != null && nest.apply(created).equals(ownerNest) && pureClass(created);
        }

        /**
         * @return whether a call without dispatch runs only code that builds values
         */
        private boolean calls(MethodInsnNode call) {
            Set<String> jdk = JDK.get(call.owner);
            if (jdk != null && (jdk.contains("*") || jdk.contains(call.name))) {
                return true;
            }
            ClassNode named = jarClass.apply(call.owner);
            if (named == null || !nest.apply(named).equals(ownerNest)) {
                return false;
            }
            // Calling a method of another class of the nest initializes that class, and what it extends
            if (named != owner && !initializes(named)) {
                return false;
            }
            MethodNode target = declared(named, call.name, call.desc);
            return target != null && pure(target);
        }

        /**
         * @return whether initializing a class of the nest only builds values:
         *         the static initializers of the class, its superclasses and
         *         its interfaces, which the JVM initializes first; those of
         *         the JDK, and those of the nest that only build values
         */
        private boolean initializes(ClassNode type) {
            if (type == owner) {
                // Already being initialized, with what it extends
                return true;
            }
            Boolean known = initialized.get(type.name);
            if (known != null) {
                return known;
            }
            initialized.put(type.name, false);
            MethodNode initializer = declared(type, "<clinit>", "()V");
            boolean pure = initializer == null || pure(initializer);
            List<String> supertypes = new ArrayList<>(type.interfaces);
            if (type.superName != null) {
                supertypes.add(type.superName);
            }
            for (String supertype : supertypes) {
                ClassNode inherited = jarClass.apply(supertype);
                pure = pure && (inherited == null ? supertype.startsWith("java/")
                    : nest.apply(inherited).equals(ownerNest) && initializes(inherited));
            }
            initialized.put(type.name, pure);
            return pure;
        }

        /**
         * @return whether every method of a class of the nest only builds values, as code that the JDK may call on
         *         one of its objects, and its superclass is the JDK's or such a class too
         */
        private boolean pureClass(ClassNode type) {
            Boolean known = classes.get(type.name);
            if (known != null) {
                return known;
            }
            classes.put(type.name, false);
            // The class being initialized isn't done yet
            boolean pure = type != owner;
            List<String> supertypes = new ArrayList<>(type.interfaces);
            if (type.superName != null) {
                supertypes.add(type.superName);
            }
            for (String supertype : supertypes) {
                ClassNode inherited = jarClass.apply(supertype);
                // The JDK's interfaces declare no code of the JAR's, and its superclasses must be known to run none
                pure = pure && (inherited == null ? type.interfaces.contains(supertype) && supertype.startsWith("java/")
                    || JDK.containsKey(supertype) : nest.apply(inherited).equals(ownerNest) && pureClass(inherited));
            }
            for (MethodNode method : type.methods) {
                pure = pure && pure(method);
            }
            classes.put(type.name, pure);
            return pure;
        }

        /**
         * @return whether a method of the nest reads and writes no static field of the JAR, calls only
         *         {@linkplain #JDK the JDK's methods} and such methods of the nest without dispatch, and creates
         *         only such objects
         */
        private boolean pure(MethodNode method) {
            Boolean known = methods.get(method);
            if (known != null) {
                return known;
            }
            methods.put(method, false);
            // A native method's code can't be seen
            boolean pure = (method.access & Opcodes.ACC_NATIVE) == 0;
            for (AbstractInsnNode instruction : method.instructions) {
                if (!pure) {
                    break;
                }
                pure = switch (instruction.getOpcode()) {
                    // Of the JDK, whose classes initialize without the JAR's code
                    case Opcodes.GETSTATIC, Opcodes.PUTSTATIC -> jarClass.apply(((FieldInsnNode) instruction).owner)
                        == null && ((FieldInsnNode) instruction).owner.startsWith("java/");
                    case Opcodes.INVOKESTATIC, Opcodes.INVOKESPECIAL -> calls((MethodInsnNode) instruction);
                    case Opcodes.INVOKEVIRTUAL, Opcodes.INVOKEINTERFACE, Opcodes.INVOKEDYNAMIC -> false;
                    case Opcodes.NEW -> creates(((TypeInsnNode) instruction).desc);
                    case Opcodes.LDC -> !(((LdcInsnNode) instruction).cst instanceof Handle
                        || ((LdcInsnNode) instruction).cst instanceof ConstantDynamic);
                    default -> true;
                };
            }
            methods.put(method, pure);
            return pure;
        }

        private static MethodNode declared(ClassNode type, String name, String descriptor) {
            for (MethodNode method : type.methods) {
                if (method.name.equals(name) && method.desc.equals(descriptor)) {
                    return method;
                }
            }
            return null;
        }
    }
}
