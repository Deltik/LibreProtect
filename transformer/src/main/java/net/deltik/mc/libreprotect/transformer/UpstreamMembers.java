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
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Finds classes, methods and fields in the upstream JAR the way the
 * extensions' reflective lookups resolve them: declared by the class, or
 * inherited from its superclasses and interfaces. Access doesn't matter for
 * the class's own members, because the extensions look members up with
 * private access; private members of its supertypes aren't inherited, and
 * neither are static methods of its interfaces.
 *
 * <p>Supertypes from the JDK are read from the JDK that runs the transformer.
 * Other supertypes outside the JAR, such as Bukkit's, can't be seen, so a
 * member that one of them might declare is {@link Lookup#UNKNOWN}.
 */
final class UpstreamMembers {

    /** Whether the JAR has a member */
    enum Lookup {
        FOUND,
        MISSING,
        /** Not in the JAR or the JDK, but a supertype outside both might declare it */
        UNKNOWN
    }

    private static final int PARSING = ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES;

    private final Map<String, ClassNode> classes = new HashMap<>();
    private final Map<String, Optional<ClassNode>> jdk = new HashMap<>();

    UpstreamMembers(JarContents jar) {
        for (String name : jar.names()) {
            if (JarContents.isClass(name) && !JarContents.isVersioned(name)) {
                ClassNode node = new ClassNode();
                new ClassReader(jar.get(name)).accept(node, PARSING);
                classes.put(node.name, node);
            }
        }
    }

    /**
     * @param member a class as {@code owner}, a method as {@code owner#name(descriptor)}, or a field as
     *               {@code owner#name:descriptor}; the owner must be in the JAR
     */
    Lookup find(String member) {
        int hash = member.indexOf('#');
        if (hash < 0) {
            return classes.containsKey(member) ? Lookup.FOUND : Lookup.MISSING;
        }
        String owner = member.substring(0, hash);
        if (!classes.containsKey(owner)) {
            return Lookup.MISSING;
        }
        String signature = member.substring(hash + 1);
        return search(owner, signature, !signature.contains(":"), true, false, new HashSet<>());
    }

    /**
     * @return the names of the enum's constants in declaration order, or
     *         {@code null} if the JAR has no such enum
     */
    List<String> enumConstants(String owner) {
        ClassNode node = classes.get(owner);
        if (node == null || (node.access & Opcodes.ACC_ENUM) == 0) {
            return null;
        }
        List<String> constants = new ArrayList<>();
        for (FieldNode field : node.fields) {
            if ((field.access & Opcodes.ACC_ENUM) != 0) {
                constants.add(field.name);
            }
        }
        return constants;
    }

    /**
     * @param signature   {@code name(descriptor)} for a method, {@code name:descriptor} for a field
     * @param owner       whether this is the class that the member was named on, whose private members count
     * @param throughInterface whether this type was reached through an interface, whose static methods don't count
     */
    private Lookup search(String type, String signature, boolean method, boolean owner, boolean throughInterface,
                          Set<String> seen) {
        if (!seen.add(type)) {
            return Lookup.MISSING;
        }
        ClassNode node = classes.get(type);
        if (node == null) {
            node = jdkClass(type);
            if (node == null) {
                return Lookup.UNKNOWN;
            }
        }
        if (declares(node, signature, method, owner, throughInterface)) {
            return Lookup.FOUND;
        }
        Lookup result = Lookup.MISSING;
        List<String> interfaces = new ArrayList<>(node.interfaces);
        boolean isInterface = (node.access & Opcodes.ACC_INTERFACE) != 0;
        if (node.superName != null) {
            Lookup inherited = search(node.superName, signature, method, false, throughInterface || isInterface,
                seen);
            if (inherited == Lookup.FOUND) {
                return Lookup.FOUND;
            }
            if (inherited == Lookup.UNKNOWN) {
                result = Lookup.UNKNOWN;
            }
        }
        for (String anInterface : interfaces) {
            Lookup inherited = search(anInterface, signature, method, false, true, seen);
            if (inherited == Lookup.FOUND) {
                return Lookup.FOUND;
            }
            if (inherited == Lookup.UNKNOWN) {
                result = Lookup.UNKNOWN;
            }
        }
        return result;
    }

    private static boolean declares(ClassNode node, String signature, boolean method, boolean owner,
                                    boolean throughInterface) {
        if (method) {
            for (MethodNode candidate : node.methods) {
                if (signature.equals(candidate.name + candidate.desc) && (owner
                    || (candidate.access & Opcodes.ACC_PRIVATE) == 0
                    && !(throughInterface && (candidate.access & Opcodes.ACC_STATIC) != 0))) {
                    return true;
                }
            }
        } else {
            for (FieldNode candidate : node.fields) {
                if (signature.equals(candidate.name + ":" + candidate.desc)
                    && (owner || (candidate.access & Opcodes.ACC_PRIVATE) == 0)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @return a class of the JDK that runs the transformer, or {@code null} if it has none by that name
     */
    private ClassNode jdkClass(String type) {
        return jdk.computeIfAbsent(type, name -> {
            try (InputStream in = ClassLoader.getPlatformClassLoader().getResourceAsStream(name + ".class")) {
                if (in == null) {
                    return Optional.empty();
                }
                ClassNode node = new ClassNode();
                new ClassReader(in).accept(node, PARSING);
                return Optional.of(node);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }).orElse(null);
    }
}
