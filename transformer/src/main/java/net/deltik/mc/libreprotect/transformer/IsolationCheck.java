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
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Proves that some of LibreProtect's classes don't reference upstream's
 * classes at all, so that nothing upstream changes can make them fail to link.
 *
 * <p>The runtime classes must not reference upstream: {@code Bootstrap} runs
 * before CoreProtect initializes, and loading its classes early would freeze
 * upstream's static state. The extensions must not either: they reach
 * CoreProtect only by reflection, so that a class, method or field that
 * upstream removed or changed costs a feature instead of a
 * {@link LinkageError} on a server.
 *
 * <p>Every class that the constant pool names counts, as does every type in a
 * member reference, a method type constant, or a field or method declaration.
 * Annotations, generic signatures and debug information don't count: the JVM
 * never links them.
 */
final class IsolationCheck {

    /** Upstream's package root. A class under it that LibreProtect doesn't ship is upstream's. */
    static final String UPSTREAM_ROOT = "net/coreprotect/";

    private static final int CONSTANT_CLASS = 7;
    private static final int CONSTANT_NAME_AND_TYPE = 12;
    private static final int CONSTANT_METHOD_TYPE = 16;

    private final Set<String> upstreamClasses;
    private final Set<String> ownClasses;
    private final Set<String> violations = new TreeSet<>();

    /**
     * @param upstreamClasses internal names of the classes that the upstream JAR ships
     * @param ownClasses internal names of the classes that LibreProtect adds
     */
    IsolationCheck(Set<String> upstreamClasses, Set<String> ownClasses) {
        this.upstreamClasses = upstreamClasses;
        this.ownClasses = ownClasses;
    }

    /**
     * Check a class that must not reference upstream.
     *
     * @param rule why not, and what to do instead, for the violation's message
     */
    void check(byte[] classBytes, String rule) {
        ClassReader reader = new ClassReader(classBytes);
        String from = reader.getClassName();
        char[] buffer = new char[reader.getMaxStringLength()];
        for (int item = 1; item < reader.getItemCount(); item++) {
            int offset = reader.getItem(item);
            if (offset == 0) {
                continue; // the unusable entry after a long or double
            }
            switch (reader.readByte(offset - 1)) {
                case CONSTANT_CLASS -> classReference(from, reader.readUTF8(offset, buffer), rule);
                case CONSTANT_NAME_AND_TYPE -> descriptorReferences(from, reader.readUTF8(offset + 2, buffer), rule);
                case CONSTANT_METHOD_TYPE -> descriptorReferences(from, reader.readUTF8(offset, buffer), rule);
                default -> {
                }
            }
        }

        ClassNode node = new ClassNode();
        reader.accept(node, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        for (FieldNode field : node.fields) {
            descriptorReferences(from, field.desc, rule);
        }
        for (MethodNode method : node.methods) {
            descriptorReferences(from, method.desc, rule);
        }
    }

    /**
     * @return a description of each reference to upstream, in order
     */
    List<String> violations() {
        return List.copyOf(violations);
    }

    private void descriptorReferences(String from, String descriptor, String rule) {
        Type type = Type.getType(descriptor);
        if (type.getSort() == Type.METHOD) {
            typeReference(from, type.getReturnType(), rule);
            for (Type argument : type.getArgumentTypes()) {
                typeReference(from, argument, rule);
            }
        } else {
            typeReference(from, type, rule);
        }
    }

    private void typeReference(String from, Type type, String rule) {
        Type element = type.getSort() == Type.ARRAY ? type.getElementType() : type;
        if (element.getSort() == Type.OBJECT) {
            classReference(from, element.getInternalName(), rule);
        }
    }

    /**
     * @param name an internal name, or an array descriptor
     */
    private void classReference(String from, String name, String rule) {
        String owner = name.startsWith("[") ? elementClass(name) : name;
        if (owner != null && isUpstream(owner)) {
            violations.add(readable(from) + " uses upstream's " + readable(owner) + ", but " + rule);
        }
    }

    private boolean isUpstream(String internalName) {
        return upstreamClasses.contains(internalName)
            || internalName.startsWith(UPSTREAM_ROOT) && !ownClasses.contains(internalName);
    }

    /**
     * @return the class an array descriptor's elements are, or null for primitives
     */
    private static String elementClass(String descriptor) {
        Type element = Type.getType(descriptor).getElementType();
        return element.getSort() == Type.OBJECT ? element.getInternalName() : null;
    }

    private static String readable(String internalName) {
        return internalName.replace('/', '.');
    }
}
