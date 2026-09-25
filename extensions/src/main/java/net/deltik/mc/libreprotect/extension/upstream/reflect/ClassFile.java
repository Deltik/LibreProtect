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

package net.deltik.mc.libreprotect.extension.upstream.reflect;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The fields and methods a class declares, with their access flags and
 * descriptors, read from its class file. Reading them this way loads no
 * class, where reflection would load every type in every signature and link
 * the class; a server API type that one of upstream's methods names but the
 * build's older API lacks would then fail a probe that doesn't need it.
 */
final class ClassFile {

    static final int STATIC = 0x0008;
    static final int FINAL = 0x0010;
    static final int SYNCHRONIZED = 0x0020;
    static final int BRIDGE = 0x0040;
    static final int SYNTHETIC = 0x1000;
    static final int ENUM = 0x4000;

    /** A field or method */
    static final class Member {
        final int access;
        final String name;
        final String descriptor;

        Member(int access, String name, String descriptor) {
            this.access = access;
            this.name = name;
            this.descriptor = descriptor;
        }

        boolean is(int flag) {
            return (access & flag) != 0;
        }
    }

    final int access;
    final List<Member> fields;
    final List<Member> methods;
    /**
     * Whether these are all of the class's members: not when neither its
     * class file nor reflection could list them, so that whether it has a
     * member can't be told
     */
    final boolean complete;

    private ClassFile(int access, List<Member> fields, List<Member> methods, boolean complete) {
        this.access = access;
        this.fields = Collections.unmodifiableList(fields);
        this.methods = Collections.unmodifiableList(methods);
        this.complete = complete;
    }

    /**
     * @return the class file of a class name that the loader can see, or
     *         {@code null} if there is none; for one that can't be read, such
     *         as one of a newer format, what reflection finds
     */
    static ClassFile find(ClassLoader loader, String binaryName) {
        String resource = Descriptors.internalName(binaryName) + ".class";
        byte[] bytes;
        try (InputStream in = loader == null ? ClassLoader.getSystemResourceAsStream(resource)
            : loader.getResourceAsStream(resource)) {
            if (in == null) {
                return null;
            }
            bytes = in.readAllBytes();
        } catch (IOException | RuntimeException e) {
            return reflect(loader, binaryName);
        }
        try {
            return read(bytes);
        } catch (IOException | RuntimeException e) {
            return reflect(loader, binaryName);
        }
    }

    /**
     * @return what a loaded class declares, from its class file, or through
     *         reflection for a class without one
     */
    static ClassFile of(Class<?> type) {
        ClassFile file = find(type.getClassLoader(), type.getName());
        return file != null ? file : reflect(type);
    }

    private static ClassFile reflect(ClassLoader loader, String binaryName) {
        try {
            return reflect(Class.forName(binaryName, false, loader));
        } catch (ClassNotFoundException | LinkageError e) {
            return new ClassFile(0, new ArrayList<>(), new ArrayList<>(), false);
        }
    }

    private static ClassFile reflect(Class<?> type) {
        List<Member> fields = new ArrayList<>();
        List<Member> methods = new ArrayList<>();
        boolean complete = true;
        try {
            for (Field field : type.getDeclaredFields()) {
                fields.add(new Member(field.getModifiers() | (field.isEnumConstant() ? ENUM : 0), field.getName(),
                    Descriptors.of(field.getType())));
            }
            for (Method method : type.getDeclaredMethods()) {
                int flags = method.getModifiers() | (method.isBridge() ? BRIDGE : 0)
                    | (method.isSynthetic() ? SYNTHETIC : 0);
                methods.add(new Member(flags, method.getName(),
                    Descriptors.method(method.getReturnType(), List.of(method.getParameterTypes()))));
            }
        } catch (LinkageError e) {
            // A signature names a class that isn't there
            complete = false;
        }
        return new ClassFile(type.getModifiers() | (type.isEnum() ? ENUM : 0), fields, methods, complete);
    }

    static ClassFile read(byte[] bytes) throws IOException {
        DataInputStream data = new DataInputStream(new ByteArrayInputStream(bytes));
        if (data.readInt() != 0xCAFEBABE) {
            throw new IOException("Not a class file");
        }
        skip(data, 4);
        int count = data.readUnsignedShort();
        String[] strings = new String[count];
        for (int i = 1; i < count; i++) {
            int tag = data.readUnsignedByte();
            switch (tag) {
                case 1:
                    strings[i] = data.readUTF();
                    break;
                case 7:
                case 8:
                case 16:
                case 19:
                case 20:
                    skip(data, 2);
                    break;
                case 15:
                    skip(data, 3);
                    break;
                case 3:
                case 4:
                case 9:
                case 10:
                case 11:
                case 12:
                case 17:
                case 18:
                    skip(data, 4);
                    break;
                case 5:
                case 6:
                    // Takes two entries
                    skip(data, 8);
                    i++;
                    break;
                default:
                    throw new IOException("Unknown constant pool tag " + tag);
            }
        }
        int access = data.readUnsignedShort();
        // This class, its superclass, and its interfaces
        skip(data, 4);
        skip(data, 2 * data.readUnsignedShort());
        List<Member> fields = members(data, strings);
        List<Member> methods = members(data, strings);
        return new ClassFile(access, fields, methods, true);
    }

    private static List<Member> members(DataInputStream data, String[] strings) throws IOException {
        int count = data.readUnsignedShort();
        List<Member> members = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            int access = data.readUnsignedShort();
            String name = strings[data.readUnsignedShort()];
            String descriptor = strings[data.readUnsignedShort()];
            if (name == null || descriptor == null) {
                throw new IOException("A member's name or descriptor isn't a string");
            }
            int attributes = data.readUnsignedShort();
            for (int j = 0; j < attributes; j++) {
                skip(data, 2);
                skip(data, data.readInt());
            }
            members.add(new Member(access, name, descriptor));
        }
        return members;
    }

    private static void skip(DataInputStream data, int bytes) throws IOException {
        if (bytes < 0 || data.skipBytes(bytes) != bytes) {
            throw new IOException("The class file ends early");
        }
    }

    boolean isEnum() {
        return (access & ENUM) != 0;
    }

    /**
     * @return the names of the enum constants, in the order they're declared
     */
    List<String> enumConstants() {
        List<String> names = new ArrayList<>();
        for (Member field : fields) {
            if (field.is(ENUM)) {
                names.add(field.name);
            }
        }
        return names;
    }
}
