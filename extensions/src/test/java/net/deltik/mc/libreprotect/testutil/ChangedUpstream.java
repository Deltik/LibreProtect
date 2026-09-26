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

package net.deltik.mc.libreprotect.testutil;

import net.deltik.mc.libreprotect.extension.upstream.Names;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * The CoreProtect being built, changed as an upstream refactoring could
 * change it: classes renamed along with every reference to them, or a field
 * made final. It changes the class files the way LibreProtect's reviews do
 * with ASM, in memory: CoreProtect's own classes come from the changed copy,
 * and only from there; everything else comes from the test's class path.
 * Nothing is initialized, so only probing works with it.
 */
public final class ChangedUpstream extends ClassLoader {

    private static final String OWN = "net/coreprotect/";

    /** CoreProtect's changed class files, by resource name */
    private final Map<String, byte[]> classes;

    private ChangedUpstream(Map<String, byte[]> classes) {
        super(ChangedUpstream.class.getClassLoader());
        this.classes = classes;
    }

    /**
     * @param renames binary class names, old to new; a class's nested
     *                classes follow it
     * @return CoreProtect with those classes renamed
     */
    public static Upstream renaming(Map<String, String> renames) throws IOException {
        return changing(renames, null, null);
    }

    /**
     * @param className a binary class name
     * @return CoreProtect with the class's field made final, and so not volatile
     */
    public static Upstream makingFinal(String className, String field) throws IOException {
        return changing(Map.of(), className.replace('.', '/'), field);
    }

    private static Upstream changing(Map<String, String> renames, String finalOwner, String finalField)
        throws IOException {
        Map<String, String> internal = new LinkedHashMap<>();
        renames.forEach((from, to) -> internal.put(from.replace('.', '/'), to.replace('.', '/')));
        Remapper remapper = new Remapper() {
            @Override
            public String map(String name) {
                for (Map.Entry<String, String> rename : internal.entrySet()) {
                    if (name.equals(rename.getKey()) || name.startsWith(rename.getKey() + "$")) {
                        return rename.getValue() + name.substring(rename.getKey().length());
                    }
                }
                return name;
            }
        };
        Map<String, byte[]> classes = new HashMap<>();
        try (JarFile jar = new JarFile(upstreamJar())) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (!name.startsWith(OWN) || !name.endsWith(".class")) {
                    continue;
                }
                byte[] bytes;
                try (InputStream in = jar.getInputStream(entry)) {
                    bytes = in.readAllBytes();
                }
                String className = name.substring(0, name.length() - ".class".length());
                ClassWriter writer = new ClassWriter(0);
                ClassVisitor visitor = className.equals(finalOwner) ? finalField(writer, finalField) : writer;
                new ClassReader(bytes).accept(new ClassRemapper(visitor, remapper), 0);
                classes.put(remapper.map(className) + ".class", writer.toByteArray());
            }
        }
        return Upstream.of("CoreProtect", new ChangedUpstream(classes));
    }

    /**
     * @return a visitor that makes the field final, and so not volatile
     */
    private static ClassVisitor finalField(ClassVisitor next, String field) {
        return new ClassVisitor(Opcodes.ASM9, next) {
            @Override
            public FieldVisitor visitField(int access, String name, String descriptor, String signature,
                                           Object value) {
                int changed = name.equals(field) ? (access | Opcodes.ACC_FINAL) & ~Opcodes.ACC_VOLATILE : access;
                return super.visitField(changed, name, descriptor, signature, value);
            }
        };
    }

    /**
     * @return the upstream JAR on the test's class path
     */
    private static File upstreamJar() throws IOException {
        String resource = Names.CONFIG_HANDLER.replace('.', '/') + ".class";
        URL found = ChangedUpstream.class.getClassLoader().getResource(resource);
        if (found == null) {
            throw new IllegalStateException("CoreProtect isn't on the class path");
        }
        try {
            return new File(((JarURLConnection) found.openConnection()).getJarFileURL().toURI());
        } catch (URISyntaxException e) {
            throw new IOException(e);
        }
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        if (!name.startsWith(OWN.replace('/', '.'))) {
            return super.loadClass(name, resolve);
        }
        synchronized (getClassLoadingLock(name)) {
            Class<?> loaded = findLoadedClass(name);
            if (loaded == null) {
                byte[] bytes = classes.get(name.replace('.', '/') + ".class");
                if (bytes == null) {
                    throw new ClassNotFoundException(name);
                }
                loaded = defineClass(name, bytes, 0, bytes.length);
            }
            if (resolve) {
                resolveClass(loaded);
            }
            return loaded;
        }
    }

    @Override
    public URL getResource(String name) {
        return name.startsWith(OWN) ? null : super.getResource(name);
    }

    @Override
    public InputStream getResourceAsStream(String name) {
        if (name.startsWith(OWN)) {
            byte[] bytes = classes.get(name);
            return bytes == null ? null : new ByteArrayInputStream(bytes);
        }
        return super.getResourceAsStream(name);
    }
}
