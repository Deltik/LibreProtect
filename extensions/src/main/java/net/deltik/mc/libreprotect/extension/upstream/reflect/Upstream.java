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

import java.lang.invoke.MethodType;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The code LibreProtect adapts to, reached only by name: CoreProtect, or a
 * library it brings along. Probing never initializes a class; it reads class
 * files and loads classes, and a member's handle is made on first use.
 *
 * <p>While {@link Choice} probes a way, the way's {@code Upstream} records
 * everything it resolves and relies on, for the capability report.
 *
 * <p>Tests can make members disappear with {@link #hiding} and put their own
 * classes in place of upstream's with {@link #replacing}, to see how the ways
 * cope with an upstream that changed.
 */
public final class Upstream {

    private final String name;
    private final ClassLoader loader;
    private final Set<String> hidden;
    private final Map<String, Class<?>> standIns;
    private final Findings findings;
    private final Map<String, Optional<ClassFile>> classFiles;

    private Upstream(String name, ClassLoader loader, Set<String> hidden, Map<String, Class<?>> standIns,
                     Findings findings, Map<String, Optional<ClassFile>> classFiles) {
        this.name = name;
        this.loader = loader;
        this.hidden = hidden;
        this.standIns = standIns;
        this.findings = findings;
        this.classFiles = classFiles;
    }

    /**
     * @return CoreProtect, whose classes share LibreProtect's class loader
     */
    public static Upstream coreProtect() {
        return of("CoreProtect", Upstream.class.getClassLoader());
    }

    /**
     * @param name what messages call it, such as {@code CoreProtect}
     */
    public static Upstream of(String name, ClassLoader loader) {
        return new Upstream(name, loader, Collections.emptySet(), Collections.emptyMap(), null,
            new ConcurrentHashMap<>());
    }

    /**
     * For tests: the same upstream without some of its classes or members.
     *
     * @param members classes, such as {@code net.coreprotect.consumer.Consumer};
     *                members by name, such as
     *                {@code net.coreprotect.consumer.Consumer#lockDatabaseReload};
     *                or members as the capability report writes them, such as
     *                {@code net/coreprotect/consumer/Consumer#lockDatabaseReload(J)Z}
     */
    public Upstream hiding(String... members) {
        Set<String> more = new HashSet<>(hidden);
        for (String member : members) {
            more.add(normalize(member));
        }
        return new Upstream(name, loader, Collections.unmodifiableSet(more), standIns, findings, classFiles);
    }

    /**
     * For tests: the same upstream with {@code standIn} in place of a class,
     * such as an enum with a constant upstream might add. Members declared
     * with the class's type are seen as having the stand-in's.
     */
    public Upstream replacing(String className, Class<?> standIn) {
        Map<String, Class<?>> more = new HashMap<>(standIns);
        more.put(Descriptors.binaryName(className), standIn);
        return new Upstream(name, loader, hidden, Collections.unmodifiableMap(more), findings, classFiles);
    }

    /**
     * @return a library that upstream brings along, such as a JDBC driver,
     *         seen through the same class loader, with the same classes and
     *         members hidden, and called {@code name} in messages. Nothing
     *         found in it is recorded: the capability report lists only what
     *         upstream's own JAR has.
     */
    public Upstream library(String name) {
        return new Upstream(name, loader, hidden, standIns, null, classFiles);
    }

    /**
     * @return the same upstream, recording what a way resolves into {@code findings}
     */
    Upstream recording(Findings findings) {
        return new Upstream(name, loader, hidden, standIns, findings, classFiles);
    }

    public String name() {
        return name;
    }

    /**
     * @param className a binary name, such as {@code net.coreprotect.consumer.Consumer$OperationStartResult}
     * @return the class, loaded but not initialized
     * @throws Missing if upstream has no such class
     */
    public UpstreamClass type(String className) throws Missing {
        String binary = Descriptors.binaryName(className);
        Class<?> type = load(binary);
        member(Descriptors.internalName(binary));
        return new UpstreamClass(this, binary, type);
    }

    /**
     * @return a class that upstream gave out, such as the class of a
     *         connection its library opened
     */
    public UpstreamClass type(Class<?> type) throws Missing {
        String binary = upstreamName(type);
        if (isHidden(binary)) {
            throw missing("class " + Descriptors.simpleName(binary));
        }
        member(Descriptors.internalName(binary));
        return new UpstreamClass(this, binary, view(type));
    }

    /**
     * @return the class, or one that {@link UpstreamClass#exists() doesn't
     *         exist} if upstream has no such class, whose optional members are
     *         all absent
     */
    public UpstreamClass typeIfPresent(String className) {
        String binary = Descriptors.binaryName(className);
        Class<?> type;
        try {
            type = load(binary);
        } catch (Missing e) {
            type = null;
        }
        optional(Descriptors.internalName(binary), type != null);
        return new UpstreamClass(this, binary, type);
    }

    /**
     * @param trace a class, such as {@code net.coreprotect.database.DatabaseType},
     *              or a member of one by name, such as
     *              {@code net.coreprotect.database.DatabaseType#DUCKDB}
     * @return whether upstream has it, without loading anything
     */
    public boolean has(String trace) {
        String normalized = normalize(trace);
        int hash = normalized.indexOf('#');
        String owner = hash < 0 ? normalized : normalized.substring(0, hash);
        ClassFile file = isHidden(owner) ? null : classFile(loader, owner);
        if (file == null || hash < 0) {
            return file != null;
        }
        if (!file.complete) {
            // It may have the member; better to assume so than to take an older way on a newer upstream
            return true;
        }
        String member = normalized.substring(hash + 1);
        for (ClassFile.Member field : file.fields) {
            if (field.name.equals(member) && !isHidden(owner, field.name, field.descriptor, true)) {
                return true;
            }
        }
        for (ClassFile.Member method : file.methods) {
            if (method.name.equals(member) && !isHidden(owner, method.name, method.descriptor, false)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Refuse a way once upstream has something that rules it out. The
     * {@link Design} of a newer way already rules out every older way while
     * upstream has any trace of it (see {@link Choice}); this is for a way
     * that one particular member rules out besides.
     *
     * @param member a member of the class by name, or {@code null} for the class itself
     * @param because why that rules the way out, following "CoreProtect has
     *                X, ", such as "so use-mysql no longer selects its database"
     */
    public void requireAbsent(String className, String member, String because) throws Missing {
        String trace = Descriptors.binaryName(className) + (member == null ? "" : "#" + member);
        if (has(trace)) {
            throw Missing.newerDesign(name + " has " + Missing.readableTrace(trace) + ", " + because);
        }
    }

    /**
     * Record behavior of upstream methods that a way relies on and probing
     * can't prove, such as a loop that honors a flag, so that the build sees
     * when upstream changes them. The methods must exist.
     *
     * @param what what the way relies on them to do
     * @param methodDescriptors methods by name and descriptor, such as {@code pauseConsumer(I)V}
     */
    public void relyOn(String what, String className, String... methodDescriptors) throws Missing {
        String owner = Descriptors.binaryName(className);
        ClassFile file = isHidden(owner) ? null : classFile(loader, owner);
        if (file == null) {
            throw missing("class " + Descriptors.simpleName(owner));
        }
        if (!file.complete) {
            throw new Missing(name + "'s class " + Descriptors.simpleName(owner) + " can't be read");
        }
        for (String method : methodDescriptors) {
            int parenthesis = method.indexOf('(');
            String methodName = method.substring(0, parenthesis);
            String descriptor = method.substring(parenthesis);
            boolean found = false;
            for (ClassFile.Member candidate : file.methods) {
                if (candidate.name.equals(methodName) && candidate.descriptor.equals(descriptor)
                    && !isHidden(owner, methodName, descriptor, false)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw missing(Missing.readable(Descriptors.internalName(owner) + "#" + method));
            }
            if (findings != null) {
                findings.relies.put(Descriptors.internalName(owner) + "#" + method, what);
            }
        }
    }

    /**
     * Like {@link #relyOn(String, String, String...)}, for behavior that a
     * design brought: required while upstream has any trace of the design,
     * and nothing to rely on before it.
     */
    public void relyOnSince(Design design, String what, String className, String... methodDescriptors)
        throws Missing {
        if (design.isIn(this)) {
            relyOn(what, className, methodDescriptors);
        }
    }

    /**
     * Record behavior of a method that a way already found and relies on
     * beyond its signature, such as what it creates.
     *
     * @param what what the way relies on it to do
     * @throws IllegalArgumentException if the method is absent
     */
    public void relyOn(String what, StaticMethod<?, ?> method) {
        if (!method.exists()) {
            throw new IllegalArgumentException(method + " is absent");
        }
        if (findings != null) {
            findings.relies.put(method.member(), what);
        }
    }

    /**
     * Record upstream documentation that a way follows, for the build to
     * watch for changes.
     *
     * @param path the document's path in upstream's source tree, such as {@code docs/config.md}
     * @param what what it documents that the way follows
     */
    public void doc(String path, String what) {
        if (findings != null) {
            findings.docs.put(path, what);
        }
    }

    Missing missing(String what) {
        return new Missing(name + " has no " + what);
    }

    /**
     * @return a class by binary name, or its stand-in, loaded without initializing it
     */
    Class<?> load(String binaryName) throws Missing {
        return load(binaryName, loader);
    }

    Class<?> load(String binaryName, ClassLoader from) throws Missing {
        if (isHidden(binaryName)) {
            throw missing("class " + Descriptors.simpleName(binaryName));
        }
        Class<?> standIn = standIns.get(binaryName);
        if (standIn != null) {
            return standIn;
        }
        try {
            return Class.forName(binaryName, false, from);
        } catch (ClassNotFoundException e) {
            throw missing("class " + Descriptors.simpleName(binaryName));
        } catch (LinkageError e) {
            throw new Missing(name + "'s class " + Descriptors.simpleName(binaryName) + " can't be loaded: " + e);
        }
    }

    /**
     * @return the class a type descriptor names, as the JVM sees it, without its stand-in
     */
    Class<?> loadType(String typeDescriptor, ClassLoader from) throws Missing {
        try {
            return MethodType.fromMethodDescriptorString("()" + typeDescriptor, from).returnType();
        } catch (TypeNotPresentException | LinkageError e) {
            throw new Missing(name + "'s " + Descriptors.readableType(typeDescriptor) + " can't be loaded: " + e);
        }
    }

    /**
     * @return a class's stand-in, or the class
     */
    Class<?> view(Class<?> type) {
        Class<?> standIn = standIns.get(type.getName());
        return standIn != null ? standIn : type;
    }

    /**
     * @return the upstream name of a class or of its stand-in
     */
    String upstreamName(Class<?> type) {
        for (Map.Entry<String, Class<?>> standIn : standIns.entrySet()) {
            if (standIn.getValue() == type) {
                return standIn.getKey();
            }
        }
        return type.getName();
    }

    /**
     * @return the class file of a class name, or of its stand-in, or {@code null} if there is none
     */
    ClassFile classFile(ClassLoader from, String binaryName) {
        Class<?> standIn = standIns.get(binaryName);
        if (standIn != null) {
            return ClassFile.of(standIn);
        }
        if (from != loader) {
            return ClassFile.find(from, binaryName);
        }
        return classFiles.computeIfAbsent(binaryName, key -> Optional.ofNullable(ClassFile.find(loader, key)))
            .orElse(null);
    }

    /**
     * @return what a loaded class declares
     */
    ClassFile classFile(Class<?> type) {
        ClassFile file = type.getClassLoader() == loader ? classFile(loader, type.getName()) : null;
        return file != null ? file : ClassFile.of(type);
    }

    boolean isHidden(String className) {
        return hidden.contains(className);
    }

    boolean isHidden(String className, String member, String descriptor, boolean field) {
        return hidden.contains(className) || hidden.contains(className + "#" + member)
            || hidden.contains(className + "#" + member + (field ? ":" : "") + descriptor);
    }

    /**
     * @return a class named in a descriptor that is hidden, or {@code null}
     */
    String hiddenType(String descriptor) {
        List<String> names = Descriptors.classNames(descriptor);
        for (String className : names) {
            if (isHidden(className)) {
                return className;
            }
        }
        return null;
    }

    void member(String member) {
        if (findings != null) {
            findings.members.add(member);
        }
    }

    void optional(String member, boolean present) {
        if (findings != null) {
            findings.optional.put(member, present);
        }
    }

    void enumeration(String owner, List<String> constants) {
        if (findings != null) {
            findings.enums.put(owner, constants);
        }
    }

    private static String normalize(String member) {
        int hash = member.indexOf('#');
        return hash < 0 ? Descriptors.binaryName(member)
            : Descriptors.binaryName(member.substring(0, hash)) + member.substring(hash);
    }

    @Override
    public String toString() {
        return name;
    }
}
