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

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;

/**
 * A method handle for a member that probing found, made on first use and
 * kept. Probing only reads class files; making the handle waits until the
 * member is used, since the JVM may link the class to make it.
 *
 * <p>Handles come from a private lookup in the member's class, which reads
 * and writes fields the way {@code getstatic} and {@code putstatic} do,
 * volatile ones included, and reaches protected and private members without
 * extending their class.
 */
final class Handle {

    enum Kind {
        STATIC_GETTER, STATIC_SETTER, GETTER, SETTER, STATIC_METHOD, VIRTUAL_METHOD, CONSTRUCTOR
    }

    private final Kind kind;
    private final Class<?> owner;
    private final String name;
    private final String descriptor;
    private final MethodType type;
    private final String what;
    private volatile MethodHandle exact;
    private volatile MethodHandle generic;

    /**
     * @param owner the class that declares the member
     * @param descriptor the member's field or method descriptor
     * @param type the type that callers invoke the handle with exactly
     * @param what the member, for errors, such as "CoreProtect's Consumer.isPaused"
     */
    Handle(Kind kind, Class<?> owner, String name, String descriptor, MethodType type, String what) {
        this.kind = kind;
        this.owner = owner;
        this.name = name;
        this.descriptor = descriptor;
        this.type = type;
        this.what = what;
    }

    MethodType type() {
        return type;
    }

    /**
     * @return the handle, with exactly {@link #type()}
     */
    MethodHandle exact() {
        MethodHandle handle = exact;
        if (handle == null) {
            handle = resolve().asType(type);
            exact = handle;
        }
        return handle;
    }

    /**
     * @return the handle with only {@code Object} parameters and result
     */
    MethodHandle generic() {
        MethodHandle handle = generic;
        if (handle == null) {
            handle = exact().asType(MethodType.genericMethodType(type.parameterCount()));
            generic = handle;
        }
        return handle;
    }

    private MethodHandle resolve() {
        try {
            MethodHandles.Lookup lookup = lookup();
            ClassLoader loader = owner.getClassLoader();
            switch (kind) {
                case STATIC_GETTER:
                    return lookup.findStaticGetter(owner, name, fieldType(loader));
                case STATIC_SETTER:
                    return lookup.findStaticSetter(owner, name, fieldType(loader));
                case GETTER:
                    return lookup.findGetter(owner, name, fieldType(loader));
                case SETTER:
                    return lookup.findSetter(owner, name, fieldType(loader));
                case STATIC_METHOD:
                    return lookup.findStatic(owner, name, MethodType.fromMethodDescriptorString(descriptor, loader));
                case VIRTUAL_METHOD:
                    return lookup.findVirtual(owner, name, MethodType.fromMethodDescriptorString(descriptor, loader));
                default:
                    return lookup.findConstructor(owner, MethodType.fromMethodDescriptorString(descriptor, loader));
            }
        } catch (ReflectiveOperationException | RuntimeException e) {
            throw new UpstreamChanged(what + " can't be reached: " + e, e);
        }
    }

    private Class<?> fieldType(ClassLoader loader) {
        return MethodType.fromMethodDescriptorString("()" + descriptor, loader).returnType();
    }

    private MethodHandles.Lookup lookup() {
        try {
            return MethodHandles.privateLookupIn(owner, MethodHandles.lookup());
        } catch (IllegalAccessException e) {
            // A class in a named module that doesn't open its package; its public members are enough
            return MethodHandles.publicLookup();
        }
    }

    /**
     * Call a generic handle with the arguments, without spreading them for
     * the usual numbers of arguments.
     */
    static Object invoke(MethodHandle generic, Object[] args) throws Throwable {
        switch (args.length) {
            case 0:
                return (Object) generic.invokeExact();
            case 1:
                return (Object) generic.invokeExact(args[0]);
            case 2:
                return (Object) generic.invokeExact(args[0], args[1]);
            case 3:
                return (Object) generic.invokeExact(args[0], args[1], args[2]);
            case 4:
                return (Object) generic.invokeExact(args[0], args[1], args[2], args[3]);
            case 5:
                return (Object) generic.invokeExact(args[0], args[1], args[2], args[3], args[4]);
            default:
                return generic.invokeWithArguments(args);
        }
    }

    /**
     * @return {@code thrown} if callers may see it, having rethrown unchecked
     *         exceptions and errors
     * @throws UpstreamChanged for a checked exception that isn't allowed
     */
    static <X extends Exception> X filter(Throwable thrown, Class<X> allowed, String what) {
        if (thrown instanceof RuntimeException) {
            throw (RuntimeException) thrown;
        }
        if (thrown instanceof Error) {
            throw (Error) thrown;
        }
        if (allowed.isInstance(thrown)) {
            return allowed.cast(thrown);
        }
        throw new UpstreamChanged(what + " failed with an unexpected " + thrown, thrown);
    }

    /**
     * @return the value of a type that a missing member stands for: false,
     *         zero or {@code null}
     */
    static Object zero(Class<?> type) {
        if (!type.isPrimitive() || type == void.class) {
            return null;
        }
        try {
            return (Object) MethodHandles.zero(type).asType(MethodType.methodType(Object.class)).invokeExact();
        } catch (Throwable e) {
            throw new AssertionError(e);
        }
    }
}
