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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

/**
 * An upstream class, whose members are found by name and shape. Finding one
 * records it for the capability report. A required member that isn't there,
 * or isn't what the way expects, throws {@link Missing}; an optional one
 * that isn't there comes back {@linkplain StaticMethod#exists() absent}, but
 * one that is there in another shape still throws, since that's a change.
 * Optional is only for members whose absence is harmless on any upstream; a
 * member that a newer design brought is required while upstream has the
 * design ({@link #staticMethodSince}). A class whose members can't be read
 * fails every lookup, rather than seeming to lack them.
 *
 * <p>Members declared in superclasses count, as they do for upstream's own
 * code. Parameter types must match exactly; a return type may be a subtype
 * of the one asked for. A field that LibreProtect writes is found as
 * writable, which a final field isn't; one found for reading refuses writes.
 */
public final class UpstreamClass {

    private final Upstream upstream;
    private final String name;
    private final Class<?> type;

    UpstreamClass(Upstream upstream, String name, Class<?> type) {
        this.upstream = upstream;
        this.name = name;
        this.type = type;
    }

    /**
     * @return upstream's binary name of the class
     */
    public String name() {
        return name;
    }

    /**
     * @return whether upstream has the class; only one from
     *         {@link Upstream#typeIfPresent} can lack it
     */
    public boolean exists() {
        return type != null;
    }

    /**
     * @return the class, loaded but not initialized, or its stand-in in tests
     * @throws IllegalStateException if upstream has no such class
     */
    public Class<?> type() {
        if (type == null) {
            throw new IllegalStateException(upstream.name() + " has no class " + simpleName());
        }
        return type;
    }

    /**
     * @param fieldType its type: a primitive exactly, or a class it's assignable to
     * @return the field, for reading only
     */
    public StaticField staticField(String fieldName, Class<?> fieldType) throws Missing {
        return staticField(fieldName, fieldType, false, false);
    }

    /**
     * @return the field, for reading and writing
     * @throws Missing if upstream has no such field, or it's final, which
     *                 LibreProtect can't write
     */
    public StaticField writableStaticField(String fieldName, Class<?> fieldType) throws Missing {
        return staticField(fieldName, fieldType, false, true);
    }

    /**
     * @return the field, for reading only, or an absent one if upstream has
     *         no field of that name
     * @throws Missing if upstream has the field, but not as asked for
     */
    public StaticField staticFieldIfPresent(String fieldName, Class<?> fieldType) throws Missing {
        return staticField(fieldName, fieldType, true, false);
    }

    /**
     * @return a field that a design brought, for reading only: required
     *         while upstream has any trace of the design, since the design
     *         can't work without it, and as for {@link #staticFieldIfPresent}
     *         on an upstream from before the design
     */
    public StaticField staticFieldSince(Design design, String fieldName, Class<?> fieldType) throws Missing {
        return staticField(fieldName, fieldType, !design.isIn(upstream), false);
    }

    private StaticField staticField(String fieldName, Class<?> fieldType, boolean optional, boolean writable)
        throws Missing {
        Found found = field(fieldName, fieldType, true, optional, writable);
        if (found == null) {
            return new StaticField(what(simpleName() + "." + fieldName), fieldType, null, null);
        }
        Class<?> handleType = fieldType.isPrimitive() ? fieldType : Object.class;
        return new StaticField(found.what, found.type,
            found.handle(Handle.Kind.STATIC_GETTER, MethodType.methodType(handleType)),
            writable ? found.handle(Handle.Kind.STATIC_SETTER, MethodType.methodType(void.class, handleType)) : null);
    }

    /**
     * @return the field, for reading only
     */
    public InstanceField field(String fieldName, Class<?> fieldType) throws Missing {
        return field(fieldName, fieldType, false);
    }

    /**
     * @return the field, for reading and writing
     * @throws Missing if upstream has no such field, or it's final, which
     *                 LibreProtect can't write
     */
    public InstanceField writableField(String fieldName, Class<?> fieldType) throws Missing {
        return field(fieldName, fieldType, true);
    }

    private InstanceField field(String fieldName, Class<?> fieldType, boolean writable) throws Missing {
        Found found = field(fieldName, fieldType, false, false, writable);
        Class<?> handleType = fieldType.isPrimitive() ? fieldType : Object.class;
        return new InstanceField(found.what, found.type,
            found.handle(Handle.Kind.GETTER, MethodType.methodType(handleType, Object.class)),
            writable ? found.handle(Handle.Kind.SETTER, MethodType.methodType(void.class, Object.class, handleType))
                : null);
    }

    /**
     * @param returns what it returns: a primitive or {@code void} exactly, or
     *                a class it returns a subtype of; {@code Object.class}
     *                for any object
     */
    public <R> StaticMethod<R, RuntimeException> staticMethod(String methodName, Class<R> returns,
                                                              Class<?>... parameters) throws Missing {
        return staticMethod(methodName, returns, exactly(parameters), false);
    }

    /**
     * @return the method, or an absent one if upstream has no method of that name
     * @throws Missing if upstream has the method, but not as asked for
     */
    public <R> StaticMethod<R, RuntimeException> staticMethodIfPresent(String methodName, Class<R> returns,
                                                                       Class<?>... parameters) throws Missing {
        return staticMethod(methodName, returns, exactly(parameters), true);
    }

    /**
     * @return a method that a design brought: required while upstream has
     *         any trace of the design, since the design can't work without
     *         it, and as for {@link #staticMethodIfPresent} on an upstream
     *         from before the design
     */
    public <R> StaticMethod<R, RuntimeException> staticMethodSince(Design design, String methodName, Class<R> returns,
                                                                   Class<?>... parameters) throws Missing {
        return staticMethod(methodName, returns, exactly(parameters), !design.isIn(upstream));
    }

    /**
     * Find a method by the shapes of its parameters, for parameter types
     * that can't be named, such as upstream's own enums. Only one method may
     * have that shape.
     */
    public <R> StaticMethod<R, RuntimeException> staticMethodShaped(String methodName, Class<R> returns,
                                                                    Shape... parameters) throws Missing {
        return staticMethod(methodName, returns, Arrays.asList(parameters), false);
    }

    private <R> StaticMethod<R, RuntimeException> staticMethod(String methodName, Class<R> returns,
                                                               List<Shape> parameters, boolean optional)
        throws Missing {
        Found found = method(methodName, returns, parameters, true, optional);
        if (found == null) {
            return new StaticMethod<>(what(readable(methodName, parameters)), null, null, returns, null, null,
                RuntimeException.class);
        }
        MethodType handleType = MethodType.methodType(returns, handleTypes(parameters));
        return new StaticMethod<>(found.what, found.recorded, found.handle(Handle.Kind.STATIC_METHOD, handleType),
            returns, found.parameterTypes, found.type, RuntimeException.class);
    }

    public <R> InstanceMethod<R, RuntimeException> method(String methodName, Class<R> returns,
                                                          Class<?>... parameters) throws Missing {
        return method(methodName, returns, parameters, false);
    }

    /**
     * @return the method, or an absent one if upstream has no method of that name
     * @throws Missing if upstream has the method, but not as asked for
     */
    public <R> InstanceMethod<R, RuntimeException> methodIfPresent(String methodName, Class<R> returns,
                                                                   Class<?>... parameters) throws Missing {
        return method(methodName, returns, parameters, true);
    }

    /**
     * Find a method whatever it returns, such as one that returned nothing
     * and now returns its object for chaining calls. Its result is dropped.
     */
    public InstanceMethod<Void, RuntimeException> methodIgnoringResult(String methodName, Class<?>... parameters)
        throws Missing {
        List<Shape> shapes = exactly(parameters);
        Found found = method(methodName, null, shapes, false, false);
        MethodType handleType = MethodType.methodType(void.class, handleTypes(shapes)).insertParameterTypes(0,
            Object.class);
        return new InstanceMethod<>(found.what, found.handle(Handle.Kind.VIRTUAL_METHOD, handleType), void.class,
            found.type, RuntimeException.class);
    }

    private <R> InstanceMethod<R, RuntimeException> method(String methodName, Class<R> returns,
                                                           Class<?>[] parameters, boolean optional) throws Missing {
        List<Shape> shapes = exactly(parameters);
        Found found = method(methodName, returns, shapes, false, optional);
        if (found == null) {
            return new InstanceMethod<>(what(readable(methodName, shapes)), null, returns, null,
                RuntimeException.class);
        }
        MethodType handleType = MethodType.methodType(returns, handleTypes(shapes)).insertParameterTypes(0,
            Object.class);
        return new InstanceMethod<>(found.what, found.handle(Handle.Kind.VIRTUAL_METHOD, handleType), returns,
            found.type, RuntimeException.class);
    }

    public Creator constructor(Class<?>... parameters) throws Missing {
        requireExists();
        String readable = simpleName() + readableParameters(exactly(parameters));
        String descriptor = Descriptors.method(void.class, Arrays.asList(parameters));
        for (ClassFile.Member method : read(type).methods) {
            if (method.name.equals("<init>") && method.descriptor.equals(descriptor)
                && !upstream.isHidden(name, "<init>", descriptor, false)) {
                upstream.member(Descriptors.internalName(name) + "#<init>" + descriptor);
                String what = what(readable);
                return new Creator(what, new Handle(Handle.Kind.CONSTRUCTOR, type, "<init>", descriptor,
                    MethodType.methodType(Object.class, parameters), what));
            }
        }
        throw upstream.missing("constructor " + readable);
    }

    /**
     * @return a reader of a static {@code int} constant, which reads it from
     *         upstream when called, never a copy that the compiler inlined
     */
    public IntSupplier intConstant(String fieldName) throws Missing {
        StaticField field = staticField(fieldName, int.class, false, false);
        return field::getInt;
    }

    /**
     * @return a reader of a static {@code String} constant, which reads it
     *         from upstream when called, or gives {@code orElse} if upstream
     *         has no field of that name
     * @throws Missing if upstream has the field, but not as a {@code String}
     */
    public Supplier<String> stringConstant(String fieldName, String orElse) throws Missing {
        StaticField field = staticField(fieldName, String.class, true, false);
        return () -> field.exists() ? (String) field.get() : orElse;
    }

    /**
     * @return the class as an enum, recording its constants for the report
     * @throws Missing if it isn't an enum
     */
    public UpstreamEnum asEnum() throws Missing {
        requireExists();
        ClassFile file = read(type);
        if (!file.isEnum()) {
            throw new Missing(what(simpleName()) + " isn't an enum");
        }
        List<String> constants = new ArrayList<>();
        for (ClassFile.Member field : file.fields) {
            if (field.is(ClassFile.ENUM) && !upstream.isHidden(name, field.name, field.descriptor, true)) {
                constants.add(field.name);
            }
        }
        upstream.enumeration(Descriptors.internalName(name), constants);
        return new UpstreamEnum(upstream.name(), name, type, constants);
    }

    /**
     * @return whether the class declares a {@code static synchronized}
     *         method, which holds the lock on the class itself
     */
    public boolean hasStaticSynchronizedMethod() throws Missing {
        return !staticSynchronizedMethods().isEmpty();
    }

    /**
     * @return the {@code static synchronized} methods the class declares, by
     *         name and descriptor, such as {@code reloadAndGetId(Ljava/lang/String;)I}
     */
    public List<String> staticSynchronizedMethods() throws Missing {
        List<String> methods = new ArrayList<>();
        if (type != null) {
            for (ClassFile.Member method : read(type).methods) {
                if (method.is(ClassFile.STATIC) && method.is(ClassFile.SYNCHRONIZED)
                    && !upstream.isHidden(name, method.name, method.descriptor, false)) {
                    methods.add(method.name + method.descriptor);
                }
            }
        }
        methods.sort(null);
        return methods;
    }

    /**
     * A member that probing found, with what's needed to make its handle.
     */
    private static final class Found {
        final Class<?> owner;
        final ClassFile.Member member;
        /** The member as the report writes it */
        final String recorded;
        final String what;
        /** The field's type, or what the method returns, as upstream declares it or its stand-in */
        final Class<?> type;
        final List<Class<?>> parameterTypes;

        Found(Class<?> owner, ClassFile.Member member, String recorded, String what, Class<?> type,
              List<Class<?>> parameterTypes) {
            this.owner = owner;
            this.member = member;
            this.recorded = recorded;
            this.what = what;
            this.type = type;
            this.parameterTypes = parameterTypes;
        }

        Handle handle(Handle.Kind kind, MethodType handleType) {
            return new Handle(kind, owner, member.name, member.descriptor, handleType, what);
        }
    }

    /**
     * @param writable whether LibreProtect writes the field, which it can't
     *                 if it's final
     * @return the field, or {@code null} for an optional one that upstream doesn't have
     */
    private Found field(String fieldName, Class<?> fieldType, boolean isStatic, boolean optional, boolean writable)
        throws Missing {
        String readable = simpleName() + "." + fieldName;
        String requested = Descriptors.internalName(name) + "#" + fieldName + ":" + Descriptors.of(fieldType);
        if (type == null && optional) {
            upstream.optional(requested, false);
            return null;
        }
        requireExists();
        Class<?> owner = null;
        ClassFile.Member field = null;
        for (Class<?> c = type; c != null && c != Object.class && field == null; c = c.getSuperclass()) {
            for (ClassFile.Member candidate : read(c).fields) {
                if (candidate.name.equals(fieldName) && !hidden(c, candidate, true)) {
                    owner = c;
                    field = candidate;
                    break;
                }
            }
        }
        // A field whose type is a hidden class is as good as gone
        String hiddenType = field == null ? null : upstream.hiddenType(field.descriptor);
        if (field == null || (hiddenType != null && optional)) {
            if (optional) {
                upstream.optional(requested, false);
                return null;
            }
            throw upstream.missing(readable);
        }
        if (hiddenType != null) {
            throw upstream.missing("class " + Descriptors.simpleName(hiddenType) + ", the type of " + readable);
        }
        String what = what(readable);
        if (field.is(ClassFile.STATIC) != isStatic) {
            throw new Missing(what + (isStatic ? " isn't static" : " is static"));
        }
        if (writable && field.is(ClassFile.FINAL)) {
            throw new Missing(what + " is final, so LibreProtect can't set it");
        }
        Class<?> declared = checkType(field.descriptor, fieldType, owner, what + " has type ");
        String recorded = Descriptors.internalName(upstream.upstreamName(owner)) + "#" + fieldName + ":"
            + field.descriptor;
        record(recorded, optional);
        return new Found(owner, field, recorded, what, declared, null);
    }

    /**
     * @param returns what it must return, or {@code null} for anything
     * @return the method, or {@code null} for an optional one that upstream
     *         has no method of that name for
     */
    private Found method(String methodName, Class<?> returns, List<Shape> parameters, boolean isStatic,
                         boolean optional) throws Missing {
        String readable = readable(methodName, parameters);
        if (type == null && optional) {
            upstream.optional(requested(methodName, returns, parameters), false);
            return null;
        }
        requireExists();
        List<Class<?>> owners = new ArrayList<>();
        List<ClassFile.Member> matches = new ArrayList<>();
        boolean named = false;
        String hiddenType = null;
        for (Class<?> c = type; c != null && c != Object.class; c = c.getSuperclass()) {
            for (ClassFile.Member candidate : read(c).methods) {
                if (!candidate.name.equals(methodName) || candidate.is(ClassFile.BRIDGE)
                    || candidate.is(ClassFile.SYNTHETIC) || hidden(c, candidate, false)) {
                    continue;
                }
                // A method whose signature names a hidden class is as good as gone
                String hidden = upstream.hiddenType(candidate.descriptor);
                if (hidden != null) {
                    hiddenType = hidden;
                    continue;
                }
                named = true;
                List<String> actual = Descriptors.parameters(candidate.descriptor);
                boolean fits = actual.size() == parameters.size();
                for (int i = 0; i < actual.size() && fits; i++) {
                    fits = parameters.get(i).matches(upstream, c.getClassLoader(), actual.get(i));
                }
                // A method that a subclass overrides counts once
                if (fits && !overridden(matches, candidate)) {
                    owners.add(c);
                    matches.add(candidate);
                }
            }
        }
        if (matches.isEmpty()) {
            if (optional && !named) {
                upstream.optional(requested(methodName, returns, parameters), false);
                return null;
            }
            if (hiddenType != null) {
                throw upstream.missing("class " + Descriptors.simpleName(hiddenType) + ", which " + readable
                    + " uses");
            }
            throw upstream.missing(readable);
        }
        if (matches.size() > 1) {
            throw new Missing(upstream.name() + " has more than one " + readable);
        }
        String what = what(readable);
        Class<?> owner = owners.get(0);
        ClassFile.Member method = matches.get(0);
        if (method.is(ClassFile.STATIC) != isStatic) {
            throw new Missing(what + (isStatic ? " isn't static" : " is static"));
        }
        String returned = Descriptors.returnType(method.descriptor);
        Class<?> declared = returns == null ? loadViewed(returned, owner)
            : checkType(returned, returns, owner, what + " returns ");
        List<Class<?>> parameterTypes = new ArrayList<>();
        for (String parameter : Descriptors.parameters(method.descriptor)) {
            parameterTypes.add(loadViewed(parameter, owner));
        }
        String recorded = Descriptors.internalName(upstream.upstreamName(owner)) + "#" + methodName
            + method.descriptor;
        record(recorded, optional);
        return new Found(owner, method, recorded, what, declared, parameterTypes);
    }

    /**
     * @return whether a test hid a member, under the class asked for or the one declaring it
     */
    private boolean hidden(Class<?> owner, ClassFile.Member member, boolean field) {
        return upstream.isHidden(name, member.name, member.descriptor, field)
            || upstream.isHidden(upstream.upstreamName(owner), member.name, member.descriptor, field);
    }

    private static boolean overridden(List<ClassFile.Member> matches, ClassFile.Member candidate) {
        for (ClassFile.Member match : matches) {
            if (Descriptors.parameters(match.descriptor).equals(Descriptors.parameters(candidate.descriptor))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check a field's type or a method's return type against the one asked
     * for: primitives exactly, objects by assignment.
     *
     * @return the declared type, or its stand-in in tests
     */
    private Class<?> checkType(String descriptor, Class<?> wanted, Class<?> owner, String mismatch) throws Missing {
        boolean fits;
        Class<?> declared = null;
        if (wanted.isPrimitive()) {
            fits = descriptor.equals(Descriptors.of(wanted));
        } else if (!Descriptors.isReference(descriptor)) {
            fits = false;
        } else {
            declared = upstream.loadType(descriptor, owner.getClassLoader());
            fits = wanted.isAssignableFrom(declared);
        }
        if (!fits) {
            throw new Missing(mismatch + Descriptors.readableType(descriptor) + ", not "
                + Descriptors.simpleName(wanted));
        }
        return declared == null ? wanted : upstream.view(declared);
    }

    private Class<?> loadViewed(String descriptor, Class<?> owner) throws Missing {
        return upstream.view(upstream.loadType(descriptor, owner.getClassLoader()));
    }

    private void record(String member, boolean optional) {
        if (optional) {
            upstream.optional(member, true);
        } else {
            upstream.member(member);
        }
    }

    private void requireExists() throws Missing {
        if (type == null) {
            throw upstream.missing("class " + simpleName());
        }
    }

    /**
     * @return what a class of the hierarchy declares
     * @throws Missing if that can't be read, so whether it has a member
     *                 can't be told either way
     */
    private ClassFile read(Class<?> c) throws Missing {
        ClassFile file = upstream.classFile(c);
        if (!file.complete) {
            throw new Missing(upstream.name() + "'s class " + Descriptors.simpleName(upstream.upstreamName(c))
                + " can't be read");
        }
        return file;
    }

    /**
     * @return a method as asked for, as the report writes members, for one that's absent
     */
    private String requested(String methodName, Class<?> returns, List<Shape> parameters) {
        StringBuilder descriptor = new StringBuilder("(");
        for (Shape parameter : parameters) {
            descriptor.append(Descriptors.of(parameter.handleType()));
        }
        descriptor.append(')').append(returns == null ? "V" : Descriptors.of(returns));
        return Descriptors.internalName(name) + "#" + methodName + descriptor;
    }

    /**
     * @return a member for messages, such as "CoreProtect's Consumer.isPaused"
     */
    private String what(String readable) {
        return upstream.name() + "'s " + readable;
    }

    /**
     * @return a method for messages, such as {@code Consumer.lockDatabaseReload(long)}
     */
    private String readable(String methodName, List<Shape> parameters) {
        return simpleName() + "." + methodName + readableParameters(parameters);
    }

    private static String readableParameters(List<Shape> parameters) {
        List<String> readable = new ArrayList<>();
        for (Shape parameter : parameters) {
            readable.add(parameter.toString());
        }
        return "(" + String.join(", ", readable) + ")";
    }

    private String simpleName() {
        return Descriptors.simpleName(name);
    }

    private static List<Shape> exactly(Class<?>... types) {
        List<Shape> shapes = new ArrayList<>();
        for (Class<?> type : types) {
            shapes.add(Shape.exactly(type));
        }
        return shapes;
    }

    private static List<Class<?>> handleTypes(List<Shape> shapes) {
        List<Class<?>> types = new ArrayList<>();
        for (Shape shape : shapes) {
            types.add(shape.handleType());
        }
        return types;
    }

    @Override
    public String toString() {
        return name;
    }
}
