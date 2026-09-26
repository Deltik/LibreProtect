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

import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.upstream.ActiveDatabase;
import net.deltik.mc.libreprotect.extension.upstream.Names;
import net.deltik.mc.libreprotect.extension.upstream.reflect.InstanceField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Shape;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * CoreProtect's static state for tests of either generation, set through
 * the same toolkit that LibreProtect's extensions use, so that tests name
 * no member that only one generation has. Every change is undone by
 * {@link #reset()}, which runs after each test when this is registered with
 * {@code @RegisterExtension}.
 */
public final class CoreProtectFixture implements AfterEachCallback {

    private final Upstream upstream;
    /** How to put back each field this changed, by path */
    private final Map<String, Runnable> originals = new LinkedHashMap<>();

    public CoreProtectFixture() {
        this(Upstream.coreProtect());
    }

    public CoreProtectFixture(Upstream upstream) {
        this.upstream = upstream;
    }

    /**
     * Make CoreProtect use an engine, the way this CoreProtect selects one:
     * its engine type where it has one, and {@code use-mysql}.
     */
    public CoreProtectFixture useEngine(Engine engine) {
        if (upstream.has(Names.CONFIG_HANDLER + "#databaseType")) {
            set("ConfigHandler.databaseType", engine.name());
        }
        return set("Config.MYSQL", engine == Engine.MYSQL);
    }

    /**
     * @param path a field as {@code Class.field}, with the class's simple
     *             name, such as {@code ConfigHandler.serverRunning} or
     *             {@code Consumer.pausedSuccess}; a field of {@code Config}
     *             is the global config's
     * @param value the new value; for an enum field, a constant's name
     */
    public CoreProtectFixture set(String path, Object value) {
        Accessor accessor = accessor(path);
        if (!originals.containsKey(path)) {
            Object original = accessor.get.get();
            originals.put(path, () -> accessor.set.accept(original));
        }
        accessor.set.accept(convert(accessor.type, value));
        return this;
    }

    /**
     * @return a field's value, as for {@link #set}
     */
    public Object get(String path) {
        return accessor(path).get.get();
    }

    /**
     * Call a static method of CoreProtect's, found by its name and number of
     * parameters, such as one that only one generation has. What it
     * changes isn't put back.
     *
     * @param path a method as {@code Class.method}, as for {@link #set}, such
     *             as {@code Consumer.claimRollback}
     * @return what it returns, or {@code null} if nothing
     */
    public Object call(String path, Object... args) {
        int dot = path.lastIndexOf('.');
        String methodName = path.substring(dot + 1);
        try {
            UpstreamClass owner = upstream.type(qualified(path.substring(0, dot)));
            Method declared = declaredMethod(owner.type(), methodName, args.length);
            Class<?> returns = declared.getReturnType().isPrimitive() ? declared.getReturnType() : Object.class;
            return owner.staticMethod(methodName, returns, declared.getParameterTypes()).call(args);
        } catch (Missing e) {
            throw new IllegalArgumentException("CoreProtect has no " + path + ": " + e.getMessage(), e);
        }
    }

    /**
     * Have CoreProtect create its tables in the database it uses, with its
     * own schema code, which also lists them in
     * {@code ConfigHandler.databaseTables}, as at startup: through the
     * overload that takes the engine where CoreProtect has one, and otherwise
     * through the one that takes {@code use-mysql}.
     */
    public CoreProtectFixture createTables(String prefix) throws Exception {
        Engine engine = ActiveDatabase.CAPABILITY.probe(upstream).require().activeEngine();
        UpstreamClass database = upstream.type(Names.DATABASE);
        try (Connection connection = database.staticMethod("getConnection", Connection.class, boolean.class,
            int.class).call(true, 0)) {
            if (upstream.has(Names.DATABASE_TYPE)) {
                StaticMethod<Void, RuntimeException> create = database.staticMethodShaped("createDatabaseTables",
                    void.class, Shape.exactly(String.class), Shape.exactly(boolean.class),
                    Shape.exactly(Connection.class), Shape.enumWith("SQLITE", "MYSQL"), Shape.exactly(boolean.class));
                create.call(prefix, true, connection, upstream.type(create.parameterType(3)).asEnum()
                    .constant(engine.name()), false);
            } else {
                database.staticMethod("createDatabaseTables", void.class, String.class, boolean.class,
                    Connection.class, boolean.class, boolean.class).call(prefix, true, connection,
                    engine == Engine.MYSQL, false);
            }
        }
        return this;
    }

    /**
     * @return whether CoreProtect has a background purge claimed, where it
     *         has such claims
     */
    public boolean backgroundPurgeClaimed() {
        return upstream.has(Names.CONSUMER + "#isBackgroundPurgeRunning")
            && Boolean.TRUE.equals(call("Consumer.isBackgroundPurgeRunning"));
    }

    /**
     * Put back every field this changed.
     */
    public void reset() {
        List<Runnable> restores = new ArrayList<>(originals.values());
        for (int i = restores.size() - 1; i >= 0; i--) {
            restores.get(i).run();
        }
        originals.clear();
    }

    @Override
    public void afterEach(ExtensionContext context) {
        reset();
    }

    private static final class Accessor {
        final Class<?> type;
        final Supplier<Object> get;
        final Consumer<Object> set;

        Accessor(Class<?> type, Supplier<Object> get, Consumer<Object> set) {
            this.type = type;
            this.get = get;
            this.set = set;
        }
    }

    private Accessor accessor(String path) {
        int dot = path.lastIndexOf('.');
        String fieldName = path.substring(dot + 1);
        try {
            UpstreamClass owner = upstream.type(qualified(path.substring(0, dot)));
            Field declared = declared(owner.type(), fieldName);
            if (Modifier.isStatic(declared.getModifiers())) {
                StaticField field = owner.staticField(fieldName, declared.getType());
                return new Accessor(declared.getType(), field::get, value -> writable(path, () ->
                    owner.writableStaticField(fieldName, declared.getType())).set(value));
            }
            // An instance field, of the instance that the class's getGlobal() gives, as Config's
            Object global = owner.staticMethod("getGlobal", owner.type()).call();
            InstanceField field = owner.field(fieldName, declared.getType());
            return new Accessor(declared.getType(), () -> field.get(global), value -> writable(path, () ->
                owner.writableField(fieldName, declared.getType())).set(global, value));
        } catch (Missing e) {
            throw new IllegalArgumentException("CoreProtect has no " + path + ": " + e.getMessage(), e);
        }
    }

    /** A lookup that may find upstream lacking what it looks for */
    @FunctionalInterface
    private interface Lookup<T> {
        T find() throws Missing;
    }

    /**
     * @return a field found for writing, which only a test sets
     */
    private static <T> T writable(String path, Lookup<T> lookup) {
        try {
            return lookup.find();
        } catch (Missing e) {
            throw new IllegalArgumentException("CoreProtect's " + path + " can't be set: " + e.getMessage(), e);
        }
    }

    private static Method declaredMethod(Class<?> type, String name, int parameters) {
        List<Method> found = new ArrayList<>();
        for (Class<?> c = type; c != null; c = c.getSuperclass()) {
            for (Method method : c.getDeclaredMethods()) {
                if (method.getName().equals(name) && method.getParameterCount() == parameters
                    && Modifier.isStatic(method.getModifiers()) && !method.isSynthetic()) {
                    found.add(method);
                }
            }
        }
        if (found.size() != 1) {
            throw new IllegalArgumentException(type.getName() + " has " + found.size() + " static methods " + name
                + " with " + parameters + " parameters");
        }
        return found.get(0);
    }

    private static Field declared(Class<?> type, String name) {
        for (Class<?> c = type; c != null; c = c.getSuperclass()) {
            for (Field field : c.getDeclaredFields()) {
                if (field.getName().equals(name)) {
                    return field;
                }
            }
        }
        throw new IllegalArgumentException(type.getName() + " has no field " + name);
    }

    /**
     * @return the binary name in {@link Names} of a class's simple name
     */
    private static String qualified(String simpleName) {
        for (Field constant : Names.class.getFields()) {
            try {
                String name = (String) constant.get(null);
                String simple = name.substring(name.lastIndexOf('.') + 1).replace('$', '.');
                if (simple.equals(simpleName)) {
                    return name;
                }
            } catch (IllegalAccessException e) {
                throw new IllegalStateException(e);
            }
        }
        throw new IllegalArgumentException("Names has no class " + simpleName);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Object convert(Class<?> type, Object value) {
        if (type.isEnum() && value instanceof String) {
            return Enum.valueOf((Class) type, (String) value);
        }
        return value;
    }
}
