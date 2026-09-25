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
import java.util.List;

/**
 * An upstream static method. {@link #call} lets unchecked exceptions and
 * errors through, and the checked exception chosen with {@link #throwing};
 * any other checked exception means upstream changed, so it becomes
 * {@link UpstreamChanged}. One that probing found absent does nothing and
 * returns false, zero or {@code null}.
 *
 * @param <R> what it returns, boxed
 * @param <X> the checked exception it may throw
 */
public final class StaticMethod<R, X extends Exception> {

    private final String what;
    private final String member;
    private final Handle handle;
    private final Class<?> returns;
    private final List<Class<?>> parameterTypes;
    private final Class<?> returnType;
    private final Class<X> allowed;

    /**
     * @param member the method as the report writes it, or {@code null} if it's absent
     */
    StaticMethod(String what, String member, Handle handle, Class<?> returns, List<Class<?>> parameterTypes,
                 Class<?> returnType, Class<X> allowed) {
        this.what = what;
        this.member = member;
        this.handle = handle;
        this.returns = returns;
        this.parameterTypes = parameterTypes;
        this.returnType = returnType;
        this.allowed = allowed;
    }

    public boolean exists() {
        return handle != null;
    }

    String member() {
        return member;
    }

    /**
     * @return this method, letting {@code exception} through when it throws
     *         one, as upstream declares it may
     */
    public <Y extends Exception> StaticMethod<R, Y> throwing(Class<Y> exception) {
        return new StaticMethod<>(what, member, handle, returns, parameterTypes, returnType, exception);
    }

    @SuppressWarnings("unchecked")
    public R call(Object... args) throws X {
        if (handle == null) {
            return (R) Handle.zero(returns);
        }
        try {
            return (R) Handle.invoke(handle.generic(), args);
        } catch (Throwable e) {
            throw Handle.filter(e, allowed, what);
        }
    }

    /**
     * @return the handle for hot paths, which takes exactly the parameter
     *         types asked for ({@code Object} for those matched by shape) and
     *         returns exactly the type asked for
     * @throws IllegalStateException if the method is absent
     */
    public MethodHandle exact() {
        if (handle == null) {
            throw new IllegalStateException(what + " is absent");
        }
        return handle.exact();
    }

    /**
     * @return the type of a parameter as upstream declares it, or its
     *         stand-in in tests, such as the enum a parameter matched by
     *         shape turned out to be
     */
    public Class<?> parameterType(int index) {
        return parameterTypes.get(index);
    }

    /**
     * @return what upstream declares that the method returns, or its
     *         stand-in in tests
     */
    public Class<?> returnType() {
        return returnType;
    }

    @Override
    public String toString() {
        return what;
    }
}
