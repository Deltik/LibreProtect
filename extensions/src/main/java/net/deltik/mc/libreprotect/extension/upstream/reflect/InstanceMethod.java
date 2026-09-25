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

/**
 * An upstream instance method, called on an object that upstream gave out.
 * Exceptions pass as they do for {@link StaticMethod}. One that probing found
 * absent does nothing and returns false, zero or {@code null}.
 *
 * @param <R> what it returns, boxed
 * @param <X> the checked exception it may throw
 */
public final class InstanceMethod<R, X extends Exception> {

    private final String what;
    private final Handle handle;
    private final Class<?> returns;
    private final Class<?> returnType;
    private final Class<X> allowed;

    InstanceMethod(String what, Handle handle, Class<?> returns, Class<?> returnType, Class<X> allowed) {
        this.what = what;
        this.handle = handle;
        this.returns = returns;
        this.returnType = returnType;
        this.allowed = allowed;
    }

    public boolean exists() {
        return handle != null;
    }

    /**
     * @return this method, letting {@code exception} through when it throws
     *         one, as upstream declares it may
     */
    public <Y extends Exception> InstanceMethod<R, Y> throwing(Class<Y> exception) {
        return new InstanceMethod<>(what, handle, returns, returnType, exception);
    }

    @SuppressWarnings("unchecked")
    public R call(Object target, Object... args) throws X {
        if (handle == null) {
            return (R) Handle.zero(returns);
        }
        Object[] all = new Object[args.length + 1];
        all[0] = target;
        System.arraycopy(args, 0, all, 1, args.length);
        try {
            return (R) Handle.invoke(handle.generic(), all);
        } catch (Throwable e) {
            throw Handle.filter(e, allowed, what);
        }
    }

    /**
     * @return the handle for hot paths, which takes the target as an
     *         {@code Object}, then exactly the parameter types asked for, and
     *         returns exactly the type asked for ({@code void} for a method
     *         whose result is ignored)
     * @throws IllegalStateException if the method is absent
     */
    public MethodHandle exact() {
        if (handle == null) {
            throw new IllegalStateException(what + " is absent");
        }
        return handle.exact();
    }

    /**
     * @return what upstream declares that the method returns, or its stand-in in tests
     */
    public Class<?> returnType() {
        return returnType;
    }

    @Override
    public String toString() {
        return what;
    }
}
