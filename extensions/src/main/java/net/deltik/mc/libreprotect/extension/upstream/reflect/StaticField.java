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

/**
 * An upstream static field, read and written like upstream's own code does,
 * volatile semantics included, whatever its access. Only one found
 * {@linkplain UpstreamClass#writableStaticField writable} can be written:
 * probing made sure that it isn't final. One that probing found absent reads
 * as false, zero or {@code null}, and ignores writes.
 */
public final class StaticField {

    private final String what;
    private final Class<?> type;
    private final Handle getter;
    /** How it's written, or {@code null} if it's absent or was found for reading only */
    private final Handle setter;

    StaticField(String what, Class<?> type, Handle getter, Handle setter) {
        this.what = what;
        this.type = type;
        this.getter = getter;
        this.setter = setter;
    }

    public boolean exists() {
        return getter != null;
    }

    /**
     * @return the field's declared type, or its stand-in in tests; the
     *         requested type if the field is absent
     */
    public Class<?> type() {
        return type;
    }

    public Object get() {
        if (getter == null) {
            return Handle.zero(type);
        }
        try {
            return (Object) getter.generic().invokeExact();
        } catch (Throwable e) {
            throw Handle.filter(e, RuntimeException.class, what);
        }
    }

    public boolean getBoolean() {
        if (getter == null) {
            return false;
        }
        try {
            return (boolean) getter.exact().invokeExact();
        } catch (Throwable e) {
            throw Handle.filter(e, RuntimeException.class, what);
        }
    }

    public int getInt() {
        if (getter == null) {
            return 0;
        }
        try {
            return (int) getter.exact().invokeExact();
        } catch (Throwable e) {
            throw Handle.filter(e, RuntimeException.class, what);
        }
    }

    /**
     * @throws IllegalStateException if the field was found for reading only
     */
    public void set(Object value) {
        if (!writable()) {
            return;
        }
        try {
            Object ignored = (Object) setter.generic().invokeExact(value);
        } catch (Throwable e) {
            throw Handle.filter(e, RuntimeException.class, what);
        }
    }

    /**
     * @throws IllegalStateException if the field was found for reading only
     */
    public void setBoolean(boolean value) {
        if (!writable()) {
            return;
        }
        try {
            setter.exact().invokeExact(value);
        } catch (Throwable e) {
            throw Handle.filter(e, RuntimeException.class, what);
        }
    }

    /**
     * @throws IllegalStateException if the field was found for reading only
     */
    public void setInt(int value) {
        if (!writable()) {
            return;
        }
        try {
            setter.exact().invokeExact(value);
        } catch (Throwable e) {
            throw Handle.filter(e, RuntimeException.class, what);
        }
    }

    /**
     * @return whether a write goes to upstream: not if the field is absent
     * @throws IllegalStateException if the field was found for reading only
     */
    private boolean writable() {
        if (getter == null) {
            return false;
        }
        if (setter == null) {
            throw new IllegalStateException(what + " was found for reading only");
        }
        return true;
    }

    @Override
    public String toString() {
        return what;
    }
}
