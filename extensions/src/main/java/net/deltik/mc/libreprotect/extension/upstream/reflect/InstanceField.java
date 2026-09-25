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
 * An upstream instance field, such as a setting of CoreProtect's
 * {@code Config}, read like upstream's own code does, whatever its access.
 * Only one found {@linkplain UpstreamClass#writableField writable} can be
 * written: probing made sure that it isn't final.
 */
public final class InstanceField {

    private final String what;
    private final Class<?> type;
    private final Handle getter;
    /** How it's written, or {@code null} if it was found for reading only */
    private final Handle setter;

    InstanceField(String what, Class<?> type, Handle getter, Handle setter) {
        this.what = what;
        this.type = type;
        this.getter = getter;
        this.setter = setter;
    }

    /**
     * @return the field's declared type, or its stand-in in tests
     */
    public Class<?> type() {
        return type;
    }

    public Object get(Object target) {
        try {
            return (Object) getter.generic().invokeExact(target);
        } catch (Throwable e) {
            throw Handle.filter(e, RuntimeException.class, what);
        }
    }

    public boolean getBoolean(Object target) {
        try {
            return (boolean) getter.exact().invokeExact(target);
        } catch (Throwable e) {
            throw Handle.filter(e, RuntimeException.class, what);
        }
    }

    public int getInt(Object target) {
        try {
            return (int) getter.exact().invokeExact(target);
        } catch (Throwable e) {
            throw Handle.filter(e, RuntimeException.class, what);
        }
    }

    /**
     * @throws IllegalStateException if the field was found for reading only
     */
    public void set(Object target, Object value) {
        try {
            Object ignored = (Object) setter().generic().invokeExact(target, value);
        } catch (Throwable e) {
            throw Handle.filter(e, RuntimeException.class, what);
        }
    }

    /**
     * @throws IllegalStateException if the field was found for reading only
     */
    public void setBoolean(Object target, boolean value) {
        try {
            setter().exact().invokeExact(target, value);
        } catch (Throwable e) {
            throw Handle.filter(e, RuntimeException.class, what);
        }
    }

    /**
     * @throws IllegalStateException if the field was found for reading only
     */
    public void setInt(Object target, int value) {
        try {
            setter().exact().invokeExact(target, value);
        } catch (Throwable e) {
            throw Handle.filter(e, RuntimeException.class, what);
        }
    }

    private Handle setter() {
        if (setter == null) {
            throw new IllegalStateException(what + " was found for reading only");
        }
        return setter;
    }

    @Override
    public String toString() {
        return what;
    }
}
