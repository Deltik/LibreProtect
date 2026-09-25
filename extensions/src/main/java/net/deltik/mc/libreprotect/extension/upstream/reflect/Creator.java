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
 * An upstream constructor. Exceptions pass as they do for
 * {@link StaticMethod}, except that no checked exception is let through.
 */
public final class Creator {

    private final String what;
    private final Handle handle;

    Creator(String what, Handle handle) {
        this.what = what;
        this.handle = handle;
    }

    /**
     * @return a new instance of the upstream class
     */
    public Object create(Object... args) {
        try {
            return Handle.invoke(handle.generic(), args);
        } catch (Throwable e) {
            throw Handle.filter(e, RuntimeException.class, what);
        }
    }

    /**
     * @return the handle for hot paths, which takes exactly the parameter
     *         types asked for and returns an {@code Object}
     */
    public MethodHandle exact() {
        return handle.exact();
    }

    @Override
    public String toString() {
        return what;
    }
}
