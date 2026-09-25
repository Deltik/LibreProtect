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

package net.deltik.mc.libreprotect.extension.upstream.reflect.fake;

/**
 * A fake upstream class that only the test of initialization touches, so
 * that its static initializer shows whether probing ran it.
 */
public class Pristine {

    public static final int CONSTANT = 5;

    public static volatile boolean flag;
    protected static volatile boolean handshake;
    public int value;

    static {
        Initialized.CLASSES.add("Pristine");
    }

    public static String run(Kind kind) {
        return kind.name();
    }

    static synchronized void lock() {
    }

    /**
     * A nested enum, like CoreProtect's Consumer.OperationStartResult.
     */
    public enum Kind {
        ONE, TWO;

        static {
            Initialized.CLASSES.add("Pristine.Kind");
        }
    }
}
