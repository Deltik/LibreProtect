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

import java.util.Arrays;
import java.util.List;

/**
 * What a parameter of an upstream method must look like, for methods whose
 * parameter types can't be named from LibreProtect's side, such as
 * CoreProtect's engine enum.
 */
public abstract class Shape {

    Shape() {
    }

    /**
     * @return a parameter of exactly this type
     */
    public static Shape exactly(Class<?> type) {
        return new Exactly(type);
    }

    /**
     * @return a parameter whose type is an enum with at least these constants
     */
    public static Shape enumWith(String... constants) {
        return new EnumWith(Arrays.asList(constants));
    }

    /**
     * @return a parameter of any class or interface type, for a method known
     *         by its other parameters, whose own type upstream may rename or
     *         move, such as a class of one database engine's
     */
    public static Shape anyObject() {
        return AnyObject.INSTANCE;
    }

    /**
     * @param descriptor the parameter's type descriptor
     * @throws Missing if the parameter's class can't be read, so whether it
     *                 matches can't be told
     */
    abstract boolean matches(Upstream upstream, ClassLoader loader, String descriptor) throws Missing;

    /**
     * @return the type that the method's exact handle takes for this parameter
     */
    abstract Class<?> handleType();

    private static final class Exactly extends Shape {
        private final Class<?> type;

        Exactly(Class<?> type) {
            this.type = type;
        }

        @Override
        boolean matches(Upstream upstream, ClassLoader loader, String descriptor) {
            return descriptor.equals(Descriptors.of(type));
        }

        @Override
        Class<?> handleType() {
            return type;
        }

        @Override
        public String toString() {
            return Descriptors.simpleName(type);
        }
    }

    private static final class EnumWith extends Shape {
        private final List<String> constants;

        EnumWith(List<String> constants) {
            this.constants = constants;
        }

        @Override
        boolean matches(Upstream upstream, ClassLoader loader, String descriptor) throws Missing {
            if (!descriptor.startsWith("L")) {
                return false;
            }
            String className = Descriptors.className(descriptor);
            ClassFile file = upstream.classFile(loader, className);
            if (file != null && !file.complete) {
                throw new Missing(upstream.name() + "'s class " + Descriptors.simpleName(className)
                    + " can't be read");
            }
            return file != null && file.isEnum() && file.enumConstants().containsAll(constants);
        }

        @Override
        Class<?> handleType() {
            return Object.class;
        }

        @Override
        public String toString() {
            return "an enum with " + String.join(", ", constants);
        }
    }

    private static final class AnyObject extends Shape {
        static final AnyObject INSTANCE = new AnyObject();

        @Override
        boolean matches(Upstream upstream, ClassLoader loader, String descriptor) {
            return descriptor.startsWith("L");
        }

        @Override
        Class<?> handleType() {
            return Object.class;
        }

        @Override
        public String toString() {
            return "any object";
        }
    }
}
