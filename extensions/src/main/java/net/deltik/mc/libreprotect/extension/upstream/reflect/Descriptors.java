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
import java.util.List;

/**
 * JVM type descriptors, such as {@code (J)Z}, and their readable forms,
 * such as {@code (long)}, for the report and for messages.
 */
final class Descriptors {

    private Descriptors() {
    }

    /**
     * @return the descriptor of a type, such as {@code Z} or {@code Ljava/lang/String;}
     */
    static String of(Class<?> type) {
        return MethodType.methodType(type).toMethodDescriptorString().substring(2);
    }

    static String method(Class<?> returns, List<Class<?>> parameters) {
        return MethodType.methodType(returns, parameters).toMethodDescriptorString();
    }

    /**
     * @return the descriptors of a method descriptor's parameters
     */
    static List<String> parameters(String methodDescriptor) {
        List<String> parameters = new ArrayList<>();
        int i = 1;
        while (methodDescriptor.charAt(i) != ')') {
            int end = typeEnd(methodDescriptor, i);
            parameters.add(methodDescriptor.substring(i, end));
            i = end;
        }
        return parameters;
    }

    static String returnType(String methodDescriptor) {
        return methodDescriptor.substring(methodDescriptor.indexOf(')') + 1);
    }

    private static int typeEnd(String descriptor, int start) {
        int i = start;
        while (descriptor.charAt(i) == '[') {
            i++;
        }
        return descriptor.charAt(i) == 'L' ? descriptor.indexOf(';', i) + 1 : i + 1;
    }

    /**
     * @return the binary name of the class a type descriptor names, of an
     *         array's elements for an array, or {@code null} for a primitive
     */
    static String className(String typeDescriptor) {
        String element = typeDescriptor.replace("[", "");
        return element.startsWith("L") ? element.substring(1, element.length() - 1).replace('/', '.') : null;
    }

    /**
     * @return the binary names of the classes a field or method descriptor names
     */
    static List<String> classNames(String descriptor) {
        List<String> names = new ArrayList<>();
        List<String> types = new ArrayList<>();
        if (descriptor.startsWith("(")) {
            types.addAll(parameters(descriptor));
            types.add(returnType(descriptor));
        } else {
            types.add(descriptor);
        }
        for (String type : types) {
            String name = className(type);
            if (name != null) {
                names.add(name);
            }
        }
        return names;
    }

    static boolean isReference(String typeDescriptor) {
        return typeDescriptor.startsWith("L") || typeDescriptor.startsWith("[");
    }

    /**
     * @return a class name without its package, with nested classes joined
     *         by dots, such as {@code Consumer.OperationStartResult}
     */
    static String simpleName(String binaryName) {
        String name = binaryName.replace('/', '.');
        return name.substring(name.lastIndexOf('.') + 1).replace('$', '.');
    }

    static String simpleName(Class<?> type) {
        return type.isArray() ? simpleName(type.getComponentType()) + "[]" : type.isPrimitive() ? type.getName()
            : simpleName(type.getName());
    }

    /**
     * @return a type descriptor as Java would write it, such as {@code byte[]}
     */
    static String readableType(String typeDescriptor) {
        int dimensions = 0;
        while (typeDescriptor.charAt(dimensions) == '[') {
            dimensions++;
        }
        String element;
        switch (typeDescriptor.charAt(dimensions)) {
            case 'Z':
                element = "boolean";
                break;
            case 'B':
                element = "byte";
                break;
            case 'C':
                element = "char";
                break;
            case 'S':
                element = "short";
                break;
            case 'I':
                element = "int";
                break;
            case 'J':
                element = "long";
                break;
            case 'F':
                element = "float";
                break;
            case 'D':
                element = "double";
                break;
            case 'V':
                element = "void";
                break;
            default:
                element = simpleName(className(typeDescriptor));
                break;
        }
        StringBuilder readable = new StringBuilder(element);
        for (int i = 0; i < dimensions; i++) {
            readable.append("[]");
        }
        return readable.toString();
    }

    /**
     * @return a method descriptor's parameters as Java would write them, such as {@code (String, long)}
     */
    static String readableParameters(String methodDescriptor) {
        List<String> readable = new ArrayList<>();
        for (String parameter : parameters(methodDescriptor)) {
            readable.add(readableType(parameter));
        }
        return "(" + String.join(", ", readable) + ")";
    }

    /**
     * @return a class name in the JVM's internal form, such as {@code net/coreprotect/consumer/Consumer}
     */
    static String internalName(String binaryName) {
        return binaryName.replace('.', '/');
    }

    /**
     * @return a class name with dots, however it was written
     */
    static String binaryName(String name) {
        return name.replace('/', '.');
    }
}
