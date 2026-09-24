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

package net.deltik.mc.libreprotect.transformer;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SubclassGeneratorTest {

    private static List<String> calls(MethodNode method) {
        List<String> calls = new ArrayList<>();
        for (AbstractInsnNode instruction : method.instructions) {
            if (instruction instanceof MethodInsnNode call) {
                calls.add(call.getOpcode() + " " + call.owner + "." + call.name + call.desc);
            }
        }
        return calls;
    }

    private static MethodNode method(ClassNode node, String name, String descriptor) {
        return node.methods.stream()
            .filter(method -> method.name.equals(name) && method.desc.equals(descriptor))
            .findFirst().orElse(null);
    }

    @Test
    @DisplayName("generates a public subclass that calls the bootstrap hooks around the superclass")
    void generatesSubclass() {
        byte[] bytes = SubclassGenerator.generate("example/Main", Opcodes.V11);
        TestClasses.verify(bytes, false);

        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        assertEquals(Opcodes.V11, node.version);
        assertEquals(SubclassGenerator.CLASS_NAME, node.name);
        assertEquals("example/Main", node.superName);
        assertEquals(Opcodes.ACC_PUBLIC, node.access & Opcodes.ACC_PUBLIC);

        MethodNode constructor = method(node, "<init>", "()V");
        assertNotNull(constructor);
        assertEquals(List.of(
            Opcodes.INVOKESPECIAL + " example/Main.<init>()V",
            Opcodes.INVOKESTATIC + " net/deltik/mc/libreprotect/Bootstrap.init(Lorg/bukkit/plugin/java/JavaPlugin;)V"),
            calls(constructor));

        MethodNode onEnable = method(node, "onEnable", "()V");
        assertNotNull(onEnable);
        assertEquals(List.of(
            Opcodes.INVOKESPECIAL + " example/Main.onEnable()V",
            Opcodes.INVOKESTATIC + " net/deltik/mc/libreprotect/Bootstrap.enabled(Lorg/bukkit/plugin/java/JavaPlugin;)V"),
            calls(onEnable));
    }
}
