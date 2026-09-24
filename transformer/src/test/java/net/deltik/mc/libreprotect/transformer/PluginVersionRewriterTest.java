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

import net.deltik.mc.libreprotect.transformer.fixture.VersionFixture;
import org.bukkit.plugin.PluginDescriptionFile;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PluginVersionRewriterTest {

    private static Class<?> rewrite(String version, List<TransformReport.PluginVersionRead> reads) {
        ClassReader reader = new ClassReader(TestClasses.bytesOf(VersionFixture.class));
        ClassWriter writer = new ClassWriter(0);
        reader.accept(new PluginVersionRewriter(writer, "fixture.class", version, reads), 0);
        byte[] rewritten = writer.toByteArray();
        TestClasses.verify(rewritten, true);
        return TestClasses.define(VersionFixture.class.getName(), rewritten);
    }

    @Test
    @DisplayName("getPluginVersion reads upstream's version, and everything else still reads plugin.yml's")
    void rewritesPluginVersion() throws Exception {
        assertEquals("24.0", VersionFixture.getPluginVersion(), "precondition: LibreProtect's version, to the dash");

        List<TransformReport.PluginVersionRead> reads = new ArrayList<>();
        Class<?> type = rewrite("24.1", reads);

        assertEquals("24.1", type.getMethod("getPluginVersion").invoke(null));
        assertEquals("v24.0-121-gd5cad31-libre-dev", type.getMethod("shownVersion").invoke(null));
        Object instance = type.getConstructor().newInstance();
        assertEquals("9.9", type.getMethod("getPluginVersion", PluginDescriptionFile.class).invoke(instance,
            new PluginDescriptionFile("Other", "9.9", "other.Main")), "the instance overload must not be rewritten");
        assertEquals(List.of(new TransformReport.PluginVersionRead("fixture.class",
            VersionFixture.class.getName().replace('.', '/'), "getPluginVersion()Ljava/lang/String;", "24.1")), reads);
    }

    @Test
    @DisplayName("getPluginVersion still does with upstream's version what it did with plugin.yml's")
    void keepsWhatTheMethodDoes() throws Exception {
        Class<?> type = rewrite("24.1-local", new ArrayList<>());

        assertEquals("24.1", type.getMethod("getPluginVersion").invoke(null));
    }
}
