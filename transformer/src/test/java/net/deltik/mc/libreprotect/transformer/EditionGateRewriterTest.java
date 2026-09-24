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

import net.deltik.mc.libreprotect.transformer.fixture.GateFixture;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EditionGateRewriterTest {

    @Test
    @DisplayName("static gates return constants and other methods keep their behavior")
    void rewritesGates() throws Exception {
        assertFalse(GateFixture.validDonationKey(), "precondition: no key set");
        assertTrue(GateFixture.isCommunityEdition(), "precondition: community edition");

        List<TransformReport.EditionGate> gates = new ArrayList<>();
        ClassReader reader = new ClassReader(TestClasses.bytesOf(GateFixture.class));
        ClassWriter writer = new ClassWriter(0);
        reader.accept(new EditionGateRewriter(writer, "fixture.class", gates), 0);
        byte[] rewritten = writer.toByteArray();
        TestClasses.verify(rewritten, true);

        Class<?> type = TestClasses.define(GateFixture.class.getName(), rewritten);
        assertEquals(true, type.getMethod("validDonationKey").invoke(null));
        assertEquals(false, type.getMethod("isCommunityEdition").invoke(null));

        Object instance = type.getConstructor().newInstance();
        assertEquals(false, type.getMethod("validDonationKey", String.class).invoke(instance, (Object) null),
            "the instance overload must not be rewritten");

        assertEquals(2, gates.size());
        assertTrue(gates.contains(new TransformReport.EditionGate("fixture.class",
            GateFixture.class.getName().replace('.', '/'), "validDonationKey()Z", true)));
        assertTrue(gates.contains(new TransformReport.EditionGate("fixture.class",
            GateFixture.class.getName().replace('.', '/'), "isCommunityEdition()Z", false)));
    }
}
