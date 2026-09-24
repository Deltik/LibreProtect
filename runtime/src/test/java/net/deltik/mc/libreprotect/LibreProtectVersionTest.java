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

package net.deltik.mc.libreprotect;

import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

class LibreProtectVersionTest {

    @Test
    @DisplayName("should read build information from /libreprotect-build.properties")
    void resourceName() {
        assertEquals("/libreprotect-build.properties", LibreProtectVersion.RESOURCE);
    }

    @Test
    @DisplayName("should report unknown when the resource is absent")
    void unknownWithoutResource() {
        Assumptions.assumeTrue(LibreProtectVersion.class.getResource(LibreProtectVersion.RESOURCE) == null,
            "build information is on the test classpath");

        assertEquals("unknown", LibreProtectVersion.getForkVersion());
    }

    @Test
    @DisplayName("mock connections should advertise the LibreProtect version")
    void mockServerHeaderUsesForkVersion() {
        MockHttpURLConnection conn = new MockHttpURLConnection(MockUrlFactory.updateUrl());
        assertEquals(PrivacyConstants.FORK_NAME + "/" + LibreProtectVersion.getForkVersion(),
            conn.getHeaderField("Server"));
    }
}
