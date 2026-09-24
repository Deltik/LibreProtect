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

package net.deltik.mc.libreprotect.routing.answer;

import net.deltik.mc.libreprotect.PrivacyConstants;
import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TranslationAnswerTest {

    // An empty answer would become an empty language cache, so there is no
    // answer at all until LibreProtect bundles translations.

    @Test
    @DisplayName("should fail, since no translations are bundled yet")
    void fails() {
        Request request = new Request(MockUrlFactory.translateUrl(), "POST",
            Map.of("Content-Type", "application/x-www-form-urlencoded; charset=utf-8"),
            "data={\"DATA_LANGUAGE\":\"de\"}".getBytes(StandardCharsets.UTF_8));

        IOException ex = assertThrows(IOException.class, () -> new TranslationAnswer().answer(request));
        assertTrue(ex.getMessage().contains(PrivacyConstants.FORK_NAME), ex.getMessage());
        assertTrue(ex.getMessage().contains("translations"), ex.getMessage());
    }
}
