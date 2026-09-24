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

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PluginYmlTest {

    /** The top of CoreProtect v24.1's plugin.yml, after Maven resource filtering */
    static final String UPSTREAM = """
        name: CoreProtect
        main: net.coreprotect.CoreProtect
        version: 24.1
        branch: libre
        api-version: 1.16
        folia-supported: true
        website: http://coreprotect.net
        author: Intelli
        softdepend: [WorldEdit]
        description: >
                     Provides block protection for your server.
        commands:
          co:
            description: Utilize the plugin
            permission: coreprotect.co
        permissions:
            coreprotect.*:
                description: Gives access to all CoreProtect actions and commands
                default: op
        """;

    private static Map<String, String> changes() {
        Map<String, String> changes = new LinkedHashMap<>();
        changes.put("main", "net.deltik.mc.libreprotect.LibreProtectPlugin");
        changes.put("version", "24.1-libre1");
        changes.put("description", "Privacy-hardened build of CoreProtect");
        changes.put("website", "https://github.com/Deltik/LibreProtect");
        return changes;
    }

    @Test
    @DisplayName("replaces only the requested keys, including a folded block scalar")
    void replacesKeys() {
        PluginYml edited = new PluginYml(UPSTREAM).with(changes());

        assertEquals("net.deltik.mc.libreprotect.LibreProtectPlugin", edited.getString("main"));
        assertEquals("24.1-libre1", edited.getString("version"));
        assertEquals("Privacy-hardened build of CoreProtect", edited.getString("description"));
        assertEquals("https://github.com/Deltik/LibreProtect", edited.getString("website"));
        assertEquals("CoreProtect", edited.getString("name"));
        assertEquals("libre", edited.getString("branch"));
        assertEquals("Intelli", edited.getString("author"));
        assertTrue(edited.get("commands") instanceof Map);
        assertFalse(edited.text().contains("Provides block protection"), edited.text());
        assertTrue(edited.text().contains("  co:\n    description: Utilize the plugin\n"), "layout kept");
    }

    @Test
    @DisplayName("appends a key that upstream doesn't set")
    void appendsMissingKey() {
        String withoutWebsite = UPSTREAM.replace("website: http://coreprotect.net\n", "");
        PluginYml edited = new PluginYml(withoutWebsite).with(changes());
        assertEquals("https://github.com/Deltik/LibreProtect", edited.getString("website"));
        assertEquals("CoreProtect", edited.getString("name"));
    }

    @Test
    @DisplayName("keeps CRLF line endings")
    void keepsCrlf() {
        PluginYml edited = new PluginYml(UPSTREAM.replace("\n", "\r\n")).with(changes());
        assertEquals("24.1-libre1", edited.getString("version"));
        assertFalse(edited.text().replace("\r\n", "").contains("\n"));
    }

    @Test
    @DisplayName("handles a literal block scalar with a blank line inside")
    void literalBlockWithBlankLine() {
        String text = "name: CoreProtect\ndescription: |\n  first\n\n  second\nauthor: Intelli\n";
        PluginYml edited = new PluginYml(text).with(Map.of("description", "one line"));
        assertEquals("one line", edited.getString("description"));
        assertEquals("Intelli", edited.getString("author"));
    }

    @Test
    @DisplayName("quotes values that YAML would otherwise misread")
    void quotesValues() {
        PluginYml edited = new PluginYml(UPSTREAM).with(Map.of("description", "a: \"b\" # c"));
        assertEquals("a: \"b\" # c", edited.getString("description"));
    }
}
