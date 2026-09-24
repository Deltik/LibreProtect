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

package net.deltik.mc.libreprotect.update;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class CheckUpdatesSettingTest {

    @TempDir
    Path tempDir;

    private CheckUpdatesSetting setting(String content) throws IOException {
        Path file = tempDir.resolve("config.yml");
        Files.writeString(file, content, StandardCharsets.UTF_8);
        return new CheckUpdatesSetting(file.toFile());
    }

    @ParameterizedTest
    @DisplayName("should read check-updates the way CoreProtect does")
    @CsvSource(delimiter = '|', value = {
        "check-updates: true                          | true",
        "check-updates: false                         | false",
        "'check-updates: ''true'''                    | true",
        "'check-updates: ''false'''                   | false",
        "check-updates: \"false\"                     | false",
        "check-updates: true # checked hourly         | true",
        "check-updates : false                        | false",
        "'  check-updates: false'                     | false",
        // CoreProtect's booleans are values that start with a lowercase t
        "check-updates: t                             | true",
        "check-updates: yes                           | false",
        "check-updates: True                          | false",
        "check-updates: 1                             | false",
        "'check-updates:'                             | false",
        // Other keys and comments don't count; the last line with the key does
        "'# check-updates: false'                     | true",
        "'Check-Updates: false'                       | true",
        "'check-updates-extra: false'                 | true",
        "'use-mysql: false\\ncheck-updates: false'    | false",
        "'check-updates: false\\ncheck-updates: true' | true",
        "'check-updates: true\\r\\ncheck-updates: false\\r\\n' | false",
        "'# comment\\ncheck-updates: false\\nverbose: true' | false",
        "''                                           | true"
    })
    void reads(String content, boolean expected) throws IOException {
        assertEquals(expected, setting(content.replace("\\n", "\n").replace("\\r", "\r")).isOn(), content);
    }

    @Test
    @DisplayName("should count a missing file as on, CoreProtect's default")
    void missingFile() throws IOException {
        assertTrue(new CheckUpdatesSetting(tempDir.resolve("missing.yml").toFile()).isOn());
    }

    @Test
    @DisplayName("should read past bytes that aren't UTF-8")
    void notUtf8() throws IOException {
        Path file = tempDir.resolve("config.yml");
        Files.write(file, new byte[] {'#', ' ', (byte) 0xFF, (byte) 0xFE, '\n', 'c', 'h', 'e', 'c', 'k', '-', 'u', 'p', 'd', 'a',
            't', 'e', 's', ':', ' ', 'f', 'a', 'l', 's', 'e', '\n'});

        assertFalse(new CheckUpdatesSetting(file.toFile()).isOn());
    }

    @Test
    @DisplayName("should fail when the file can't be read")
    void unreadable() throws IOException {
        File directory = Files.createDirectory(tempDir.resolve("config.yml")).toFile();

        assertThrows(IOException.class, () -> new CheckUpdatesSetting(directory).isOn());
    }

    @Test
    @DisplayName("should read the file again each time")
    void readsAgain() throws IOException {
        CheckUpdatesSetting setting = setting("check-updates: true\n");
        assertTrue(setting.isOn());

        Files.writeString(setting.file().toPath(), "check-updates: false\n");

        assertFalse(setting.isOn());
    }
}
