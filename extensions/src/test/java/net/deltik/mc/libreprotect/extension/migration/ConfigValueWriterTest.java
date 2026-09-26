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

package net.deltik.mc.libreprotect.extension.migration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class ConfigValueWriterTest {

    @TempDir
    Path folder;

    private static String update(String content) {
        return new String(ConfigValueWriter.update(content.getBytes(StandardCharsets.UTF_8), "use-mysql", "true"),
            StandardCharsets.UTF_8);
    }

    @Nested
    @DisplayName("changing the line")
    class Lines {

        @ParameterizedTest(name = "{0}")
        @CsvSource(delimiter = '|', quoteCharacter = '`', ignoreLeadingAndTrailingWhitespace = false, value = {
            "use-mysql: false|use-mysql: true",
            "use-mysql:false|use-mysql: true",
            "use-mysql:    false|use-mysql:    true",
            "use-mysql: 'false'|use-mysql: 'true'",
            "use-mysql: \"false\"|use-mysql: \"true\"",
            "use-mysql: false # set to true for MySQL|use-mysql: true # set to true for MySQL",
            "use-mysql: false\t# comment|use-mysql: true\t# comment",
            "use-mysql: # nothing yet|use-mysql: true # nothing yet",
            "  use-mysql: false|  use-mysql: true",
            "use-mysql : false|use-mysql : true",
            "use-mysql: false#no space|use-mysql: true",
            "use-mysql: \"a # b\"|use-mysql: \"true\"",
        })
        @DisplayName("should replace only the value")
        void replaces(String before, String after) {
            assertEquals("# CoreProtect Config\n" + after + "\ntable-prefix: co_\n",
                update("# CoreProtect Config\n" + before + "\ntable-prefix: co_\n"));
        }

        @Test
        @DisplayName("should keep comments, other settings, CRLF line endings and every other byte")
        void keepsEverythingElse() {
            String content = "# use-mysql: false\r\n# If true, uses MySQL\r\nuse-mysql: false\r\n\r\n"
                + "mysql-host: 127.0.0.1\r\nlanguage: de # Sprache\r\nno-final-newline: x";

            assertEquals(content.replace("use-mysql: false\r\n\r\n", "use-mysql: true\r\n\r\n"), update(content));
        }

        @Test
        @DisplayName("should keep bytes that aren't valid UTF-8")
        void keepsInvalidBytes() {
            byte[] content = {'#', ' ', (byte) 0xE9, '\n', 'u', 's', 'e', '-', 'm', 'y', 's', 'q', 'l', ':', ' ',
                'f', 'a', 'l', 's', 'e', '\n'};

            byte[] updated = ConfigValueWriter.update(content, "use-mysql", "true");

            assertEquals((byte) 0xE9, updated[2]);
            assertTrue(new String(updated, StandardCharsets.ISO_8859_1).endsWith("use-mysql: true\n"));
        }

        @Test
        @DisplayName("should change every line that sets the key, since CoreProtect reads the last one")
        void everyOccurrence() {
            assertEquals("use-mysql: true\nx: y\nuse-mysql: true\n", update("use-mysql: false\nx: y\nuse-mysql: false\n"));
        }

        @Test
        @DisplayName("should leave lines alone that CoreProtect doesn't read as the key")
        void otherKeys() {
            String content = "#use-mysql: false\n  # use-mysql: false\nuse-mysql-extra: false\nmy-use-mysql: false\n"
                + "use-mysql: true\n";

            assertEquals(content, update(content));
        }

        @Test
        @DisplayName("should append the setting when the file lacks it, as CoreProtect does for missing settings")
        void appends() {
            assertEquals("language: en\nuse-mysql: true\n", update("language: en\n"));
            assertEquals("language: en\r\nuse-mysql: true\r\n", update("language: en\r\n"));
            assertEquals("language: en\nuse-mysql: true\n", update("language: en"));
            assertEquals("use-mysql: true\n", update(""));
        }
    }

    @Nested
    @DisplayName("replacing the file")
    class Replacing {

        @Test
        @DisplayName("should replace the file atomically, keep its permissions, and leave no temporary file")
        void replaces() throws IOException {
            Path config = folder.resolve("config.yml");
            Files.writeString(config, "use-mysql: false\nmysql-password: secret\n");
            Set<PosixFilePermission> permissions = PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(config, permissions);

            assertTrue(ConfigValueWriter.set(config, "use-mysql", "true"));

            assertEquals("use-mysql: true\nmysql-password: secret\n", Files.readString(config));
            assertEquals(permissions, Files.getPosixFilePermissions(config));
            try (Stream<Path> files = Files.list(folder)) {
                assertEquals(1, files.count());
            }
        }

        @Test
        @DisplayName("should not write a file that already has the value")
        void unchanged() throws IOException {
            Path config = folder.resolve("config.yml");
            Files.writeString(config, "use-mysql: true\n");
            Files.setLastModifiedTime(config, java.nio.file.attribute.FileTime.fromMillis(0));

            assertFalse(ConfigValueWriter.set(config, "use-mysql", "true"));

            assertEquals(0, Files.getLastModifiedTime(config).toMillis());
        }

        @Test
        @DisplayName("should refuse a symbolic link, like CoreProtect 25's writer, and leave it as it was")
        void symbolicLink() throws IOException {
            Path real = folder.resolve("real.yml");
            Files.writeString(real, "use-mysql: false\n");
            Path link = Files.createSymbolicLink(folder.resolve("config.yml"), real);

            assertThrows(IOException.class, () -> ConfigValueWriter.set(link, "use-mysql", "true"));

            assertTrue(Files.isSymbolicLink(link));
            assertEquals("use-mysql: false\n", Files.readString(real));
        }

        @Test
        @DisplayName("should confirm beforehand that it can replace the file, without changing anything")
        void checkReplaceable() throws IOException {
            Path config = folder.resolve("config.yml");
            Files.writeString(config, "use-mysql: false\n");
            Files.setLastModifiedTime(config, java.nio.file.attribute.FileTime.fromMillis(0));

            ConfigValueWriter.checkReplaceable(config, false);
            ConfigValueWriter.checkReplaceable(config, true);

            assertEquals("use-mysql: false\n", Files.readString(config));
            assertEquals(0, Files.getLastModifiedTime(config).toMillis());
            try (Stream<Path> files = Files.list(folder)) {
                assertEquals(1, files.count(), "a temporary file was left");
            }
        }

        @Test
        @DisplayName("should say beforehand that it can't replace a symbolic link, or a file in a locked directory")
        void checkNotReplaceable() throws IOException {
            Path real = folder.resolve("real.yml");
            Files.writeString(real, "use-mysql: false\n");
            Path link = Files.createSymbolicLink(folder.resolve("config.yml"), real);
            assertThrows(IOException.class, () -> ConfigValueWriter.checkReplaceable(link, false));
            assertThrows(IOException.class, () -> ConfigValueWriter.checkReplaceable(folder.resolve("missing.yml"), false));

            Path directory = Files.createDirectory(folder.resolve("locked"));
            Path config = directory.resolve("config.yml");
            Files.writeString(config, "use-mysql: false\n");
            Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("r-x------"));
            try {
                assertThrows(IOException.class, () -> ConfigValueWriter.checkReplaceable(config, false));
            } finally {
                Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
            }
        }

        @Test
        @DisplayName("should fail without changing anything when the directory isn't writable")
        void readOnlyDirectory() throws IOException {
            Path directory = Files.createDirectory(folder.resolve("locked"));
            Path config = directory.resolve("config.yml");
            Files.writeString(config, "use-mysql: false\n");
            Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("r-x------"));
            try {
                assertThrows(IOException.class, () -> ConfigValueWriter.set(config, "use-mysql", "true"));
                assertEquals("use-mysql: false\n", Files.readString(config));
            } finally {
                Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
            }
        }
    }
}
