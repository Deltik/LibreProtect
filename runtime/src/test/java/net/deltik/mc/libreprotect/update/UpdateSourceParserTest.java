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

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.bukkit.configuration.InvalidConfigurationException;
import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import static org.junit.jupiter.api.Assertions.*;

class UpdateSourceParserTest {

    private final UpdateSourceParser parser = new UpdateSourceParser();
    private TestLogger testLogger;

    @BeforeEach
    void setUp() {
        LibreProtectLogger.reset();
        testLogger = new TestLogger();
        LibreProtectLogger.initialize(testLogger);
    }

    @AfterEach
    void tearDown() {
        LibreProtectLogger.reset();
    }

    /** Parse update-sources the way libreprotect.yml gives them, from YAML */
    private List<UpdateSource> parseYaml(String... lines) throws InvalidConfigurationException {
        YamlConfiguration yaml = new YamlConfiguration();
        yaml.loadFromString("update-sources:\n" + String.join("\n", lines) + "\n");
        return parser.parse(yaml.getList("update-sources"));
    }

    private static Map<String, Object> source(Object... keysAndValues) {
        Map<String, Object> source = new HashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            source.put((String) keysAndValues[i], keysAndValues[i + 1]);
        }
        return source;
    }

    @Nested
    @DisplayName("Valid sources")
    class Valid {

        @Test
        @DisplayName("should parse both types in order, with the default APIs")
        void bothTypes() throws InvalidConfigurationException {
            List<UpdateSource> sources = parseYaml(
                "  - type: github",
                "    repository: Deltik/LibreProtect",
                "  - type: modrinth",
                "    project: libreprotect");

            assertEquals(List.of(new GitHubSource("Deltik/LibreProtect", "https://api.github.com"),
                new ModrinthSource("libreprotect", "https://api.modrinth.com/v2")), sources);
            assertTrue(testLogger.getRecords().isEmpty());
        }

        @Test
        @DisplayName("should accept the type in any case and values with surrounding space")
        void caseAndSpace() {
            List<UpdateSource> sources = parser.parse(List.of(
                source("type", " GitHub ", "repository", " Deltik/LibreProtect "),
                source("type", "MODRINTH", "project", "TGIIS09S")));

            assertEquals(List.of(new GitHubSource("Deltik/LibreProtect", "https://api.github.com"),
                new ModrinthSource("TGIIS09S", "https://api.modrinth.com/v2")), sources);
        }

        @ParameterizedTest
        @DisplayName("should accept an http or https API and drop its final slashes")
        @CsvSource({
            "https://api.modrinth.com/v2, https://api.modrinth.com/v2",
            "https://api.modrinth.com/v2/, https://api.modrinth.com/v2",
            "http://127.0.0.1:8080/v2//, http://127.0.0.1:8080/v2",
            "HTTPS://Mirror.Example, HTTPS://Mirror.Example",
            "http://[::1]:8080, http://[::1]:8080"
        })
        void api(String api, String expected) {
            List<UpdateSource> sources = parser.parse(List.of(source("type", "modrinth", "project", "x", "api", api)));

            assertEquals(1, sources.size());
            assertEquals(expected, sources.get(0).api());
            assertTrue(testLogger.getRecords().isEmpty());
        }

        @Test
        @DisplayName("should ignore settings it doesn't know")
        void ignoresUnknownSettings() {
            assertEquals(1, parser.parse(List.of(source("type", "modrinth", "project", "x", "repository", "a/b"))).size());
        }

        @Test
        @DisplayName("should read a numeric project as text")
        void numericProject() {
            assertEquals("12345", ((ModrinthSource) parser.parse(List.of(source("type", "modrinth", "project", 12345)))
                .get(0)).project());
        }
    }

    @Nested
    @DisplayName("Lists")
    class Lists {

        @Test
        @DisplayName("should give no sources for an empty list")
        void empty() {
            assertEquals(List.of(), parser.parse(List.of()));
            assertTrue(testLogger.getRecords().isEmpty());
        }

        @Test
        @DisplayName("should give no sources for null")
        void nullList() {
            assertEquals(List.of(), parser.parse(null));
        }

        @Test
        @DisplayName("should return a list the caller can keep")
        void modifiable() {
            List<UpdateSource> sources = parser.parse(List.of(source("type", "modrinth", "project", "x")));
            sources.add(new ModrinthSource("y", ModrinthSource.DEFAULT_API));
            assertEquals(2, sources.size());
        }
    }

    @Nested
    @DisplayName("Invalid sources")
    class Invalid {

        private void assertSkipped(Object item, String reason) {
            List<Object> items = new ArrayList<>(Arrays.asList(source("type", "modrinth", "project", "first"), item,
                source("type", "github", "repository", "last/one")));

            List<UpdateSource> sources = parser.parse(items);

            assertEquals(List.of("Modrinth project first", "GitHub repository last/one"),
                sources.stream().map(UpdateSource::describe).toList());
            assertTrue(testLogger.hasMessageContaining(Level.WARNING, "Skipping update source #2 in libreprotect.yml: "
                + reason),
                testLogger.getMessages().toString());
            assertEquals(1, testLogger.countAtLevel(Level.WARNING));
        }

        @ParameterizedTest
        @DisplayName("should skip an item that isn't a map")
        @ValueSource(strings = {"modrinth", "type: modrinth"})
        void notAMap(String item) {
            assertSkipped(item, "it isn't a map with a type and its settings");
        }

        @Test
        @DisplayName("should skip a null item")
        void nullItem() {
            assertSkipped(null, "it isn't a map with a type and its settings");
        }

        @Test
        @DisplayName("should skip an item without a type")
        void noType() {
            assertSkipped(source("project", "libreprotect"), "it has no 'type'");
            testLogger.clear();
            assertSkipped(source("type", " ", "project", "libreprotect"), "it has no 'type'");
        }

        @Test
        @DisplayName("should skip an unknown type")
        void unknownType() {
            assertSkipped(source("type", "GitLab", "project", "x"), "its type 'gitlab' isn't modrinth or github");
        }

        @Test
        @DisplayName("should skip Modrinth without a project")
        void noProject() {
            assertSkipped(source("type", "modrinth"), "it has no 'project'");
            testLogger.clear();
            assertSkipped(source("type", "modrinth", "project", ""), "it has no 'project'");
        }

        @ParameterizedTest
        @DisplayName("should skip a Modrinth project that isn't an ID or slug")
        @ValueSource(strings = {"lib/re", "..", ".hidden", "-x", "a b", "a?b=c", "a#b", "§cred",
            "x12345678901234567890123456789012345678901234567890123456789012345", "lib%2Fre"})
        void badProject(String project) {
            assertSkipped(source("type", "modrinth", "project", project),
                "its project '" + project + "' isn't a Modrinth project ID or slug");
        }

        @Test
        @DisplayName("should skip GitHub without a repository")
        void noRepository() {
            assertSkipped(source("type", "github", "project", "LibreProtect"), "it has no 'repository'");
        }

        @ParameterizedTest
        @DisplayName("should skip a GitHub repository that isn't shaped owner/name")
        @ValueSource(strings = {"LibreProtect", "Deltik/", "/LibreProtect", "Deltik/LibreProtect/extra", "Deltik/..",
            "Deltik/.", "-Deltik/LibreProtect", "Del tik/LibreProtect", "Deltik/Libre?Protect", "Deltik\\LibreProtect",
            "https://github.com/Deltik/LibreProtect"})
        void badRepository(String repository) {
            assertSkipped(source("type", "github", "repository", repository),
                "its repository '" + repository + "' isn't shaped owner/name");
        }

        @ParameterizedTest
        @DisplayName("should skip an API that isn't an http or https URL")
        @ValueSource(strings = {"ftp://mirror.example", "file:///etc/passwd", "api.modrinth.com/v2", "https://",
            "https://user:secret@mirror.example", "https://mirror.example/v2?key=x", "https://mirror.example/#x",
            "https://mirror example", "", "mailto:x@example.com", "jar:https://x!/"})
        void badApi(String api) {
            assertSkipped(source("type", "modrinth", "project", "x", "api", api),
                "its api '" + api + "' isn't an http or https URL");
        }
    }
}
