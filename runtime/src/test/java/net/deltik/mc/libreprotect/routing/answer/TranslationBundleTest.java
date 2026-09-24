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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TranslationBundleTest {

    /**
     * @param files the bundle's files by name, such as {@code de.yml}
     * @return a bundle of the files that records the names it is asked to open
     */
    static TranslationBundle bundle(Map<String, String> files, List<String> opened) {
        return new TranslationBundle(name -> {
            opened.add(name);
            String content = files.get(name);
            return content == null ? null : new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
        });
    }

    static TranslationBundle bundle(String... codes) {
        Map<String, String> files = new LinkedHashMap<>();
        for (String code : codes) {
            files.put(code + ".yml", "# CoreProtect Language File (" + code + ")\n\nHELP_HEADER: \"" + code + "\"\n");
        }
        return bundle(files, new ArrayList<>());
    }

    /**
     * @return the phrases as {@value TranslationBundle#DEFAULTS} holds them
     */
    static String properties(Map<String, String> phrases) {
        Properties properties = new Properties();
        properties.putAll(phrases);
        StringWriter text = new StringWriter();
        try {
            properties.store(text, null);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return text.toString();
    }

    private static Map<String, String> parse(String text) throws IOException {
        return TranslationBundle.parse(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)));
    }

    @Nested
    @DisplayName("parse()")
    class Parse {

        @Test
        @DisplayName("should read upstream's format: a header comment, then quoted phrases")
        void upstreamFormat() throws IOException {
            Map<String, String> phrases = parse(String.join("\n",
                "# CoreProtect Language File (de)",
                "",
                "HELP_HEADER: \"{0} Hilfe\"",
                "COMMAND_NOT_FOUND: \"Befehl \\\"{0}\\\" nicht gefunden.\"",
                "HELP_INSPECT_7: \"Tipp: Benutze \\\"/co i\\\" für schnelleren Zugriff\""));

            assertEquals(Map.of(
                "HELP_HEADER", "{0} Hilfe",
                "COMMAND_NOT_FOUND", "Befehl \"{0}\" nicht gefunden.",
                "HELP_INSPECT_7", "Tipp: Benutze \"/co i\" für schnelleren Zugriff"), phrases);
        }

        @ParameterizedTest(name = "{0}")
        @CsvSource(delimiter = '|', quoteCharacter = '`', value = {
            "double quotes with escapes      | KEY: \"a \\\"b\\\" c\\\\d\"   | a \"b\" c\\d",
            "single quotes with escapes      | KEY: 'it''s \\'x\\' \\\\'     | it's 'x' \\",
            "no quotes                       | KEY: plain text                 | plain text",
            "a lone quote is kept            | KEY: \"                         | \"",
            "unmatched quotes are kept       | KEY: \"text'                    | \"text'",
            "split at the first colon        | KEY: \"a: b\"                   | a: b",
            "surrounding spaces are trimmed  | `  KEY  :   \"x\"   `           | x",
            "spaces inside quotes are kept   | KEY: \"  x  \"                  | `  x  `",
            "empty quotes                    | KEY: \"\"                       | ``",
            "no value                        | KEY:                            | ``",
        })
        @DisplayName("should unquote values like CoreProtect's ConfigFile.load")
        void values(String description, String line, String expected) throws IOException {
            assertEquals(Map.of("KEY", expected), parse(line + "\n"));
        }

        @Test
        @DisplayName("should uppercase names and skip comments and lines without a colon")
        void namesAndComments() throws IOException {
            Map<String, String> phrases = parse("# HEADER: comment\nhelp_header: \"x\"\nno colon here\r\n"
                + "Enable_Success: \"y\"\r\n");
            assertEquals(Map.of("HELP_HEADER", "x", "ENABLE_SUCCESS", "y"), phrases);
        }

        @Test
        @DisplayName("should keep the last value of a repeated name")
        void repeatedName() throws IOException {
            assertEquals(Map.of("KEY", "second"), parse("KEY: \"first\"\nKEY: \"second\"\n"));
        }
    }

    @Nested
    @DisplayName("resolve()")
    class Resolve {

        private final TranslationBundle bundle = bundle("de", "en", "ja", "zh-cn", "zh-tw", "he", "vi", "it");

        @ParameterizedTest(name = "{0} -> {1}")
        @CsvSource({
            "de, de",
            "zh-tw, zh-tw",
            "DE, de",
            "' de ', de",
            "De_AT-x-y, de",
            // "VI" and "IT" as CoreProtect lowercases them on a Turkish system
            "vı, vi",
            "ıt, it",
            "zh_CN, zh-cn",
            "ZH_TW, zh-tw",
            "zh, zh-cn",
            "zh-hans, zh-cn",
            "zh-sg, zh-cn",
            "zh-hant, zh-tw",
            "zh-hk, zh-tw",
            "zh-mo, zh-tw",
            "zh-hant-tw, zh-tw",
            "zh-hans-cn, zh-cn",
            "iw, he",
            "de-at, de",
            "de_CH, de",
            "ja-jp, ja",
        })
        @DisplayName("should find the bundled language by code, alias or base language")
        void finds(String language, String expected) throws IOException {
            assertEquals(expected, bundle.resolve(language));
        }

        @ParameterizedTest(name = "\"{0}\"")
        @ValueSource(strings = {"nl", "pt-br", "english", "", " ", "-", "de-", "../en", "de/../en", "de.yml", "d e",
            "zh-cn-x-y-z-w-v", "abcdefghi"})
        @DisplayName("should find nothing for other codes, including anything that isn't a plain code")
        void findsNothing(String language) throws IOException {
            assertNull(bundle.resolve(language));
        }

        @Test
        @DisplayName("should find nothing for no code")
        void nullCode() throws IOException {
            assertNull(bundle.resolve(null));
        }

        @Test
        @DisplayName("should prefer a bundled file over an alias of the same name")
        void fileBeforeAlias() throws IOException {
            assertEquals("zh", bundle("zh", "zh-cn").resolve("zh"));
        }

        @Test
        @DisplayName("should open only plain file names")
        void opensPlainNames() throws IOException {
            List<String> opened = new ArrayList<>();
            TranslationBundle recording = bundle(Map.of(), opened);
            recording.resolve("zh-hant-tw");
            recording.resolve("../../plugin");
            assertEquals(List.of("zh-hant-tw.yml", "zh-hant.yml", "zh-tw.yml", "zh.yml", "zh-cn.yml"), opened);
        }

        @Test
        @DisplayName("should never open a name outside its directory, whatever the code")
        void hostileCodes() throws IOException {
            List<String> opened = new ArrayList<>();
            TranslationBundle recording = bundle(Map.of("de.yml", "HELP_HEADER: x\n"), opened);
            for (String code : List.of("../en", "..", "de/../../x", "de\u0000", "de.yml", "/de", "de\\..", "DE-\u0130",
                "de%2f..", "de-" + "a".repeat(9), "a-b-c-d-e-f-g", " ", "")) {
                recording.resolve(code);
            }
            assertEquals(List.of("de.yml"), opened.stream().distinct().toList());
            for (String name : opened) {
                assertFalse(name.contains("/") || name.contains("\\") || name.contains("..") || name.contains("\u0000"),
                    name);
            }
        }
    }

    @Nested
    @DisplayName("defaults()")
    class Defaults {

        @Test
        @DisplayName("should read CoreProtect's built-in English exactly, once")
        void readsExactly() throws IOException {
            Map<String, String> phrases = Map.of(
                "HELP_HEADER", " {0} \"Help\" \\ C:\\path\n\ttab ü ☃ 😀 # = : !",
                "EMPTY", "");
            List<String> opened = new ArrayList<>();
            TranslationBundle bundle = bundle(Map.of(TranslationBundle.DEFAULTS, properties(phrases)), opened);

            assertEquals(phrases, bundle.defaults());
            assertEquals(phrases, bundle.defaults());
            assertEquals(List.of(TranslationBundle.DEFAULTS), opened);
            assertThrows(UnsupportedOperationException.class, () -> bundle.defaults().put("X", "y"));
        }

        @Test
        @DisplayName("should give nothing when it isn't bundled")
        void missing() throws IOException {
            assertNull(bundle("de").defaults());
        }
    }

    @Nested
    @DisplayName("phrases()")
    class Phrases {

        @Test
        @DisplayName("should read each file once, and remember files that don't exist")
        void readsOnce() throws IOException {
            List<String> opened = new ArrayList<>();
            TranslationBundle bundle = bundle(Map.of("de.yml", "HELP_HEADER: \"{0} Hilfe\"\n"), opened);

            assertEquals(Map.of("HELP_HEADER", "{0} Hilfe"), bundle.phrases("de"));
            assertEquals(Map.of("HELP_HEADER", "{0} Hilfe"), bundle.phrases("de"));
            assertNull(bundle.phrases("nl"));
            assertNull(bundle.phrases("nl"));
            assertEquals(List.of("de.yml", "nl.yml"), opened);
        }

        @Test
        @DisplayName("should pass on read errors, and try again next time")
        void readError() {
            List<String> opened = new ArrayList<>();
            TranslationBundle bundle = new TranslationBundle(name -> {
                opened.add(name);
                throw new IOException("disk on fire");
            });

            assertThrows(IOException.class, () -> bundle.phrases("de"));
            assertThrows(IOException.class, () -> bundle.phrases("de"));
            assertEquals(2, opened.size());
        }

        @Test
        @DisplayName("should give an unmodifiable map")
        void unmodifiable() throws IOException {
            Map<String, String> phrases = bundle("de").phrases("de");
            assertThrows(UnsupportedOperationException.class, () -> phrases.put("X", "y"));
        }
    }
}
