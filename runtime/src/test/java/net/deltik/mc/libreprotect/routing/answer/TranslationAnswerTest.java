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

/*
 * Portions of this file are copied or adapted from CoreProtect
 * <https://github.com/PlayPro/CoreProtect>:
 *
 * Copyright (c) Intelli and the CoreProtect contributors
 *
 * CoreProtect is licensed under the Artistic License 2.0 (see
 * LICENSES/Artistic-2.0.txt). As section 4(c)(ii) of that license
 * permits, LibreProtect distributes these portions under the
 * GNU General Public License, version 3 or later. See NOTICE.
 */

package net.deltik.mc.libreprotect.routing.answer;

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.LibreProtectVersion;
import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Level;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TranslationAnswerTest {

    /** Shaped like upstream's lang/en.yml, with the kinds of text that need care */
    static final String ENGLISH = """
        # CoreProtect Language File (en)

        BLANK: "Blank in German"
        COMMAND_NOT_FOUND: "Command \\"{0}\\" not found."
        HELP_ACTION_2: "Examples: [a:+block], [a:-block]"
        HELP_FILTER_2: "Examples: [a:sign f:Shop]"
        HELP_HEADER: "{0} Help"
        HELP_INSPECT_7: "Tip: You can use just \\"/co i\\" for quicker access."
        HELP_STATUS_COMMAND: "Displays the plugin status."
        STATUS_AUTO_PURGE: "Auto-purge: {0}"
        UNICODE: "Déjà vu… 50% ≈ done \\\\ ok\u2028"
        WORLD_NOT_FOUND: "World \\"{0}\\" not found."
        """;

    /**
     * CoreProtect's built-in English: {@link #ENGLISH}, except for
     * HELP_FILTER_2, where en.yml fell behind the code, as on upstream's
     * master
     */
    static final Map<String, String> BUILT_IN = builtIn();

    static final String GERMAN = """
        # CoreProtect Language File (de)

        BLANK: "  "
        COMMAND_NOT_FOUND: "Befehl \\"{0}\\" nicht gefunden."
        HELP_ACTION_2: "Beispiele: [a:+block], [a:-block]"
        HELP_FILTER_2: "Beispiele: [a:sign f:-Shop]"
        HELP_HEADER: "{0} Hilfe"
        HELP_INSPECT_7: "Tipp: Benutze \\"/co i\\" für schnelleren Zugriff"
        HELP_STATUS_COMMAND: "Zeigt den Plugin-Status an."
        ONLY_GERMAN: "Nur auf Deutsch"
        UNICODE: "Schon gesehen… ≈"
        WORLD_NOT_FOUND: "Welt \\"{0}\\" nicht gefunden."
        """;

    /** What the answer gives for German when nothing is customized */
    static final Map<String, String> GERMAN_ANSWER = Map.of(
        "COMMAND_NOT_FOUND", "Befehl \"{0}\" nicht gefunden.",
        "HELP_ACTION_2", "Beispiele: [a:+block], [a:-block]",
        "HELP_FILTER_2", "Beispiele: [a:sign f:-Shop]",
        "HELP_HEADER", "{0} Hilfe",
        "HELP_INSPECT_7", "Tipp: Benutze \"/co i\" für schnelleren Zugriff",
        "HELP_STATUS_COMMAND", "Zeigt den Plugin-Status an.",
        "UNICODE", "Schon gesehen… ≈");

    private static Map<String, String> builtIn() {
        try {
            Map<String, String> phrases = new HashMap<>(TranslationBundle.parse(
                new ByteArrayInputStream(ENGLISH.getBytes(StandardCharsets.UTF_8))));
            phrases.put("HELP_FILTER_2", "Examples: [a:sign f:-Shop]");
            return Map.copyOf(phrases);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static TranslationBundle bundle() {
        return TranslationBundleTest.bundle(Map.of(
            TranslationBundle.DEFAULTS, TranslationBundleTest.properties(BUILT_IN),
            "en.yml", ENGLISH,
            "de.yml", GERMAN,
            "zh-cn.yml", "HELP_HEADER: \"{0} 帮助\"\n"), new ArrayList<>());
    }

    /**
     * @return the phrases that a server with nothing customized sends: the
     *         built-in English, except WORLD_NOT_FOUND, which this
     *         CoreProtect doesn't have yet
     */
    static Map<String, String> builtInPhrases(String language) {
        Map<String, String> phrases = new HashMap<>(BUILT_IN);
        phrases.remove("WORLD_NOT_FOUND");
        phrases.put("DATA_VERSION", "24.1");
        phrases.put("DATA_LANGUAGE", language);
        return phrases;
    }

    /**
     * @return the body that CoreProtect's NetworkHandler posts for these phrases
     */
    static byte[] body(Map<String, ?> phrases) {
        String mapString = "data=" + JSONObject.toJSONString(new HashMap<>(phrases));
        mapString = mapString.replaceAll("\\+", "{PLUS_SIGN}");
        return mapString.getBytes(StandardCharsets.UTF_8);
    }

    static Request request(byte[] body) {
        return new Request(MockUrlFactory.translateUrl(), "POST",
            Map.of("Content-Type", "application/x-www-form-urlencoded; charset=utf-8", "User-Agent", "CoreProtect"),
            body);
    }

    static Map<String, String> answer(Response response) throws IOException {
        return new TreeMap<>(TranslationAnswer.strings(new String(response.body(), StandardCharsets.UTF_8)));
    }

    private final TranslationAnswer answer = new TranslationAnswer(bundle());
    private TestLogger logger;

    @BeforeEach
    void setUp() {
        logger = new TestLogger();
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(logger);
    }

    @AfterEach
    void tearDown() {
        LibreProtectLogger.reset();
    }

    @Nested
    @DisplayName("A request for a bundled language")
    class Bundled {

        @Test
        @DisplayName("should be answered with the bundled translation, as JSON on one line")
        void answers() throws IOException {
            Response response = answer.answer(request(body(builtInPhrases("de"))));

            assertEquals(200, response.status());
            assertEquals(Response.JSON, response.contentType());
            String text = new String(response.body(), StandardCharsets.UTF_8);
            assertFalse(text.contains("\n"), text);
            assertEquals(new TreeMap<>(GERMAN_ANSWER), answer(response));
        }

        @Test
        @DisplayName("should record that this version's bundle answered, and nothing when it can't answer")
        void recordsAnswers() throws IOException {
            List<String> answered = new ArrayList<>();
            TranslationAnswer recording = new TranslationAnswer(bundle(), answered::add);

            recording.answer(request(body(builtInPhrases("de"))));
            assertThrows(IOException.class, () -> recording.answer(request(body(builtInPhrases("nl")))));
            assertThrows(IOException.class, () -> recording.answer(request(new byte[0])));

            assertEquals(List.of(TranslationCache.bundled(LibreProtectVersion.getForkVersion())), answered);
        }

        @Test
        @DisplayName("should read {PLUS_SIGN} as +, as CoreProtect's service does")
        void plusSign() throws IOException {
            byte[] body = body(builtInPhrases("de"));
            String text = new String(body, StandardCharsets.UTF_8);
            assertTrue(text.contains("[a:{PLUS_SIGN}block]") && !text.contains("+"), text);

            assertEquals("Beispiele: [a:+block], [a:-block]", answer(answer.answer(request(body))).get("HELP_ACTION_2"));
        }

        @Test
        @DisplayName("should leave out phrases that the server customized in language.yml")
        void customized() throws IOException {
            Map<String, String> phrases = builtInPhrases("de");
            phrases.put("HELP_STATUS_COMMAND", "Shows whether our logger is alive.");
            phrases.put("HELP_HEADER", "\u00A7a{0} Help");
            phrases.put("COMMAND_NOT_FOUND", "Command \"{0}\" not found!");

            Map<String, String> expected = new TreeMap<>(GERMAN_ANSWER);
            expected.keySet().removeAll(List.of("HELP_STATUS_COMMAND", "HELP_HEADER", "COMMAND_NOT_FOUND"));
            assertEquals(expected, answer(answer.answer(request(body(phrases)))));
        }

        @Test
        @DisplayName("should leave out phrases the request doesn't have or doesn't have as text")
        void unknownPhrases() throws IOException {
            Map<String, Object> phrases = new HashMap<>(builtInPhrases("de"));
            phrases.put("HELP_HEADER", null);
            phrases.put("HELP_STATUS_COMMAND", 42);

            Map<String, String> answered = answer(answer.answer(request(body(phrases))));
            assertFalse(answered.containsKey("WORLD_NOT_FOUND"), "CoreProtect doesn't send WORLD_NOT_FOUND");
            assertFalse(answered.containsKey("HELP_HEADER"));
            assertFalse(answered.containsKey("HELP_STATUS_COMMAND"));
            assertFalse(answered.containsKey("ONLY_GERMAN"), "CoreProtect has no built-in ONLY_GERMAN");
            assertFalse(answered.containsKey("BLANK"), "the German BLANK is blank");
        }

        @Test
        @DisplayName("should tell customized phrases by CoreProtect's built-in English, not by en.yml")
        void builtInEnglish() throws IOException {
            Map<String, String> uncustomized = builtInPhrases("de");
            assertEquals("Beispiele: [a:sign f:-Shop]",
                answer(answer.answer(request(body(uncustomized)))).get("HELP_FILTER_2"));

            // A server that customized the phrase to what en.yml has
            Map<String, String> customized = builtInPhrases("de");
            customized.put("HELP_FILTER_2", "Examples: [a:sign f:Shop]");
            assertFalse(answer(answer.answer(request(body(customized)))).containsKey("HELP_FILTER_2"));
        }

        @Test
        @DisplayName("should survive CoreProtect's reading, parsing, cache writing and cache loading unchanged")
        void upstreamRoundTrip() throws Exception {
            String german = "# de\nA: \"quote \\\" in\"\nB: 'single '' quote'\nC: \"back\\\\slash\"\n"
                + "D: \"sep arator\"\nE: \"  padded  \"\n";
            Map<String, String> builtIn = Map.of("A", "x", "B", "y", "C", "z", "D", "w", "E", "v");
            TranslationBundle bundle = TranslationBundleTest.bundle(Map.of(
                TranslationBundle.DEFAULTS, TranslationBundleTest.properties(builtIn), "de.yml", german),
                new ArrayList<>());
            Map<String, String> sent = new HashMap<>(builtIn);
            sent.put("DATA_LANGUAGE", "de");
            Response response = new TranslationAnswer(bundle).answer(request(body(sent)));

            // CoreProtect's NetworkHandler: lines trimmed and joined, parsed by json-simple, values trimmed and
            // applied, then written to the cache with their quotes escaped
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                new ByteArrayInputStream(response.body()), StandardCharsets.UTF_8));
            StringBuilder joined = new StringBuilder();
            for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                joined.append(line.trim());
            }
            JSONObject json = (JSONObject) new JSONParser().parse(joined.toString());
            StringBuilder cache = new StringBuilder("# CoreProtect v24.1 Language Cache (de)\n");
            Map<String, String> applied = new TreeMap<>();
            for (Object key : json.keySet()) {
                String value = ((String) json.get(key)).trim();
                applied.put((String) key, value);
                cache.append("\n").append(key).append(": \"").append(value.replaceAll("\"", "\\\\\"")).append("\"");
            }
            assertEquals(Map.of("A", "quote \" in", "B", "single ' quote", "C", "back\\slash", "D", "sep arator",
                "E", "padded"), applied);

            // CoreProtect's ConfigFile.load, reading the cache at the next start
            assertEquals(applied, new TreeMap<>(TranslationBundle.parse(
                new ByteArrayInputStream(cache.toString().getBytes(StandardCharsets.UTF_8)))));
        }

        @Test
        @DisplayName("should find the language by alias, as CoreProtect's documentation spells it")
        void alias() throws IOException {
            Map<String, String> phrases = builtInPhrases("zh");
            assertEquals(Map.of("HELP_HEADER", "{0} 帮助"), answer(answer.answer(request(body(phrases)))));
        }

        @Test
        @DisplayName("should answer an empty object when every phrase is customized")
        void allCustomized() throws IOException {
            Map<String, String> phrases = new HashMap<>();
            phrases.put("HELP_HEADER", "{0} Manual");
            phrases.put("DATA_LANGUAGE", "de");
            Response response = answer.answer(request(body(phrases)));
            assertEquals("{}", new String(response.body(), StandardCharsets.UTF_8));
        }

        @Test
        @DisplayName("should be read by CoreProtect's own code the way it reads its service's reply")
        void readByCoreProtect() throws IOException, ParseException {
            // What CoreProtect's NetworkHandler does with the connection that Egress returns
            HttpURLConnection connection = new AnswerConnection(MockUrlFactory.translateUrl(), answer);
            byte[] postData = body(builtInPhrases("de"));
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Accept-Charset", "UTF-8");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
            connection.setRequestProperty("User-Agent", "CoreProtect");
            connection.setRequestProperty("Content-Length", Integer.toString(postData.length));
            connection.setDoOutput(true);
            connection.setConnectTimeout(5000);
            DataOutputStream outputStream = new DataOutputStream(connection.getOutputStream());
            outputStream.write(postData);
            outputStream.close();

            assertEquals(200, connection.getResponseCode());
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), "utf-8"));
            StringBuilder responseBuilder = new StringBuilder();
            String responseLine;
            while ((responseLine = reader.readLine()) != null) {
                responseBuilder.append(responseLine.trim());
            }
            String response = responseBuilder.toString();
            assertTrue(response.startsWith("{") && response.endsWith("}"), response);

            Map<String, String> translated = new TreeMap<>();
            JSONObject json = (JSONObject) new JSONParser().parse(response);
            for (Object key : json.keySet()) {
                translated.put((String) key, ((String) json.get(key)).trim());
            }
            assertEquals(new TreeMap<>(GERMAN_ANSWER), translated);
        }

        @Test
        @DisplayName("should fail if the bundle has no built-in English to compare with")
        void noBuiltInEnglish() {
            TranslationAnswer withoutBuiltIn = new TranslationAnswer(
                TranslationBundleTest.bundle(Map.of("de.yml", GERMAN, "en.yml", ENGLISH), new ArrayList<>()));
            IOException failure = assertThrows(IOException.class,
                () -> withoutBuiltIn.answer(request(body(builtInPhrases("de")))));
            assertTrue(failure.getMessage().contains("built-in English"), failure.getMessage());
        }
    }

    @Nested
    @DisplayName("A request for a language that isn't bundled")
    class NotBundled {

        @Test
        @DisplayName("should fail, so that CoreProtect stays in English and saves no cache")
        void fails() {
            IOException failure = assertThrows(IOException.class,
                () -> answer.answer(request(body(builtInPhrases("nl")))));
            assertTrue(failure.getMessage().contains("'nl'"), failure.getMessage());
        }

        @Test
        @DisplayName("should log a warning once per language")
        void warnsOnce() {
            for (String language : List.of("nl", "nl", "pt-br", "nl")) {
                assertThrows(IOException.class, () -> answer.answer(request(body(builtInPhrases(language)))));
            }

            assertEquals(2, logger.countAtLevel(Level.WARNING), logger.getMessages()::toString);
            assertTrue(logger.hasMessageContaining(Level.WARNING, "No bundled translation for 'nl'"));
            assertTrue(logger.hasMessageContaining(Level.WARNING, "No bundled translation for 'pt-br'"));
            assertTrue(logger.hasMessageContaining(Level.WARNING, "coreprotect.net"));
        }
    }

    @Nested
    @DisplayName("A request that isn't CoreProtect's translation request")
    class Garbled {

        @ParameterizedTest(name = "\"{0}\"")
        @ValueSource(strings = {
            "",
            "data=",
            "{\"DATA_LANGUAGE\":\"de\"}",
            "data={\"DATA_LANGUAGE\":\"de\"",
            "data={\"DATA_LANGUAGE\":\"de\"} trailing",
            "data={\"DATA_LANGUAGE\":\"de\"}{}",
            "data=[\"DATA_LANGUAGE\",\"de\"]",
            "data=\"de\"",
            "data={DATA_LANGUAGE:de}",
            "data={}",
            "data={\"DATA_LANGUAGE\":7}",
            "data=%7B%22DATA_LANGUAGE%22%3A%22de%22%7D",
        })
        @DisplayName("should fail without a warning")
        void fails(String body) {
            assertThrows(IOException.class, () -> answer.answer(request(body.getBytes(StandardCharsets.UTF_8))));
            assertTrue(logger.getRecords().isEmpty(), logger.getMessages()::toString);
        }
    }

    @Nested
    @DisplayName("phrases()")
    class Phrases {

        @Test
        @DisplayName("should read every escape that json-simple writes")
        void jsonSimpleEscapes() throws IOException {
            Map<String, String> phrases = new LinkedHashMap<>();
            phrases.put("QUOTES", "say \"hi\" and 'bye'");
            phrases.put("BACKSLASH", "C:\\path\\to\\ \\\" \\\\");
            phrases.put("PLUS", "a+b ++ +{0}+");
            phrases.put("SLASH", "</script> / //");
            phrases.put("CONTROL", "tab\tnl\ncr\rbs\bff\f\u0001\u001f\u007f\u009f");
            phrases.put("GENERAL_PUNCTUATION", "\u2000\u2014\u2028\u2029\u20ac\u20ff");
            phrases.put("ASTRAL", "😀 𝄞");
            phrases.put("COLOR", "§a&bgreen");
            phrases.put("BRACES", "{PLUS} {PLUS_SIGN_} {0} {1}");
            phrases.put("EMPTY", "");
            phrases.put("DATA_LANGUAGE", "de");
            assertEquals(phrases, TranslationAnswer.phrases(body(phrases)));
        }

        @Test
        @DisplayName("should read a literal {PLUS_SIGN} as +, which CoreProtect sends it as")
        void literalPlusSign() throws IOException {
            // Only a customized phrase can have it, and those are never translated
            Map<String, String> phrases = Map.of("HELP_HEADER", "literal {PLUS_SIGN}", "DATA_LANGUAGE", "de");
            assertEquals("literal +", TranslationAnswer.phrases(body(phrases)).get("HELP_HEADER"));
        }
    }

    @Test
    @DisplayName("strings() should keep the object's order and the last of repeated keys")
    void stringsOrder() throws IOException {
        Map<String, String> expected = new LinkedHashMap<>();
        expected.put("b", "2");
        expected.put("a", "3");
        assertEquals(new ArrayList<>(expected.entrySet()),
            new ArrayList<>(TranslationAnswer.strings("{\"b\":\"2\",\"a\":\"1\",\"a\":\"3\"}").entrySet()));
    }
}
