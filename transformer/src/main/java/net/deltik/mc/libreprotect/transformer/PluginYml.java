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

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Edits top-level keys of {@code plugin.yml} as text, so upstream's layout and
 * comments survive, and then proves with a YAML parser that nothing except
 * those keys changed.
 */
final class PluginYml {

    static final String ENTRY = "plugin.yml";

    private final String text;
    private final Map<String, Object> values;

    PluginYml(String text) {
        this.text = text;
        this.values = parse(text);
    }

    String text() {
        return text;
    }

    Object get(String key) {
        return values.get(key);
    }

    String getString(String key) {
        Object value = values.get(key);
        return value == null ? null : value.toString();
    }

    /**
     * @return a copy of this file with each given top-level key set to a string value
     */
    PluginYml with(Map<String, String> replacements) {
        String lineEnding = text.contains("\r\n") ? "\r\n" : "\n";
        List<String> lines = new ArrayList<>(Arrays.asList(text.split(lineEnding, -1)));

        for (Map.Entry<String, String> replacement : replacements.entrySet()) {
            String key = replacement.getKey();
            String line = key + ": " + quote(replacement.getValue());
            int start = findTopLevelKey(lines, key);
            if (start < 0) {
                int end = !lines.isEmpty() && lines.get(lines.size() - 1).isEmpty() ? lines.size() - 1 : lines.size();
                lines.add(end, line);
                continue;
            }
            int end = start + 1;
            while (end < lines.size() && isContinuation(lines, end)) {
                end++;
            }
            lines.subList(start, end).clear();
            lines.add(start, line);
        }

        PluginYml edited = new PluginYml(String.join(lineEnding, lines));

        Map<String, Object> expected = new LinkedHashMap<>(values);
        expected.putAll(replacements);
        ContractViolation.require(expected.equals(edited.values),
            "Editing plugin.yml changed more than " + replacements.keySet() + "; its layout may have changed upstream.\n"
                + "Expected: " + expected + "\nActual:   " + edited.values);
        return edited;
    }

    private static int findTopLevelKey(List<String> lines, String key) {
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.startsWith(key + ":")
                && (line.length() == key.length() + 1 || Character.isWhitespace(line.charAt(key.length() + 1)))) {
                return i;
            }
        }
        return -1;
    }

    /**
     * A line continues the previous top-level value if it is indented, or if
     * it is blank and the next non-blank line is indented (block scalars can
     * contain blank lines).
     */
    private static boolean isContinuation(List<String> lines, int index) {
        String line = lines.get(index);
        if (!line.isBlank()) {
            return isIndented(line);
        }
        for (int next = index + 1; next < lines.size(); next++) {
            if (!lines.get(next).isBlank()) {
                return isIndented(lines.get(next));
            }
        }
        return false;
    }

    private static boolean isIndented(String line) {
        return line.charAt(0) == ' ' || line.charAt(0) == '\t';
    }

    private static String quote(String value) {
        return '"' + value.replace("\\", "\\\\").replace("\"", "\\\"") + '"';
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parse(String text) {
        Object parsed = new Yaml(new SafeConstructor(new LoaderOptions())).load(text);
        ContractViolation.require(parsed instanceof Map, "plugin.yml is not a YAML mapping");
        return new LinkedHashMap<>((Map<String, Object>) parsed);
    }
}
