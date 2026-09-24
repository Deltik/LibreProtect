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

package net.deltik.mc.libreprotect.transformer;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The translations in CoreProtect's source code, in {@code lang/}, which
 * CoreProtect's JAR leaves out. LibreProtect bundles them, so that it can
 * answer CoreProtect's translation requests itself, without a network
 * request. The runtime side is
 * {@code net.deltik.mc.libreprotect.routing.answer.TranslationAnswer},
 * and {@code TranslationBundle} there reads the files with the same rules as
 * {@link #parse}.
 *
 * <p>With them goes CoreProtect's built-in English, taken from its code. A
 * server sends it for each phrase that it didn't customize, and the runtime
 * leaves out the phrases whose text differs, as CoreProtect's own cache
 * loader does.
 */
final class Translations {

    static final String DIRECTORY = Transformer.REPORT_DIRECTORY + "lang/";
    /** Upstream's English translation, which upstream keeps next to its code's English */
    static final String ENGLISH = "en";
    /** CoreProtect's built-in English phrases, as Java properties */
    static final String DEFAULTS = DIRECTORY + "defaults.properties";

    /** What the runtime accepts as a language code */
    private static final Pattern CODE = Pattern.compile("[a-z0-9]{1,8}(-[a-z0-9]{1,8}){0,4}");
    /**
     * The share of phrases that must have built-in English. Upstream's code
     * gives each phrase a plain text; much less means that the way it does
     * so changed.
     */
    private static final double DEFAULTS_REQUIRED = 0.9;
    private static final String MAP_PUT = "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;";

    private Translations() {
    }

    /**
     * Read the language files and check each against the phrase enum.
     *
     * @param directory upstream's {@code lang/} directory
     * @param phrases   the names of upstream's phrases, the constants of its
     *                  phrase enum
     * @param report    receives one entry per language, in order of code
     * @return each file's entry in the JAR and its unchanged content
     */
    static Map<String, byte[]> read(Path directory, Set<String> phrases, List<TransformReport.Translation> report)
        throws IOException {
        ContractViolation.require(Files.isDirectory(directory), "Upstream's language directory " + directory
            + " doesn't exist. LibreProtect bundles upstream's translations from it, to translate without network "
            + "requests; upstream may have moved or dropped them.");
        List<Path> files;
        try (Stream<Path> listing = Files.list(directory)) {
            files = listing.filter(file -> file.getFileName().toString().endsWith(".yml") && Files.isRegularFile(file))
                .sorted().toList();
        }
        ContractViolation.require(!files.isEmpty(), "Upstream's language directory " + directory + " has no *.yml "
            + "files. LibreProtect bundles upstream's translations from it, to translate without network requests; "
            + "upstream may have moved or dropped them.");

        Map<String, byte[]> entries = new TreeMap<>();
        List<TransformReport.Translation> translations = new ArrayList<>();
        for (Path file : files) {
            String name = file.getFileName().toString();
            String code = name.substring(0, name.length() - ".yml".length()).toLowerCase(Locale.ROOT).replace('_', '-');
            ContractViolation.require(CODE.matcher(code).matches(), "Upstream's language file " + file
                + " isn't named like a language code, such as de.yml or zh-cn.yml");
            String entry = DIRECTORY + code + ".yml";
            byte[] content = Files.readAllBytes(file);
            ContractViolation.require(entries.put(entry, content) == null,
                "Upstream has two language files for '" + code + "' in " + directory);

            Map<String, String> translated = parse(new String(content, StandardCharsets.UTF_8));
            TreeSet<String> known = new TreeSet<>();
            TreeSet<String> unknown = new TreeSet<>();
            translated.forEach((phrase, text) -> {
                if (!phrases.contains(phrase)) {
                    unknown.add(phrase);
                } else if (!text.isBlank()) {
                    known.add(phrase);
                }
            });
            ContractViolation.require(!known.isEmpty(), "Upstream's language file " + file + " translates none of "
                + "the " + phrases.size() + " phrases. Upstream may have changed the file format, which LibreProtect "
                + "reads like CoreProtect's language.yml.");
            TreeSet<String> missing = new TreeSet<>(phrases);
            missing.removeAll(known);
            translations.add(new TransformReport.Translation(code, known.size(), List.copyOf(missing),
                List.copyOf(unknown)));
        }
        ContractViolation.require(entries.containsKey(DIRECTORY + ENGLISH + ".yml"), "Upstream's language directory "
            + directory + " has no " + ENGLISH + ".yml, its English translation. Upstream may have changed how it "
            + "ships translations; review that before relaxing this check.");
        translations.sort(Comparator.comparing(TransformReport.Translation::language));
        report.addAll(translations);
        return entries;
    }

    /**
     * Read a language file like CoreProtect's {@code ConfigFile.load} does:
     * lines starting with {@code #} are comments; other lines are split at
     * the first {@code :} into a phrase name, in uppercase, and its text;
     * both are trimmed; and matching quotes around the text are removed,
     * along with their escapes.
     */
    static Map<String, String> parse(String text) {
        Map<String, String> phrases = new LinkedHashMap<>();
        text.lines().forEach(line -> {
            int split = line.indexOf(':');
            if (line.startsWith("#") || split < 0) {
                return;
            }
            String name = line.substring(0, split).trim().toUpperCase(Locale.ROOT);
            String value = line.substring(split + 1).trim();
            if (value.length() >= 2 && value.startsWith("'") && value.endsWith("'")) {
                value = value.substring(1, value.length() - 1).replace("''", "'").replace("\\'", "'")
                    .replace("\\\\", "\\");
            } else if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                value = value.substring(1, value.length() - 1).replace("\\\"", "\"").replace("\\\\", "\\");
            }
            phrases.put(name, value);
        });
        return phrases;
    }

    /**
     * @param phraseEnums internal names of upstream's phrase enums
     * @return the names of their constants
     */
    static Set<String> phrases(JarContents upstream, Set<String> phraseEnums) {
        Set<String> phrases = new TreeSet<>();
        for (String phraseEnum : phraseEnums) {
            byte[] bytes = upstream.get(phraseEnum + ".class");
            ContractViolation.require(bytes != null, "Missing phrase enum " + phraseEnum);
            ClassNode node = new ClassNode();
            new ClassReader(bytes).accept(node, ClassReader.SKIP_CODE);
            for (FieldNode field : node.fields) {
                if ((field.access & Opcodes.ACC_ENUM) != 0) {
                    phrases.add(field.name);
                }
            }
        }
        ContractViolation.require(!phrases.isEmpty(), "The phrase enum " + phraseEnums + " has no constants");
        return phrases;
    }

    /**
     * Find CoreProtect's built-in English: code in the phrase enum's package
     * that puts a phrase constant and a text into a map, like
     * {@code phrases.put(Phrase.HELP_HEADER, "{0} Help")} in
     * {@code Language.loadPhrases()}. That is the text that CoreProtect
     * compares {@code language.yml} with to tell customized phrases.
     *
     * @param phraseEnums internal names of upstream's phrase enums
     * @param phrases     the names of their constants
     * @return the built-in English by phrase name
     */
    static Map<String, String> defaults(JarContents upstream, Set<String> phraseEnums, Set<String> phrases) {
        Set<String> packages = new TreeSet<>();
        phraseEnums.forEach(phraseEnum -> packages.add(packageOf(phraseEnum)));
        Map<String, String> defaults = new TreeMap<>();
        for (String name : upstream.names()) {
            if (!JarContents.isClass(name) || JarContents.isVersioned(name)
                || !packages.contains(packageOf(JarContents.internalName(name)))) {
                continue;
            }
            ClassNode node = new ClassNode();
            new ClassReader(upstream.get(name)).accept(node, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            for (MethodNode method : node.methods) {
                List<AbstractInsnNode> code = new ArrayList<>();
                method.instructions.forEach(instruction -> {
                    if (instruction.getOpcode() >= 0) {
                        code.add(instruction);
                    }
                });
                for (int i = 0; i + 2 < code.size(); i++) {
                    if (code.get(i) instanceof FieldInsnNode field && field.getOpcode() == Opcodes.GETSTATIC
                        && phraseEnums.contains(field.owner) && field.desc.equals("L" + field.owner + ";")
                        && phrases.contains(field.name)
                        && code.get(i + 1) instanceof LdcInsnNode ldc && ldc.cst instanceof String text
                        && code.get(i + 2) instanceof MethodInsnNode put && put.name.equals("put")
                        && put.desc.equals(MAP_PUT)) {
                        String previous = defaults.put(field.name, text);
                        ContractViolation.require(previous == null || previous.equals(text), "Upstream's code gives "
                            + "the phrase " + field.name + " two built-in texts: '" + previous + "' and '" + text + "'");
                    }
                }
            }
        }
        ContractViolation.require(defaults.size() >= phrases.size() * DEFAULTS_REQUIRED, "Found built-in English in "
            + "upstream's code for " + defaults.size() + " of its " + phrases.size() + " phrases, looking for "
            + "phrases.put(Phrase.X, \"text\") in " + packages + ". LibreProtect compares a server's phrases with "
            + "it to leave out the ones the server customized; upstream may have changed how it defines them.");
        return defaults;
    }

    /**
     * @return the built-in English as Java properties, sorted by phrase name
     */
    static byte[] defaultsFile(Map<String, String> defaults) {
        StringBuilder text = new StringBuilder("# CoreProtect's built-in English phrases, from its code\n");
        new TreeMap<>(defaults).forEach((phrase, value) -> {
            text.append(phrase).append('=');
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                switch (c) {
                    case '\\' -> text.append("\\\\");
                    case '\n' -> text.append("\\n");
                    case '\r' -> text.append("\\r");
                    case '\t' -> text.append("\\t");
                    case '\f' -> text.append("\\f");
                    // Properties skip leading whitespace
                    case ' ' -> text.append(i == 0 ? "\\ " : " ");
                    default -> text.append(c < ' ' ? String.format("\\u%04x", (int) c) : String.valueOf(c));
                }
            }
            text.append('\n');
        });
        return text.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * @param english upstream's {@code en.yml}, as {@link #parse} reads it
     * @return the phrases whose text in {@code en.yml} differs from the
     *         built-in English
     */
    static List<String> englishDifferences(Map<String, String> english, Map<String, String> defaults) {
        return english.entrySet().stream()
            .filter(phrase -> defaults.containsKey(phrase.getKey())
                && !defaults.get(phrase.getKey()).equals(phrase.getValue()))
            .map(Map.Entry::getKey)
            .sorted()
            .toList();
    }

    private static String packageOf(String internalName) {
        return internalName.substring(0, internalName.lastIndexOf('/') + 1);
    }
}
