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

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * What the transformer changes so that CoreProtect's messages present
 * LibreProtect. The runtime side is {@code net.deltik.mc.libreprotect.Branding}.
 *
 * <p>CoreProtect keeps its plugin name, {@code CoreProtect}, because other
 * plugins and the data folder depend on it. So "CoreProtect" can't be
 * replaced everywhere: it is also a plugin lookup, a logger name, a file
 * name and a header that CoreProtect parses. Only text with a display shape
 * is rebranded, and anything else is left alone.
 */
final class BrandingRules {

    static final String BRANDING = "net/deltik/mc/libreprotect/Branding";
    static final String UPSTREAM_NAME = "CoreProtect";
    static final String FORK_NAME = "LibreProtect";

    static final String PHRASE_HOOK = "phrase";
    static final String PHRASE_HOOK_DESCRIPTOR =
        "(Ljava/lang/Enum;[Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;";

    static final String BUKKIT_PACKAGE = "org/bukkit/";
    static final String SEND_MESSAGE = "sendMessage";
    static final String SEND_MESSAGE_DESCRIPTOR = "(Ljava/lang/String;)V";
    static final String SEND_MESSAGE_HOOK_DESCRIPTOR = "(Lorg/bukkit/command/CommandSender;Ljava/lang/String;)V";

    static final String LOGGER = "java/util/logging/Logger";
    /** {@link java.util.logging.Logger} methods that print a message, and the descriptor of their replacement */
    static final Map<String, String> LOGGER_HOOKS = Map.of(
        "log(Ljava/util/logging/Level;Ljava/lang/String;)V",
        "(Ljava/util/logging/Logger;Ljava/util/logging/Level;Ljava/lang/String;)V",
        "info(Ljava/lang/String;)V", "(Ljava/util/logging/Logger;Ljava/lang/String;)V",
        "warning(Ljava/lang/String;)V", "(Ljava/util/logging/Logger;Ljava/lang/String;)V",
        "severe(Ljava/lang/String;)V", "(Ljava/util/logging/Logger;Ljava/lang/String;)V");

    /**
     * Formatting that can sit between the words of a message: the argument
     * and constant slots of a {@code StringConcatFactory} recipe, and
     * Minecraft format codes.
     */
    private static final String FORMAT = "(?:[\\u0001\\u0002]|\u00A7[0-9a-fk-orxA-FK-ORX])*";

    /**
     * Display shapes of the plugin name in CoreProtect's text constants. Each
     * pattern's first group is kept, and the name after it is replaced.
     */
    static final List<Pattern> TEXT_RULES = List.of(
        // Chat prefix: "CoreProtect - You do not have permission"
        Pattern.compile("()" + UPSTREAM_NAME + "(?= ?" + FORMAT + "- )"),
        // Console prefix: "[CoreProtect] Using SQLite"
        Pattern.compile("(\\[)" + UPSTREAM_NAME + "(?=])"),
        // Header: "----- CoreProtect -----"
        Pattern.compile("(----- ?" + FORMAT + ")" + UPSTREAM_NAME),
        // Lookup header: "CoreProtect | Lookup Results"
        Pattern.compile("()" + UPSTREAM_NAME + "(?=" + FORMAT + " \\| )"),
        // The name alone after a color: DARK_AQUA + "CoreProtect"
        Pattern.compile("^((?:[\\u0001\\u0002]|\u00A7[0-9a-fk-orxA-FK-ORX])+)" + UPSTREAM_NAME + "$"));

    private BrandingRules() {
    }

    /**
     * @return the text with every display of the plugin name rebranded, or
     *         the same instance if nothing matched
     */
    static String rebrand(String text) {
        if (!text.contains(UPSTREAM_NAME)) {
            return text;
        }
        String result = text;
        for (Pattern rule : TEXT_RULES) {
            Matcher matcher = rule.matcher(result);
            if (matcher.find()) {
                result = matcher.replaceAll("$1" + FORK_NAME);
            }
        }
        return result.equals(text) ? text : result;
    }

    static boolean isSendMessage(int opcode, String owner, String name, String descriptor) {
        return opcode == Opcodes.INVOKEINTERFACE && owner.startsWith(BUKKIT_PACKAGE)
            && SEND_MESSAGE.equals(name) && SEND_MESSAGE_DESCRIPTOR.equals(descriptor);
    }

    /**
     * @return the replacement's descriptor, or {@code null} if this isn't a
     *         logger call that prints a message
     */
    static String loggerHook(int opcode, String owner, String name, String descriptor) {
        return opcode == Opcodes.INVOKEVIRTUAL && LOGGER.equals(owner) ? LOGGER_HOOKS.get(name + descriptor) : null;
    }

    /**
     * Finds CoreProtect's phrase renderer by shape rather than by name: a
     * static method of an enum that takes one of the enum's constants and a
     * {@code String[]} and returns a {@code String}, like
     * {@code Phrase.build(Phrase, String...)}.
     *
     * @return {@code owner.name descriptor} of each renderer in the class, if any
     */
    static List<String> phraseRenderers(byte[] classBytes) {
        ClassNode node = new ClassNode();
        new ClassReader(classBytes).accept(node, ClassReader.SKIP_CODE);
        if (!"java/lang/Enum".equals(node.superName) || (node.access & Opcodes.ACC_ENUM) == 0) {
            return List.of();
        }
        String descriptor = "(L" + node.name + ";[Ljava/lang/String;)Ljava/lang/String;";
        return node.methods.stream()
            .filter(method -> (method.access & Opcodes.ACC_STATIC) != 0 && method.desc.equals(descriptor))
            .map(method -> key(node.name, method.name, method.desc))
            .toList();
    }

    static String key(String owner, String name, String descriptor) {
        return owner + "." + name + descriptor;
    }
}
