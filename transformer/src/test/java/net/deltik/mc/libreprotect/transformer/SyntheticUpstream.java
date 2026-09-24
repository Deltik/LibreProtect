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

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds a small fake upstream: a shaded JAR and its unshaded counterpart,
 * shaped like CoreProtect's. Each part can be changed to simulate an
 * upstream change.
 */
final class SyntheticUpstream {

    static final String MAIN = "net/coreprotect/CoreProtect";
    static final String VERSION_UTILS = "net/coreprotect/utility/VersionUtils";
    static final String NETWORK = "net/coreprotect/thread/NetworkHandler";
    static final String EXTENSIONS = "net/coreprotect/utility/Extensions";
    static final String PLAIN = "net/coreprotect/Plain";
    static final String PHRASE = "net/coreprotect/language/Phrase";
    static final String LANGUAGE = "net/coreprotect/language/Language";
    static final String CONFIG_FILE = "net/coreprotect/config/ConfigFile";
    static final String CHAT = "net/coreprotect/utility/Chat";
    static final String BSTATS = "net/coreprotect/MetricsBase";
    static final String DRIVER = "com/example/jdbc/Driver";

    String pluginYml = """
        name: CoreProtect
        main: net.coreprotect.CoreProtect
        version: 24.1
        branch: libre
        website: http://coreprotect.net
        author: Intelli
        description: >
                     Provides block protection for your server.
        commands:
          co:
            description: Utilize the plugin
        """;

    boolean mainFinal = true;
    boolean mainSealed = false;
    boolean onEnableFinal = false;
    List<String> gates = new ArrayList<>(List.of("validDonationKey", "isCommunityEdition"));
    /** Whether {@code VersionUtils} has {@code getPluginVersion()}, which reads plugin.yml's version */
    boolean pluginVersion = true;
    boolean networkEgress = true;
    boolean phraseRenderer = true;
    boolean messageOutput = true;
    List<String> extensionStrings = new ArrayList<>(List.of(
        "net.coreprotect.utility.extensions.DatabaseMigration", "runCommand",
        "net.coreprotect.utility.extensions.BackgroundService", "start", "stop"));
    /** Constants of the phrase enum */
    List<String> phrases = new ArrayList<>(List.of("HELP_HEADER", "LINK_DOWNLOAD", "NO_PERMISSION"));
    /** The built-in English that {@code Language.loadPhrases()} puts, in order; a phrase may appear twice */
    final List<Map.Entry<String, String>> defaults = new ArrayList<>(List.of(
        Map.entry("HELP_HEADER", "{0} Help"),
        Map.entry("LINK_DOWNLOAD", "Download: {0}"),
        Map.entry("NO_PERMISSION", "You do not have permission to do that.")));
    /** What upstream's code calls its translation cache */
    String languageCache = ".language";
    /** Files in upstream's lang/ directory, which isn't part of the JARs; without any, there is no directory */
    final Map<String, String> lang = new LinkedHashMap<>(Map.of(
        "en.yml", """
            # CoreProtect Language File (en)

            HELP_HEADER: "{0} Help"
            LINK_DOWNLOAD: "Download: {0}"
            NO_PERMISSION: "You do not have permission to do that."
            """,
        "de.yml", """
            # CoreProtect Language File (de)

            HELP_HEADER: "{0} Hilfe"
            LINK_DOWNLOAD: "Herunterladen: {0}"
            """));

    /** Upstream-authored entries (end up in both JARs) */
    final Map<String, byte[]> upstreamExtra = new LinkedHashMap<>();
    /** Shaded library entries (only in the shaded JAR) */
    final Map<String, byte[]> libraries = new LinkedHashMap<>();

    SyntheticUpstream() {
        libraries.put(BSTATS + ".class", classWithEgress(BSTATS));
        libraries.put(DRIVER + ".class", classWithEgress(DRIVER));
    }

    /**
     * @param lang upstream's {@code lang/} directory
     */
    record Jars(Path shaded, Path original, Path lang) {
    }

    Jars write(Path directory) throws IOException {
        Path langDirectory = directory.resolve("lang");
        if (!lang.isEmpty()) {
            Files.createDirectories(langDirectory);
        }
        for (Map.Entry<String, String> file : lang.entrySet()) {
            Files.writeString(langDirectory.resolve(file.getKey()), file.getValue(), StandardCharsets.UTF_8);
        }

        Map<String, byte[]> authored = new LinkedHashMap<>();
        authored.put("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\npaperweight-mappings-namespace: mojang\n"
            .getBytes(StandardCharsets.UTF_8));
        authored.put("plugin.yml", pluginYml.getBytes(StandardCharsets.UTF_8));
        authored.put(MAIN + ".class", mainClass());
        authored.put(VERSION_UTILS + ".class", gateClass(VERSION_UTILS, gates, pluginVersion));
        authored.put(NETWORK + ".class", networkEgress ? classWithEgress(NETWORK) : plainClass(NETWORK));
        authored.put(EXTENSIONS + ".class", classWithStrings(EXTENSIONS, extensionStrings));
        authored.put(PLAIN + ".class", plainClass(PLAIN));
        authored.put(PHRASE + ".class", phraseEnum(phraseRenderer, phrases));
        authored.put(LANGUAGE + ".class", languageClass(defaults));
        authored.put(CONFIG_FILE + ".class", classWithStrings(CONFIG_FILE, List.of(languageCache)));
        authored.put(CHAT + ".class", chatClass(messageOutput));
        authored.putAll(upstreamExtra);

        Map<String, byte[]> shaded = new LinkedHashMap<>(authored);
        shaded.putAll(libraries);

        return new Jars(
            TestClasses.writeJar(directory.resolve("CoreProtect-24.1.jar"), shaded),
            TestClasses.writeJar(directory.resolve("original-CoreProtect-24.1.jar"), authored),
            langDirectory);
    }

    byte[] mainClass() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        int access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER | (mainFinal ? Opcodes.ACC_FINAL : 0);
        writer.visit(Opcodes.V11, access, MAIN, null, SubclassGenerator.JAVA_PLUGIN, null);
        if (mainSealed) {
            writer.visitPermittedSubclass(MAIN + "$Only");
        }
        MethodVisitor constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        constructor.visitCode();
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, SubclassGenerator.JAVA_PLUGIN, "<init>", "()V", false);
        constructor.visitInsn(Opcodes.RETURN);
        constructor.visitMaxs(0, 0);
        constructor.visitEnd();
        MethodVisitor onEnable = writer.visitMethod(Opcodes.ACC_PUBLIC | (onEnableFinal ? Opcodes.ACC_FINAL : 0),
            "onEnable", "()V", null, null);
        onEnable.visitCode();
        onEnable.visitInsn(Opcodes.RETURN);
        onEnable.visitMaxs(0, 0);
        onEnable.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    static byte[] gateClass(String name, List<String> gates) {
        return gateClass(name, gates, false);
    }

    /**
     * @param pluginVersion whether to include {@code static String getPluginVersion()}, which returns
     *                      a {@code PluginDescriptionFile}'s version
     */
    static byte[] gateClass(String name, List<String> gates, boolean pluginVersion) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, name, null, "java/lang/Object", null);
        for (String gate : gates) {
            MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, gate, "()Z", null, null);
            method.visitCode();
            method.visitInsn(Opcodes.ICONST_0);
            method.visitInsn(Opcodes.IRETURN);
            method.visitMaxs(0, 0);
            method.visitEnd();
        }
        if (pluginVersion) {
            MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                PluginVersionRewriter.METHOD, PluginVersionRewriter.DESCRIPTOR, null, null);
            method.visitCode();
            method.visitInsn(Opcodes.ACONST_NULL);
            method.visitTypeInsn(Opcodes.CHECKCAST, PluginVersionRewriter.DESCRIPTION);
            method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, PluginVersionRewriter.DESCRIPTION,
                PluginVersionRewriter.GET_VERSION, PluginVersionRewriter.DESCRIPTOR, false);
            method.visitInsn(Opcodes.ARETURN);
            method.visitMaxs(0, 0);
            method.visitEnd();
        }
        writer.visitEnd();
        return writer.toByteArray();
    }

    static byte[] classWithEgress(String name) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, name, null, "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "send",
            "(Ljava/net/URL;)Ljava/net/URLConnection;", null, new String[] {"java/io/IOException"});
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/net/URL", "openConnection", "()Ljava/net/URLConnection;", false);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    static byte[] classWithStrings(String name, List<String> strings) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, name, null, "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "names", "()V", null, null);
        method.visitCode();
        for (String string : strings) {
            method.visitLdcInsn(string);
            method.visitInsn(Opcodes.POP);
        }
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    /**
     * @param renderer whether to include {@code static String build(Phrase, String...)}
     * @param constants the enum's constants
     */
    static byte[] phraseEnum(boolean renderer, List<String> constants) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER | Opcodes.ACC_FINAL | Opcodes.ACC_ENUM,
            PHRASE, null, "java/lang/Enum", null);
        for (String constant : constants) {
            writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL | Opcodes.ACC_ENUM, constant,
                "L" + PHRASE + ";", null, null).visitEnd();
        }
        // Not a constant, although it has the enum's type
        writer.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL, "DEFAULT", "L" + PHRASE + ";",
            null, null).visitEnd();
        if (renderer) {
            MethodVisitor build = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_VARARGS,
                "build", "(L" + PHRASE + ";[Ljava/lang/String;)Ljava/lang/String;", null, null);
            build.visitCode();
            build.visitLdcInsn("");
            build.visitInsn(Opcodes.ARETURN);
            build.visitMaxs(0, 0);
            build.visitEnd();
        }
        writer.visitEnd();
        return writer.toByteArray();
    }

    /**
     * @return a class like CoreProtect's {@code Language}, whose
     *         {@code loadPhrases()} puts each phrase's built-in English into a
     *         map: {@code phrases.put(Phrase.HELP_HEADER, "{0} Help")}
     */
    static byte[] languageClass(List<Map.Entry<String, String>> defaults) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, LANGUAGE, null, "java/lang/Object", null);
        String map = "java/util/concurrent/ConcurrentHashMap";
        writer.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "phrases", "L" + map + ";", null, null).visitEnd();
        MethodVisitor load = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "loadPhrases", "()V", null,
            null);
        load.visitCode();
        for (Map.Entry<String, String> phrase : defaults) {
            load.visitFieldInsn(Opcodes.GETSTATIC, LANGUAGE, "phrases", "L" + map + ";");
            load.visitFieldInsn(Opcodes.GETSTATIC, PHRASE, phrase.getKey(), "L" + PHRASE + ";");
            load.visitLdcInsn(phrase.getValue());
            load.visitMethodInsn(Opcodes.INVOKEVIRTUAL, map, "put",
                "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", false);
            load.visitInsn(Opcodes.POP);
        }
        load.visitInsn(Opcodes.RETURN);
        load.visitMaxs(0, 0);
        load.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    /**
     * @param output whether to print the message with {@code CommandSender.sendMessage(String)}
     */
    static byte[] chatClass(boolean output) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, CHAT, null, "java/lang/Object", null);
        MethodVisitor send = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "noPermission",
            "(Lorg/bukkit/command/CommandSender;)Ljava/lang/String;", null, null);
        send.visitCode();
        send.visitLdcInsn("CoreProtect - ");
        send.visitInsn(Opcodes.ACONST_NULL);
        send.visitInsn(Opcodes.ICONST_0);
        send.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/String");
        send.visitMethodInsn(Opcodes.INVOKESTATIC, PHRASE, "build",
            "(L" + PHRASE + ";[Ljava/lang/String;)Ljava/lang/String;", false);
        send.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "concat",
            "(Ljava/lang/String;)Ljava/lang/String;", false);
        if (output) {
            send.visitInsn(Opcodes.DUP);
            send.visitVarInsn(Opcodes.ALOAD, 0);
            send.visitInsn(Opcodes.SWAP);
            send.visitMethodInsn(Opcodes.INVOKEINTERFACE, "org/bukkit/command/CommandSender", "sendMessage",
                "(Ljava/lang/String;)V", true);
        }
        send.visitInsn(Opcodes.ARETURN);
        send.visitMaxs(0, 0);
        send.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    static byte[] plainClass(String name) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, name, null, "java/lang/Object", null);
        writer.visitEnd();
        return writer.toByteArray();
    }
}
