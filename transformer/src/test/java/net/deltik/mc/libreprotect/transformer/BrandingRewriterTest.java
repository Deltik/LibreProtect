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

import net.deltik.mc.libreprotect.transformer.fixture.BrandingFixture;
import org.bukkit.command.CommandSender;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BrandingRewriterTest {

    private static final String AQUA = "\u00A73";
    private static final String WHITE = "\u00A7f";
    private static final String FIXTURE = BrandingFixture.class.getName();
    private static final String PHRASE = BrandingFixture.Phrase.class.getName();

    private static final List<TransformReport.BrandingSite> SITES = new ArrayList<>();
    private static final Map<String, byte[]> REWRITTEN = new HashMap<>();
    private static Class<?> fixture;
    private static List<String> renderers;

    @BeforeAll
    static void rewrite() throws Exception {
        renderers = BrandingRules.phraseRenderers(TestClasses.bytesOf(BrandingFixture.Phrase.class));
        for (Class<?> type : List.of(BrandingFixture.class, BrandingFixture.Phrase.class)) {
            ClassReader reader = new ClassReader(TestClasses.bytesOf(type));
            ClassWriter writer = new ClassWriter(0);
            reader.accept(new BrandingRewriter(writer, type.getName() + ".class", Set.copyOf(renderers), SITES), 0);
            REWRITTEN.put(type.getName(), writer.toByteArray());
        }
        ClassLoader loader = new ClassLoader(BrandingRewriterTest.class.getClassLoader()) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                synchronized (getClassLoadingLock(name)) {
                    Class<?> loaded = findLoadedClass(name);
                    if (loaded == null && REWRITTEN.containsKey(name)) {
                        byte[] bytes = REWRITTEN.get(name);
                        loaded = defineClass(name, bytes, 0, bytes.length);
                    }
                    return loaded != null ? loaded : super.loadClass(name, resolve);
                }
            }
        };
        fixture = loader.loadClass(FIXTURE);
    }

    private static Object invoke(String name, Object... arguments) throws Throwable {
        for (Method method : fixture.getMethods()) {
            if (method.getName().equals(name)) {
                try {
                    return method.invoke(null, arguments);
                } catch (InvocationTargetException e) {
                    throw e.getCause();
                }
            }
        }
        throw new NoSuchMethodException(name);
    }

    private static List<String> messagesFrom(String method, Object... arguments) throws Throwable {
        List<String> messages = new ArrayList<>();
        CommandSender sender = (CommandSender) Proxy.newProxyInstance(BrandingRewriterTest.class.getClassLoader(),
            new Class<?>[] {CommandSender.class}, (proxy, called, args) -> {
                if (called.getName().equals("sendMessage") && called.getParameterTypes()[0] == String.class) {
                    messages.add((String) args[0]);
                }
                return null;
            });
        Object[] all = new Object[arguments.length + 1];
        all[0] = sender;
        System.arraycopy(arguments, 0, all, 1, arguments.length);
        invoke(method, all);
        return messages;
    }

    @Nested
    @DisplayName("Rewriting")
    class Rewriting {

        @Test
        @DisplayName("finds the phrase renderer by its shape")
        void findsRenderer() {
            String phrase = PHRASE.replace('.', '/');
            assertEquals(List.of(phrase + ".build(L" + phrase + ";[Ljava/lang/String;)Ljava/lang/String;"), renderers);
            assertEquals(List.of(), BrandingRules.phraseRenderers(TestClasses.bytesOf(BrandingFixture.class)));
        }

        @Test
        @DisplayName("hooks every phrase rendering and message output")
        void recordsHooks() {
            assertEquals(6, SITES.stream().filter(site -> site.kind().equals(BrandingRewriter.KIND_PHRASE)).count());
            assertEquals(7, SITES.stream().filter(site -> site.kind().equals(BrandingRewriter.KIND_OUTPUT)).count());
        }

        @Test
        @DisplayName("records each rebranded text")
        void recordsText() {
            List<String> texts = SITES.stream().filter(site -> site.kind().equals(BrandingRewriter.KIND_TEXT))
                .map(site -> site.member() + ": " + site.after()).toList();
            assertEquals(4, texts.size(), texts.toString());
            assertTrue(texts.contains("CONSOLE_PREFIX: [LibreProtect] "), texts.toString());
        }

        @Test
        @DisplayName("produces bytecode that passes verification")
        void verifies() {
            REWRITTEN.values().forEach(bytes -> TestClasses.verify(bytes, true));
        }
    }

    @Nested
    @DisplayName("Rewritten code")
    class RewrittenCode {

        @Test
        @DisplayName("shows /co status as LibreProtect, without the donation-key line")
        void status() throws Throwable {
            assertEquals(List.of(
                    WHITE + "----- " + AQUA + "LibreProtect" + WHITE + " -----",
                    AQUA + "Version:" + WHITE + " LibreProtect v24.1-libre1.",
                    AQUA + "Website:" + WHITE + " github.com/Deltik/LibreProtect"),
                messagesFrom("status", "24.1-libre1"));
        }

        @Test
        @DisplayName("uses LibreProtect's chat prefix")
        void chatPrefix() throws Throwable {
            assertEquals(List.of(AQUA + "LibreProtect " + WHITE + "- You do not have permission to do that."),
                messagesFrom("noPermission"));
        }

        @Test
        @DisplayName("uses LibreProtect's console prefix and leaves out dropped lines")
        void console() throws Throwable {
            Logger logger = Logger.getAnonymousLogger();
            logger.setUseParentHandlers(false);
            List<String> logged = new ArrayList<>();
            logger.addHandler(new Handler() {
                @Override
                public void publish(LogRecord record) {
                    logged.add(record.getMessage());
                }

                @Override
                public void flush() {
                }

                @Override
                public void close() {
                }
            });
            invoke("console", logger, "hello");
            assertEquals(List.of("[LibreProtect] hello"), logged);
        }

        @Test
        @DisplayName("leaves uses of the name that aren't display text alone")
        void functional() throws Throwable {
            assertArrayEquals(new String[] {"CoreProtect", "plugins/CoreProtect/", "CoreProtect/v1 (by Intelli)",
                "# CoreProtect v1 Language Cache"}, (String[]) invoke("functional", "1"));
        }
    }

    @Test
    @DisplayName("rebrands only display shapes of the name")
    void textRules() {
        // Real constants from CoreProtect v24.1, where \u0001 stands for a concatenated value
        Map<String, String> expected = new LinkedHashMap<>();
        expected.put("\u0001CoreProtect \u0001- \u0001",
            "\u0001LibreProtect \u0001- \u0001");
        expected.put("\u0001CoreProtect \u0001\u00A7o- \u0001",
            "\u0001LibreProtect \u0001\u00A7o- \u0001");
        expected.put("\u0001CoreProtect \u0001- \u00A7o\u0001",
            "\u0001LibreProtect \u0001- \u00A7o\u0001");
        expected.put("\u0001----- \u0001CoreProtect\u0001\u0001 -----",
            "\u0001----- \u0001LibreProtect\u0001\u0001 -----");
        expected.put("\u0001----- \u0001CoreProtect \u0001----- \u0001",
            "\u0001----- \u0001LibreProtect \u0001----- \u0001");
        expected.put("\u00A7r[CoreProtect] \u0001<COMPONENT>POPUP| | </COMPONENT>",
            "\u00A7r[LibreProtect] \u0001<COMPONENT>POPUP| | </COMPONENT>");
        expected.put("\u0001[CoreProtect] \u0001\u0001",
            "\u0001[LibreProtect] \u0001\u0001");
        expected.put("CoreProtect\u0001 | \u0001",
            "LibreProtect\u0001 | \u0001");
        expected.put("\u0001CoreProtect",
            "\u0001LibreProtect");
        expected.put("CoreProtect",
            "CoreProtect");
        expected.put("plugins/CoreProtect/",
            "plugins/CoreProtect/");
        expected.put("CoreProtect/v\u0001 (by Intelli)",
            "CoreProtect/v\u0001 (by Intelli)");
        expected.put("CoreProtect v\u0001",
            "CoreProtect v\u0001");
        expected.put("CoreProtect_\u0001",
            "CoreProtect_\u0001");
        expected.put("# CoreProtect v\u0001 Language Cache (\u0001)",
            "# CoreProtect v\u0001 Language Cache (\u0001)");
        expected.put("# CoreProtect is donationware. Obtain a donation key from coreprotect.net/donate/",
            "# CoreProtect is donationware. Obtain a donation key from coreprotect.net/donate/");
        expected.put("Please upgrade with a supported version of CoreProtect.",
            "Please upgrade with a supported version of CoreProtect.");
        expected.put("CoreProtect Error Reporter",
            "CoreProtect Error Reporter");
        assertAll(expected.entrySet().stream().map(entry ->
            () -> assertEquals(entry.getValue(), BrandingRules.rebrand(entry.getKey()), entry.getKey())));
    }

    @Test
    @DisplayName("returns the same instance when nothing changes")
    void sameInstance() {
        String text = "plugins/CoreProtect/";
        assertSame(text, BrandingRules.rebrand(text));
    }
}
