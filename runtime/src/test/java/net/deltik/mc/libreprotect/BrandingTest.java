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

package net.deltik.mc.libreprotect;

import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BrandingTest {

    /** Stands in for CoreProtect's phrase enum, which Branding only knows by constant name */
    enum Phrase {
        STATUS_LICENSE, INVALID_DONATION_KEY, VALID_DONATION_KEY, LINK_PATREON, LINK_DISCORD, LINK_DOWNLOAD,
        ENJOY_COREPROTECT, STATUS_VERSION, HELP_HEADER, ENABLE_SUCCESS, NO_PERMISSION, PATCH_OUTDATED_2
    }

    private static final String WHITE = ChatColor.WHITE.toString();

    @Nested
    @DisplayName("phrase()")
    class Phrases {

        @Test
        @DisplayName("marks donation-key and Patreon lines to be left out")
        void dropsDonationLines() {
            for (Phrase phrase : List.of(Phrase.STATUS_LICENSE, Phrase.INVALID_DONATION_KEY,
                Phrase.VALID_DONATION_KEY, Phrase.LINK_PATREON)) {
                String result = Branding.phrase(phrase, new String[] {WHITE, "x"}, "License: x");
                assertTrue(Branding.isDropped(result), phrase.name());
                assertTrue(Branding.isDropped("\u00A73" + result + "\u00A77 (Please check config.yml)"), phrase.name());
            }
        }

        @Test
        @DisplayName("points upstream's Discord and download links to LibreProtect, keeping the value color")
        void replacesLinks() {
            assertEquals("Website:" + WHITE + " " + PrivacyConstants.FORK_DISPLAY_URL,
                Branding.phrase(Phrase.LINK_DISCORD, new String[] {WHITE, "www.coreprotect.net/discord/"},
                    "Discord:" + WHITE + " www.coreprotect.net/discord/"));
            assertEquals("Website: " + PrivacyConstants.FORK_DISPLAY_URL,
                Branding.phrase(Phrase.LINK_DISCORD, new String[] {"www.coreprotect.net/discord/"},
                    "Discord: www.coreprotect.net/discord/"));
            assertEquals("Download: " + PrivacyConstants.FORK_DISPLAY_URL + "/releases",
                Branding.phrase(Phrase.LINK_DOWNLOAD, new String[] {"www.coreprotect.net/download/"},
                    "Download: www.coreprotect.net/download/"));
        }

        @Test
        @DisplayName("keeps the translated label of the download link, but not of the Discord link")
        void translatedLinks() {
            String releases = PrivacyConstants.FORK_DISPLAY_URL + "/releases";
            assertEquals("Herunterladen: " + releases,
                Branding.phrase(Phrase.LINK_DOWNLOAD, new String[] {"www.coreprotect.net/download/"},
                    "Herunterladen: www.coreprotect.net/download/"));
            assertEquals("Herunterladen:" + WHITE + " " + releases,
                Branding.phrase(Phrase.LINK_DOWNLOAD, new String[] {WHITE, "www.coreprotect.net/latest/"},
                    "Herunterladen:" + WHITE + " www.coreprotect.net/latest/"));
            assertEquals("下载：" + WHITE + releases,
                Branding.phrase(Phrase.LINK_DOWNLOAD, new String[] {WHITE, "www.coreprotect.net/download/"},
                    "下载：" + WHITE + "www.coreprotect.net/download/"));
            assertEquals("Website:" + WHITE + " " + PrivacyConstants.FORK_DISPLAY_URL,
                Branding.phrase(Phrase.LINK_DISCORD, new String[] {WHITE, "www.coreprotect.net/discord/"},
                    "Discord:" + WHITE + " www.coreprotect.net/discord/"));
        }

        @Test
        @DisplayName("falls back to the English download label when the rendering doesn't show the link")
        void downloadWithoutLink() {
            String releases = PrivacyConstants.FORK_DISPLAY_URL + "/releases";
            assertEquals("Download:" + WHITE + " " + releases,
                Branding.phrase(Phrase.LINK_DOWNLOAD, new String[] {WHITE, "www.coreprotect.net/download/"},
                    "Herunterladen:" + WHITE + " (Link fehlt)"));
            assertEquals("Download: " + releases, Branding.phrase(Phrase.LINK_DOWNLOAD, null, "Herunterladen: x"));
            assertEquals("Download: " + releases, Branding.phrase(Phrase.LINK_DOWNLOAD, new String[] {""}, "x"));
            assertEquals("Download:" + WHITE + " " + releases,
                Branding.phrase(Phrase.LINK_DOWNLOAD, new String[] {WHITE}, "Herunterladen:" + WHITE + " x"));
        }

        @Test
        @DisplayName("replaces the Discord invitation with an introduction that credits CoreProtect")
        void introduces() {
            String result = Branding.phrase(Phrase.ENJOY_COREPROTECT, new String[] {"CoreProtect"},
                "Enjoy CoreProtect? Join our Discord!");
            assertEquals("LibreProtect is a privacy-hardened build of CoreProtect by Intelli.", result);
        }

        @Test
        @DisplayName("names LibreProtect where the plugin names itself")
        void selfNaming() {
            assertEquals("Version:" + WHITE + " LibreProtect v24.1-libre1.",
                Branding.phrase(Phrase.STATUS_VERSION, new String[] {WHITE, "CoreProtect v24.1-libre1."},
                    "Version:" + WHITE + " CoreProtect v24.1-libre1."));
            assertEquals("LibreProtect Help",
                Branding.phrase(Phrase.HELP_HEADER, new String[] {"CoreProtect"}, "CoreProtect Help"));
            assertEquals("LibreProtect has been successfully enabled!",
                Branding.phrase(Phrase.ENABLE_SUCCESS, new String[] {"CoreProtect"},
                    "CoreProtect has been successfully enabled!"));
        }

        @Test
        @DisplayName("leaves other phrases alone, including ones that refer to CoreProtect itself")
        void leavesOthersAlone() {
            assertEquals("You do not have permission to do that.",
                Branding.phrase(Phrase.NO_PERMISSION, new String[0], "You do not have permission to do that."));
            assertEquals("Please upgrade with a supported version of CoreProtect.",
                Branding.phrase(Phrase.PATCH_OUTDATED_2, new String[0],
                    "Please upgrade with a supported version of CoreProtect."));
        }

        @Test
        @DisplayName("never throws, whatever it is given")
        void tolerant() {
            assertNull(Branding.phrase(Phrase.STATUS_VERSION, null, null));
            assertEquals("x", Branding.phrase(null, null, "x"));
            assertEquals("Website: " + PrivacyConstants.FORK_DISPLAY_URL,
                Branding.phrase(Phrase.LINK_DISCORD, null, "Discord: x"));
            assertEquals("Website: " + PrivacyConstants.FORK_DISPLAY_URL,
                Branding.phrase(Phrase.LINK_DISCORD, new String[] {null}, "Discord: x"));
        }
    }

    @Nested
    @DisplayName("Output")
    class Output {

        @Test
        @DisplayName("sendMessage() delivers messages and leaves out dropped ones")
        void sendMessage() {
            List<String> received = new ArrayList<>();
            CommandSender sender = (CommandSender) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[] {CommandSender.class}, (proxy, method, args) -> {
                    if (method.getName().equals("sendMessage") && method.getParameterCount() == 1
                        && method.getParameterTypes()[0] == String.class) {
                        received.add((String) args[0]);
                    }
                    return null;
                });

            Branding.sendMessage(sender, "kept");
            Branding.sendMessage(sender, "License: x" + Branding.DROP + " (Please check config.yml)");
            Branding.sendMessage(sender, null);
            assertEquals(Arrays.asList("kept", null), received);
        }

        @Test
        @DisplayName("logging methods deliver messages and leave out dropped ones")
        void log() {
            TestLogger logger = new TestLogger();
            String dropped = "[LibreProtect] Invalid donation key." + Branding.DROP;

            Branding.log(logger, Level.INFO, "a");
            Branding.log(logger, Level.INFO, dropped);
            Branding.info(logger, "b");
            Branding.info(logger, dropped);
            Branding.warning(logger, "c");
            Branding.warning(logger, dropped);
            Branding.severe(logger, "d");
            Branding.severe(logger, dropped);
            assertEquals(List.of("a", "b", "c", "d"), logger.getMessages());
        }

        @Test
        @DisplayName("text written by players can't hide a message")
        void notForgeable() {
            assertFalse(Branding.isDropped("\uFDD0\uFDD1 player text"));
            assertTrue(Branding.DROP.length() > 32);
        }
    }

    /**
     * The transformer redirects {@code sendMessage(String)} on any Bukkit
     * interface to {@link Branding#sendMessage(CommandSender, String)}, which
     * is only safe while every such interface is a {@link CommandSender}.
     */
    @Test
    @DisplayName("every Bukkit interface with sendMessage(String) is a CommandSender")
    void bukkitSendMessageOwners() throws Exception {
        Path api = Path.of(CommandSender.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        List<String> checked = new ArrayList<>();
        try (ZipFile jar = new ZipFile(api.toFile())) {
            Enumeration<? extends ZipEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                String name = entries.nextElement().getName();
                if (!name.startsWith("org/bukkit/") || !name.endsWith(".class")) {
                    continue;
                }
                Class<?> type = load(name.substring(0, name.length() - 6).replace('/', '.'));
                if (type == null || !type.isInterface()) {
                    continue;
                }
                for (Method method : type.getDeclaredMethods()) {
                    if (method.getName().equals("sendMessage") && method.getParameterCount() == 1
                        && method.getParameterTypes()[0] == String.class) {
                        assertTrue(CommandSender.class.isAssignableFrom(type), type.getName());
                        checked.add(type.getName());
                    }
                }
            }
        } catch (IOException e) {
            throw new AssertionError(e);
        }
        assertTrue(checked.contains(CommandSender.class.getName()), checked.toString());
    }

    private static Class<?> load(String name) {
        try {
            return Class.forName(name, false, BrandingTest.class.getClassLoader());
        } catch (ClassNotFoundException | LinkageError e) {
            return null;
        }
    }
}
