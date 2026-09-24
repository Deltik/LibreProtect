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

package net.deltik.mc.libreprotect.update;

import net.deltik.mc.libreprotect.Branding;
import org.bukkit.ChatColor;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

class UpdatePhrasesTest {

    /** Stands in for CoreProtect's phrase enum, which is only known by constant name */
    enum Phrase {
        VERSION_NOTICE, LATEST_VERSION, UPDATE_NOTICE, LINK_DOWNLOAD, UPDATE_HEADER, LINK_DISCORD, STATUS_VERSION
    }

    private static final String WHITE = ChatColor.WHITE.toString();
    private static final String MODRINTH_PAGE = "https://modrinth.com/plugin/libreprotect/version/24.1-libre2";

    @BeforeEach
    void knowRelease() {
        UpdateStatus.set(new Release(ForkVersion.parse("24.1-libre2"), MODRINTH_PAGE), "24.1.1");
    }

    @AfterEach
    void clearStatus() {
        UpdateStatus.reset();
    }

    /**
     * Render like CoreProtect's {@code Phrase.build}: substitute the
     * parameters that aren't colors, then color the text after the first
     * colon (half- or full-width) with a leading color parameter.
     */
    private static String render(String template, String... params) {
        String output = template;
        String color = "";
        int index = 0;
        for (String param : params) {
            if (index == 0 && param.equals(WHITE)) {
                color = param;
                continue;
            }
            output = output.replace("{" + index + "}", param);
            index++;
        }
        if (!color.isEmpty()) {
            output = output.replaceFirst(":", ":" + color).replaceFirst("：", "：" + color);
        }
        return output;
    }

    private static String brand(Phrase phrase, String template, String... params) {
        return Branding.phrase(phrase, params, render(template, params));
    }

    @Nested
    @DisplayName("With a newer release")
    class WithRelease {

        @ParameterizedTest
        @DisplayName("the startup notice should show the release instead of the synthetic version")
        @CsvSource(delimiter = '|', value = {
            "Version {0} is now available.   | Version 24.1-libre2 is now available.",
            "Version {0} ist nun verfügbar.  | Version 24.1-libre2 ist nun verfügbar.",
            "版本 {0} 现在可用。             | 版本 24.1-libre2 现在可用。"
        })
        void versionNotice(String template, String expected) {
            assertEquals(expected, brand(Phrase.VERSION_NOTICE, template.strip(), "24.1.1"));
        }

        @ParameterizedTest
        @DisplayName("/co status should show the release as the latest version")
        @CsvSource(delimiter = '|', value = {
            "Latest Version: {0}  | Latest Version: v24.1-libre2",
            "Neueste Version: {0} | Neueste Version: v24.1-libre2",
            "最新版本：{0}        | 最新版本：v24.1-libre2"
        })
        void latestVersion(String template, String expected) {
            assertEquals(expected, brand(Phrase.LATEST_VERSION, template.strip(), "v24.1.1"));
        }

        @ParameterizedTest
        @DisplayName("the operators' notice should name LibreProtect and the release")
        @CsvSource(delimiter = '|', value = {
            "Notice: {0} is now available.   | CoreProtect CE v24.1.1 | Notice:§f LibreProtect v24.1-libre2 is now available.",
            "Notice: {0} is now available.   | CoreProtect v24.1.1    | Notice:§f LibreProtect v24.1-libre2 is now available.",
            "Hinweis: {0} ist nun verfügbar. | CoreProtect CE v24.1.1 | Hinweis:§f LibreProtect v24.1-libre2 ist nun verfügbar."
        })
        void updateNotice(String template, String param, String expected) {
            assertEquals(expected, brand(Phrase.UPDATE_NOTICE, template.strip(), WHITE, param.strip()));
        }

        @ParameterizedTest
        @DisplayName("the download link should keep its label and point to the release page")
        @CsvSource(delimiter = '|', value = {
            "Download: {0}      | Download: modrinth.com/plugin/libreprotect/version/24.1-libre2",
            "Herunterladen: {0} | Herunterladen: modrinth.com/plugin/libreprotect/version/24.1-libre2",
            "下载：{0}          | 下载：modrinth.com/plugin/libreprotect/version/24.1-libre2"
        })
        void downloadLink(String template, String expected) {
            assertEquals(expected, brand(Phrase.LINK_DOWNLOAD, template.strip(), "www.coreprotect.net/download/"));
        }

        @Test
        @DisplayName("the download link should keep the value color of the operators' notice")
        void downloadLinkColor() {
            assertEquals("Download:" + WHITE + " modrinth.com/plugin/libreprotect/version/24.1-libre2",
                brand(Phrase.LINK_DOWNLOAD, "Download: {0}", WHITE, "www.coreprotect.net/download/"));
            assertEquals("Download:" + WHITE + " modrinth.com/plugin/libreprotect/version/24.1-libre2",
                brand(Phrase.LINK_DOWNLOAD, "Download: {0}", WHITE, "www.coreprotect.net/latest/"));
        }

        @Test
        @DisplayName("a GitHub release page should be shown without its scheme")
        void githubPage() {
            UpdateStatus.set(new Release(ForkVersion.parse("24.1-libre2"),
                "https://github.com/Deltik/LibreProtect/releases/tag/v24.1-libre2"), "24.1.1");

            assertEquals("Download: github.com/Deltik/LibreProtect/releases/tag/v24.1-libre2",
                brand(Phrase.LINK_DOWNLOAD, "Download: {0}", "www.coreprotect.net/download/"));
        }

        @Test
        @DisplayName("a release of a newer upstream version should replace its upstream version")
        void newerUpstream() {
            UpdateStatus.set(new Release(ForkVersion.parse("25.0-libre1"),
                "https://modrinth.com/plugin/libreprotect/version/25.0-libre1"), "25.0");

            assertEquals("Version 25.0-libre1 is now available.",
                brand(Phrase.VERSION_NOTICE, "Version {0} is now available.", "25.0"));
            assertEquals("Latest Version: v25.0-libre1", brand(Phrase.LATEST_VERSION, "Latest Version: {0}", "v25.0"));
        }

        @Test
        @DisplayName("versions other than the synthetic one should stay as they are")
        void otherVersions() {
            assertEquals("Version 24.2 is now available.",
                brand(Phrase.VERSION_NOTICE, "Version {0} is now available.", "24.2"));
            assertEquals("Latest Version: v24.1.12", brand(Phrase.LATEST_VERSION, "Latest Version: {0}", "v24.1.12"));
            assertEquals("Notice:" + WHITE + " CoreProtect CE v24.1.10 is now available.",
                brand(Phrase.UPDATE_NOTICE, "Notice: {0} is now available.", WHITE, "CoreProtect CE v24.1.10"));
        }

        @Test
        @DisplayName("other phrases should be left to the other branding rules")
        void otherPhrases() {
            assertNull(UpdatePhrases.rewrite("UPDATE_HEADER", new String[] {"CoreProtect"}, "CoreProtect Update"));
            assertEquals("LibreProtect Update", brand(Phrase.UPDATE_HEADER, "{0} Update", "CoreProtect"));
            assertEquals("Website: github.com/Deltik/LibreProtect",
                brand(Phrase.LINK_DISCORD, "Discord: {0}", "www.coreprotect.net/discord/"));
            assertEquals("Version: LibreProtect v24.1-libre1.",
                brand(Phrase.STATUS_VERSION, "Version: {0}", "CoreProtect v24.1-libre1."));
        }

        @Test
        @DisplayName("should never throw, whatever it is given")
        void tolerant() {
            assertNull(UpdatePhrases.rewrite(null, new String[0], "x"));
            assertNull(UpdatePhrases.rewrite("VERSION_NOTICE", null, "x"));
            assertNull(UpdatePhrases.rewrite("VERSION_NOTICE", new String[] {"24.1.1"}, null));
            assertNull(UpdatePhrases.rewrite("VERSION_NOTICE", new String[] {null}, "x"));
            assertNull(UpdatePhrases.rewrite("LINK_DOWNLOAD", new String[] {null, ""}, "Download: "));
            assertNull(UpdatePhrases.rewrite("VERSION_NOTICE", new String[] {"24.1.1"}, "Customized without it"));
        }
    }

    @Nested
    @DisplayName("After later checks")
    class AfterLaterChecks {

        private void report(String version, String synthetic) {
            UpdateStatus.set(new Release(ForkVersion.parse(version),
                "https://modrinth.com/plugin/libreprotect/version/" + version), synthetic);
        }

        @Test
        @DisplayName("a synthetic version should still show its release after a later check found nothing newer")
        void afterNothingNewer() {
            report("24.2-libre1", "24.2");
            UpdateStatus.clear();

            assertNull(UpdateStatus.current());
            assertEquals("Version 24.2-libre1 is now available.",
                brand(Phrase.VERSION_NOTICE, "Version {0} is now available.", "24.2"));
            assertEquals("Notice:" + WHITE + " LibreProtect v24.2-libre1 is now available.",
                brand(Phrase.UPDATE_NOTICE, "Notice: {0} is now available.", WHITE, "CoreProtect CE v24.2"));
            assertEquals("Download:" + WHITE + " modrinth.com/plugin/libreprotect/version/24.2-libre1",
                brand(Phrase.LINK_DOWNLOAD, "Download: {0}", WHITE, "www.coreprotect.net/download/"));
        }

        @Test
        @DisplayName("each synthetic version should show its own release after a later check reported another")
        void afterAnotherRelease() {
            report("25.0-libre1", "25.0");
            report("24.2-libre1", "24.2");

            assertEquals("Latest Version: v25.0-libre1", brand(Phrase.LATEST_VERSION, "Latest Version: {0}", "v25.0"));
            assertEquals("Latest Version: v24.2-libre1", brand(Phrase.LATEST_VERSION, "Latest Version: {0}", "v24.2"));
            assertEquals("Download: modrinth.com/plugin/libreprotect/version/24.2-libre1",
                brand(Phrase.LINK_DOWNLOAD, "Download: {0}", "www.coreprotect.net/download/"));
        }

        @Test
        @DisplayName("a synthetic version reported again should show the newer release")
        void reportedAgain() {
            report("24.1-libre3", "24.1.1");

            assertEquals("Version 24.1-libre3 is now available.",
                brand(Phrase.VERSION_NOTICE, "Version {0} is now available.", "24.1.1"));
        }

        @Test
        @DisplayName("only the last few synthetic versions should be remembered")
        void bounded() {
            // With 24.1.1, reported before each test, these fill the history
            for (int minor = 2; minor < 1 + UpdateStatus.HISTORY; minor++) {
                report("24." + minor + "-libre1", "24." + minor);
            }
            assertEquals("Latest Version: v24.1-libre2", brand(Phrase.LATEST_VERSION, "Latest Version: {0}", "v24.1.1"));

            report("25.0-libre1", "25.0");

            assertEquals("Latest Version: v24.1.1", brand(Phrase.LATEST_VERSION, "Latest Version: {0}", "v24.1.1"));
            assertEquals("Latest Version: v24.2-libre1", brand(Phrase.LATEST_VERSION, "Latest Version: {0}", "v24.2"));
            assertEquals("Latest Version: v25.0-libre1", brand(Phrase.LATEST_VERSION, "Latest Version: {0}", "v25.0"));
        }
    }

    @Nested
    @DisplayName("Without a newer release")
    class WithoutRelease {

        @BeforeEach
        void forgetRelease() {
            UpdateStatus.reset();
        }

        @Test
        @DisplayName("should leave every phrase to the other branding rules")
        void leavesAlone() {
            for (Phrase phrase : Phrase.values()) {
                assertNull(UpdatePhrases.rewrite(phrase.name(), new String[] {"24.1.1"}, "Version 24.1.1"), phrase.name());
            }
            assertEquals("Download: github.com/Deltik/LibreProtect/releases",
                brand(Phrase.LINK_DOWNLOAD, "Download: {0}", "www.coreprotect.net/download/"));
            assertEquals("Version 24.2 is now available.",
                brand(Phrase.VERSION_NOTICE, "Version {0} is now available.", "24.2"));
        }
    }
}
