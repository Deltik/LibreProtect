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

package net.deltik.mc.libreprotect.routing;

import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.net.URL;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

class UrlNormalizerTest {

    private static String normalize(String spec) {
        return UrlNormalizer.normalize(MockUrlFactory.createUrl(spec));
    }

    @Nested
    @DisplayName("Case")
    class Case {

        @Test
        @DisplayName("should lowercase the scheme and host")
        void lowercasesSchemeAndHost() {
            assertEquals("https://stats.coreprotect.net/submit", normalize("HTTPS://Stats.CoreProtect.NET/submit"));
        }

        @Test
        @DisplayName("should lowercase bStats.org as bStats spells it")
        void lowercasesBstats() {
            assertEquals("https://bstats.org/api/v2/data/bukkit", normalize("https://bStats.org/api/v2/data/bukkit"));
        }

        @Test
        @DisplayName("should keep the case of the path")
        void keepsPathCase() {
            assertEquals("https://example.com/License/ABCdef", normalize("https://EXAMPLE.com/License/ABCdef"));
        }

        @Test
        @DisplayName("should keep the case of the query")
        void keepsQueryCase() {
            assertEquals("https://example.com/p?Key=Value&b=C", normalize("https://Example.com/p?Key=Value&b=C"));
        }

        @Test
        @DisplayName("should not depend on the default locale")
        void localeIndependent() {
            Locale original = Locale.getDefault();
            try {
                // In Turkish, "I".toLowerCase() is a dotless i
                Locale.setDefault(Locale.forLanguageTag("tr-TR"));
                assertEquals("https://github.io/INDEX", normalize("HTTPS://GITHUB.IO/INDEX"));
            } finally {
                Locale.setDefault(original);
            }
        }
    }

    @Nested
    @DisplayName("Removed components")
    class Removed {

        @Test
        @DisplayName("should drop user info")
        void dropsUserInfo() {
            assertEquals("https://example.com/x", normalize("https://user:secret@example.com/x"));
        }

        @Test
        @DisplayName("should drop a user name without password")
        void dropsUserName() {
            assertEquals("http://example.com/x", normalize("http://user@example.com/x"));
        }

        @Test
        @DisplayName("should drop the fragment")
        void dropsFragment() {
            assertEquals("https://example.com/x?q=1", normalize("https://example.com/x?q=1#section"));
        }

        @Test
        @DisplayName("should drop user info and fragment together")
        void dropsBoth() {
            assertEquals("https://example.com/x", normalize("https://u:p@Example.COM/x#f"));
        }
    }

    @Nested
    @DisplayName("Preserved components")
    class Preserved {

        @ParameterizedTest
        @DisplayName("should leave already normalized URLs unchanged")
        @CsvSource({
            "http://update.coreprotect.net/version/",
            "https://coreprotect.net/license/TESTKEY",
            "http://coreprotect.net/translate/",
            "https://example.com/path?query=Value",
            "http://example.com:8080/x",
            "https://example.com"
        })
        void idempotent(String spec) {
            assertEquals(spec, normalize(spec));
            assertEquals(normalize(spec), normalize(normalize(spec)));
        }

        @Test
        @DisplayName("should keep an explicit port")
        void keepsPort() {
            assertEquals("http://example.com:8080/x", normalize("http://Example.com:8080/x"));
        }

        @Test
        @DisplayName("should not add the default port")
        void doesNotAddDefaultPort() {
            assertEquals("https://example.com/x", normalize("https://example.com/x"));
        }

        @Test
        @DisplayName("should keep an IPv6 host in brackets")
        void keepsIpv6() {
            assertEquals("http://[::1]:8080/x?y", normalize("http://[::1]:8080/x?y#z"));
        }

        @Test
        @DisplayName("should produce an empty path when the URL has none")
        void emptyPath() {
            assertEquals("https://example.com", normalize("https://example.com"));
        }

        @Test
        @DisplayName("should give file: URLs an empty authority")
        void fileUrl() {
            assertEquals("file:///tmp/Data.txt", normalize("file:/tmp/Data.txt"));
            assertEquals("file:///tmp/Data.txt", normalize("file:///tmp/Data.txt"));
        }
    }

    @Test
    @DisplayName("should produce strings that the preset patterns match")
    void matchesPresetPatterns() {
        URL url = MockUrlFactory.createUrl("HTTPS://user:pw@Update.CoreProtect.net/version/#x");
        String normalized = UrlNormalizer.normalize(url);

        assertEquals("https://update.coreprotect.net/version/", normalized);
        assertTrue(normalized.matches(RoutePreset.UPDATE), normalized);
    }
}
