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

package net.deltik.mc.libreprotect.update;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class ForkVersionTest {

    private static ForkVersion version(String text) {
        ForkVersion version = ForkVersion.parse(text);
        assertNotNull(version, text);
        return version;
    }

    /** {@code 24.1} as {@code [24, 1]} */
    private static int[] numbers(String upstream) {
        return Arrays.stream(upstream.split("\\.")).mapToInt(Integer::parseInt).toArray();
    }

    @Nested
    @DisplayName("parse")
    class Parse {

        @ParameterizedTest
        @DisplayName("should parse releases")
        @CsvSource({
            "24.1-libre1, 24.1",
            "24.1-libre12, 24.1",
            "24.1.3-libre2, 24.1.3",
            "25.0-libre1, 25.0",
            "024.01-libre1, 24.1"
        })
        void releases(String text, String upstream) {
            ForkVersion version = version(text);
            assertTrue(version.isRelease());
            assertEquals(upstream, version.upstream());
            assertEquals(text, version.toString());
            assertEquals(version, ForkVersion.parseRelease(text));
        }

        @ParameterizedTest
        @DisplayName("should parse development builds, which aren't releases")
        @CsvSource({
            "24.0-121-gd5cad31-libre-dev, 24.0",
            "24.1-0-g0af209a-libre-dev, 24.1",
            "24.0-121-gd5cad31-dirty-libre-dev, 24.0",
            "24.0-121-gd5cad31a-libre-dev, 24.0",
            "24.1.2-3-g0123456789abcdef0123456789abcdef01234567-libre-dev, 24.1.2"
        })
        void devBuilds(String text, String upstream) {
            ForkVersion version = version(text);
            assertFalse(version.isRelease());
            assertEquals(upstream, version.upstream());
            assertEquals(text, version.toString());
            assertNull(ForkVersion.parseRelease(text));
        }

        @ParameterizedTest
        @DisplayName("should reject anything else")
        @NullAndEmptySource
        @ValueSource(strings = {
            "24.1", "24.1.2.3-libre1", "v24.1-libre1", "24.1-libre", "24.1-libre-1", "24.1-LIBRE1",
            "24.1-libre1-extra", " 24.1-libre1", "24.1-libre1\n", "24.1-libre1§c", "unknown",
            "1234567890.1-libre1", "24.1-libre1234567890", "24.1-libre١",
            "25", "25-libre1", "-libre1", "25.-libre1", ".25-libre1", "25..0-libre1",
            "v24.0-121-gd5cad31-libre-dev", "24.0-121-gd5cad3-libre-dev", "24.0-121-gD5CAD31-libre-dev",
            "24.0-121-libre-dev", "24.0-gd5cad31-libre-dev", "24.0-121-d5cad31-libre-dev", "24.1-libre-dev",
            "24.0-121-gd5cad31", "24.0-121-gd5cad31-dirty", "24.0-121-gd5cad31-libre-dev-dirty",
            "24.0-121-gd5cad31-DIRTY-libre-dev", "24.0-121-gd5cad31-libre-dev.1", "24.0-1234567890-gd5cad31-libre-dev",
            "24-121-gd5cad31-libre-dev", "24.0.1.2-121-gd5cad31-libre-dev", "24.0-rc1-3-gd5cad31-libre-dev",
            "24.1-libre-dev.20260920.abc1234"
        })
        void rejects(String text) {
            assertNull(ForkVersion.parse(text), text);
            assertNull(ForkVersion.parseRelease(text), text);
        }

        @ParameterizedTest
        @DisplayName("should read CoreProtect's own version as CoreProtect does, up to the first dash")
        @CsvSource(nullValues = "null", value = {
            "24.1, 24.1",
            "24.1.3, 24.1.3",
            "24.1-local, 24.1",
            "024.01, 24.1",
            "25, null",
            "24.1.2.3, null",
            "v24.1, null",
            "unknown, null",
            "null, null"
        })
        void coreProtectParts(String version, String expected) {
            int[] parts = ForkVersion.coreProtectParts(version);
            assertEquals(expected, parts == null ? null : ForkVersion.join(parts));
        }
    }

    @Nested
    @DisplayName("Ordering")
    class Ordering {

        @Test
        @DisplayName("should order by upstream version numerically, then releases by revision, then development"
            + " builds by commits past the tag")
        void order() {
            List<String> expected = List.of("9.9-libre9", "9.9-3-gabc1234-libre-dev", "24.0-libre1",
                "24.0-0-gb5f534f-libre-dev", "24.0-9-g1234567-libre-dev", "24.0-121-gd5cad31-libre-dev",
                "24.0-121-gd5cad31-dirty-libre-dev", "24.0-1000-g7654321-libre-dev", "24.1-libre1", "24.1-libre2",
                "24.1-libre10", "24.1-5-gabc1234-libre-dev", "24.1.1-libre1", "24.1.1-2-gabc1234-libre-dev",
                "24.2-libre1", "24.10-libre1", "25.0-libre1");
            List<ForkVersion> shuffled = new ArrayList<>();
            for (int i = expected.size() - 1; i >= 0; i--) {
                shuffled.add(version(expected.get(i)));
            }

            shuffled.sort(ForkVersion.ORDER);

            assertEquals(expected, shuffled.stream().map(ForkVersion::toString).collect(Collectors.toList()));
        }

        @Test
        @DisplayName("should treat a missing third part as 0")
        void missingThirdPart() {
            assertEquals(0, version("24.1-libre1").compareNumbers(version("24.1.0-libre1")));
            assertTrue(version("24.1.1-libre1").compareNumbers(version("24.1-libre9")) > 0);
            assertTrue(ForkVersion.ORDER.compare(version("24.1.0-3-gabc1234-libre-dev"), version("24.1-libre9")) > 0);
            assertTrue(ForkVersion.ORDER.compare(version("24.1-3-gabc1234-libre-dev"), version("24.1.1-libre1")) < 0);
        }
    }

    @Nested
    @DisplayName("isUpdateFor")
    class IsUpdateFor {

        @ParameterizedTest
        @DisplayName("a release should be offered to older releases only")
        @CsvSource({
            "24.1-libre2, 24.1-libre1, true",
            "24.1-libre10, 24.1-libre9, true",
            "24.1.1-libre1, 24.1-libre5, true",
            "24.2-libre1, 24.1.9-libre9, true",
            "25.0-libre1, 24.1-libre1, true",
            "24.1-libre1, 24.1-libre1, false",
            "24.1-libre1, 24.1-libre2, false",
            "24.1-libre9, 24.1.1-libre1, false",
            "23.9-libre9, 24.1-libre1, false",
            "24.1.0-libre1, 24.1-libre1, false",
            "24.1.0-libre2, 24.1-libre1, true"
        })
        void releases(String release, String running, boolean expected) {
            assertEquals(expected, version(release).isUpdateFor(version(running)));
            assertEquals(expected, version(release).isUpdateFor(version(running), version(running).upstreamParts()));
        }

        @ParameterizedTest
        @DisplayName("a development build should only be offered releases of an upstream version newer than its tag's")
        @CsvSource({
            "24.1-libre99, 24.1-5-gabc1234-libre-dev, false",
            "24.1.0-libre1, 24.1-5-gabc1234-libre-dev, false",
            "24.0-libre9, 24.1-5-gabc1234-libre-dev, false",
            "24.1-libre1, 24.1-0-g0af209a-libre-dev, false",
            "24.1-libre2, 24.1-5-gabc1234-dirty-libre-dev, false",
            "24.1.1-libre1, 24.1-5-gabc1234-libre-dev, true",
            "24.2-libre1, 24.1-5-gabc1234-libre-dev, true",
            "25.0-libre1, 24.1-5-gabc1234-libre-dev, true",
            "24.1-libre1, 24.0-121-gd5cad31-libre-dev, true"
        })
        void devBuilds(String release, String running, boolean expected) {
            assertEquals(expected, version(release).isUpdateFor(version(running)));
        }

        @ParameterizedTest
        @DisplayName("a development build should only be offered releases newer than what its CoreProtect declares")
        @CsvSource({
            // Upstream tagged v24.1 on a branch of its own; its master declares 24.1 but describes itself from v24.0
            "24.1-libre1, 24.0-121-gd5cad31-libre-dev, 24.1, false",
            "24.1-libre9, 24.0-121-gd5cad31-libre-dev, 24.1, false",
            "24.0-libre9, 24.0-121-gd5cad31-libre-dev, 24.1, false",
            "24.1.1-libre1, 24.0-121-gd5cad31-libre-dev, 24.1, true",
            "24.2-libre1, 24.0-121-gd5cad31-libre-dev, 24.1, true",
            "25.0-libre1, 24.0-121-gd5cad31-libre-dev, 24.1, true",
            // The tag counts too, should CoreProtect declare an older version
            "24.1-libre2, 24.1-5-gabc1234-libre-dev, 24.0, false",
            "24.2-libre1, 24.1-5-gabc1234-libre-dev, 24.0, true",
            // A release's CoreProtect declares the release's version, which the build checks
            "24.1-libre2, 24.1-libre1, 24.1, true"
        })
        void declaredVersion(String release, String running, String coreProtect, boolean expected) {
            assertEquals(expected, version(release).isUpdateFor(version(running), numbers(coreProtect)));
        }

        @Test
        @DisplayName("a development build should never be offered")
        void devBuildNotOffered() {
            assertFalse(version("25.0-3-gabc1234-libre-dev").isUpdateFor(version("24.1-libre1")));
            assertFalse(version("24.1-5-gabc1234-libre-dev").isUpdateFor(version("24.1-3-gabc1234-libre-dev")));
        }
    }

    @Test
    @DisplayName("should be equal by text")
    void equality() {
        assertEquals(version("24.1-libre1"), version("24.1-libre1"));
        assertEquals(version("24.1-libre1").hashCode(), version("24.1-libre1").hashCode());
        assertNotEquals(version("24.1-libre1"), version("24.1.0-libre1"));
        assertNotEquals(version("24.0-121-gd5cad31-libre-dev"), version("24.0-121-gd5cad31-dirty-libre-dev"));
    }

    @Test
    @DisplayName("upstreamParts should be a copy")
    void upstreamPartsCopy() {
        ForkVersion version = version("24.1-libre1");
        version.upstreamParts()[0] = 99;
        assertEquals("24.1", version.upstream());
    }
}
