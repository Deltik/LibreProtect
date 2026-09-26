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

package net.deltik.mc.libreprotect.extension.purge;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.LocalTime;

import static org.junit.jupiter.api.Assertions.*;

class AutoPurgeSettingsTest {

    private static final long DAY = 86400;

    @Nested
    @DisplayName("parseRetention")
    class ParseRetention {

        @ParameterizedTest(name = "{0} = {1} s")
        @CsvSource({
            "30d, 2592000",
            "6mo, 15552000",
            "1y, 31536000",
            "12w, 7257600",
            "1mo2w, 3801600",
            "1mo 2w, 3801600",
            "1y6mo, 47088000",
            "720h, 2592000",
            "43200m, 2592000",
            "2592000s, 2592000",
            "1.5d, 129600",
            ".5y, 15768000",
            "30.d, 2592000",
            "30D, 2592000",
            "'  30d  ', 2592000",
            "30d # a month, 2592000",
            "29d23h59m60s, 2592000",
            "1d1d, 172800",
            "0.0000001s, 1",
            "0d, 0",
        })
        @DisplayName("should read times like CoreProtect's commands, with months as 30 days")
        void parses(String value, long seconds) {
            assertEquals(seconds, AutoPurgeSettings.parseRetention(value));
        }

        @ParameterizedTest(name = "{0} = {1} s")
        @CsvSource(delimiter = '|', value = {
            "4w,2d|2592000",
            "2w,5d,7h,2m,10s|1666930",
            "1mo, 2w|3801600",
            "1mo ,2w|3801600",
            "30d , 1h|2595600",
        })
        @DisplayName("should read amounts separated by commas, as in CoreProtect's t:2w,5d,7h,2m,10s")
        void commas(String value, long seconds) {
            assertEquals(seconds, AutoPurgeSettings.parseRetention(value));
            AutoPurgeSettings settings = AutoPurgeSettings.of(value, "");
            // 2w,5d,7h,2m,10s is under 20 days, below the minimum, but it is a retention time
            assertEquals(seconds >= AutoPurgeSettings.MINIMUM_RETENTION_SECONDS, settings.enabled());
            assertTrue(settings.retentionProblem() == null || settings.retentionProblem().contains("minimum"),
                settings.retentionProblem());
        }

        @Test
        @DisplayName("should read 6mo as six months, not six minutes as CoreProtect's TimeParser does")
        void monthsAreNotMinutes() {
            assertEquals(180 * DAY, AutoPurgeSettings.parseRetention("6mo"));
            assertEquals(6 * 60, AutoPurgeSettings.parseRetention("6m"));
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"false", "FALSE", " false ", "false # off"})
        @DisplayName("should turn auto-purge off for false or nothing")
        void off(String value) {
            assertEquals(0, AutoPurgeSettings.parseRetention(value));
        }

        @ParameterizedTest
        @ValueSource(strings = {"30", "d", "30x", "30 days", "-30d", "30d-40d", "1.2.3d", "t:30d", "true", "30d,", "mo", "#30d",
            ",30d", "30d,,2w", ",", "30d;2w"})
        @DisplayName("should refuse anything else")
        void invalid(String value) {
            assertThrows(IllegalArgumentException.class, () -> AutoPurgeSettings.parseRetention(value));
        }

        @Test
        @DisplayName("should cap absurd values instead of overflowing")
        void capped() {
            long seconds = AutoPurgeSettings.parseRetention("99999999999999999999999y");
            assertTrue(seconds > 999 * 365 * DAY && seconds <= 1000 * 365 * DAY, Long.toString(seconds));
        }
    }

    @Nested
    @DisplayName("parseTime")
    class ParseTime {

        @ParameterizedTest(name = "{0} = {1}")
        @CsvSource({"0:00, 00:00", "00:00, 00:00", "3:30, 03:30", "03:30, 03:30", "23:59, 23:59", "'  7:05 ', 07:05",
            "03:30 # early, 03:30"})
        @DisplayName("should read H:mm and HH:mm")
        void parses(String value, String expected) {
            assertEquals(LocalTime.parse(expected), AutoPurgeSettings.parseTime(value));
        }

        @ParameterizedTest
        @NullAndEmptySource
        @DisplayName("should default to midnight")
        void midnight(String value) {
            assertEquals(LocalTime.MIDNIGHT, AutoPurgeSettings.parseTime(value));
        }

        @ParameterizedTest
        @ValueSource(strings = {"24:00", "3:5", "03:60", "3", "3.30", "03:30 PM", "-1:00", "003:30", "03:30:00", "noon"})
        @DisplayName("should refuse anything else")
        void invalid(String value) {
            assertThrows(IllegalArgumentException.class, () -> AutoPurgeSettings.parseTime(value));
        }
    }

    @Nested
    @DisplayName("of")
    class Of {

        @Test
        @DisplayName("should be on with a valid retention of at least 30 days")
        void enabled() {
            AutoPurgeSettings settings = AutoPurgeSettings.of("180d", "03:30");
            assertTrue(settings.enabled());
            assertEquals(180 * DAY, settings.retentionSeconds());
            assertEquals(LocalTime.of(3, 30), settings.time());
            assertNull(settings.retentionProblem());
            assertNull(settings.timeProblem());
        }

        @Test
        @DisplayName("should accept exactly the 30-day minimum")
        void minimum() {
            assertTrue(AutoPurgeSettings.of("1mo", "").enabled());
            assertTrue(AutoPurgeSettings.of("30d", "").enabled());
        }

        @ParameterizedTest
        @ValueSource(strings = {"29d", "4w", "29d23h59m59s", "1s", "0d", "0s", "0.0m", "0d,0h"})
        @DisplayName("should turn off with a warning below the minimum, including zero")
        void belowMinimum(String value) {
            AutoPurgeSettings settings = AutoPurgeSettings.of(value, "");
            assertFalse(settings.enabled());
            assertEquals(0, settings.retentionSeconds());
            assertEquals("auto-purge in CoreProtect's config.yml: '" + value + "' keeps less than the minimum of 30 days."
                + " Auto-purge is off.",
                settings.retentionProblem());
        }

        @Test
        @DisplayName("should turn off with a warning for an invalid retention")
        void invalidRetention() {
            AutoPurgeSettings settings = AutoPurgeSettings.of("6months", "");
            assertFalse(settings.enabled());
            assertEquals("auto-purge in CoreProtect's config.yml: '6months' isn't a retention time. Use a time such as"
                + " 30d, 12w or 6mo, or false. Auto-purge is off.", settings.retentionProblem());
        }

        @Test
        @DisplayName("should turn off without a warning for false")
        void disabled() {
            AutoPurgeSettings settings = AutoPurgeSettings.of("false", "");
            assertFalse(settings.enabled());
            assertNull(settings.retentionProblem());
        }

        @Test
        @DisplayName("should run at midnight with a warning for an invalid time")
        void invalidTime() {
            AutoPurgeSettings settings = AutoPurgeSettings.of("30d", "25:00");
            assertTrue(settings.enabled());
            assertEquals(LocalTime.MIDNIGHT, settings.time());
            assertEquals("auto-purge-time in CoreProtect's config.yml: '25:00' isn't a time. Use 24-hour HH:mm server"
                + " time, such as 03:30. Auto-purge runs at midnight.", settings.timeProblem());
        }

        @Test
        @DisplayName("should compare the values as read")
        void sameValues() {
            assertTrue(AutoPurgeSettings.of("30d", "").sameValues(AutoPurgeSettings.of("30d", "")));
            assertFalse(AutoPurgeSettings.of("30d", "").sameValues(AutoPurgeSettings.of("30d", "1:00")));
            assertFalse(AutoPurgeSettings.of("30d", "").sameValues(AutoPurgeSettings.of("4w2d", "")));
            assertFalse(AutoPurgeSettings.of("30d", "").sameValues(null));
        }
    }

    @Nested
    @DisplayName("describeRetention")
    class DescribeRetention {

        @ParameterizedTest(name = "{0} s = {1}")
        @CsvSource(delimiter = '|', value = {
            "2592000 | 30 days",
            "86400 | 1 day",
            "15552000 | 180 days",
            "2635200 | 30 days, 12 hours",
            "2595661 | 30 days, 1 hour, 1 minute, 1 second",
            "31536000000 | 365,000 days",
        })
        @DisplayName("should name days and any remainder")
        void describes(long seconds, String expected) {
            assertEquals(expected, AutoPurgeSettings.describeRetention(seconds));
        }
    }
}
