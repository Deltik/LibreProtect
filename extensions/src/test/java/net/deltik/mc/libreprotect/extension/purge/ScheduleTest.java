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

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;

import static org.junit.jupiter.api.Assertions.*;

class ScheduleTest {

    private static final ZoneId UTC = ZoneId.of("UTC");
    private static final ZoneId NEW_YORK = ZoneId.of("America/New_York");
    private static final ZoneId SANTIAGO = ZoneId.of("America/Santiago");

    private static Instant at(String offsetDateTime) {
        return OffsetDateTime.parse(offsetDateTime).toInstant();
    }

    private static Instant next(String after, String time, ZoneId zone) {
        return Schedule.nextRun(at(after), LocalTime.parse(time), zone).toInstant();
    }

    @Nested
    @DisplayName("nextRun")
    class NextRun {

        @Test
        @DisplayName("should run later today if the time hasn't passed")
        void laterToday() {
            assertEquals(at("2026-09-24T03:30Z"), next("2026-09-24T01:00Z", "03:30", UTC));
        }

        @Test
        @DisplayName("should run tomorrow if the time has passed")
        void tomorrow() {
            assertEquals(at("2026-09-25T00:00Z"), next("2026-09-24T12:00Z", "00:00", UTC));
        }

        @Test
        @DisplayName("should run tomorrow, not again, at the exact scheduled instant")
        void strictlyAfter() {
            assertEquals(at("2026-09-25T03:30Z"), next("2026-09-24T03:30Z", "03:30", UTC));
        }

        @Test
        @DisplayName("should use the local time of the zone")
        void localTime() {
            assertEquals(at("2026-09-25T00:00-04:00"), next("2026-09-24T12:00-04:00", "00:00", NEW_YORK));
            assertEquals(at("2026-12-25T00:00-05:00"), next("2026-12-24T12:00-05:00", "00:00", NEW_YORK));
        }

        @Test
        @DisplayName("should run a time skipped by daylight saving time at the end of the gap")
        void gap() {
            // New York skips 02:00 to 03:00 on 2026-03-08
            ZonedDateTime run = Schedule.nextRun(at("2026-03-08T01:00-05:00"), LocalTime.of(2, 30), NEW_YORK);
            assertEquals(at("2026-03-08T03:00-04:00"), run.toInstant());
            // And at 02:30 again on the next day
            assertEquals(at("2026-03-09T02:30-04:00"), Schedule.nextRun(run.toInstant(), LocalTime.of(2, 30), NEW_YORK).toInstant());
        }

        @Test
        @DisplayName("should run a skipped midnight at the end of the gap")
        void midnightGap() {
            // Santiago skips 00:00 to 01:00 on 2026-09-06
            assertEquals(at("2026-09-06T01:00-03:00"), next("2026-09-05T12:00-04:00", "00:00", SANTIAGO));
        }

        @Test
        @DisplayName("should run a time repeated by daylight saving time once, at its first occurrence")
        void overlap() {
            // New York shows 01:00 to 02:00 twice on 2026-11-01, first at -04:00, then at -05:00
            Instant first = next("2026-11-01T00:00-04:00", "01:30", NEW_YORK);
            assertEquals(at("2026-11-01T01:30-04:00"), first);
            // After running at the first, the second one isn't a run
            assertEquals(at("2026-11-02T01:30-05:00"), Schedule.nextRun(first.plusSeconds(60), LocalTime.of(1, 30), NEW_YORK).toInstant());
            assertEquals(at("2026-11-02T01:30-05:00"), next("2026-11-01T01:15-05:00", "01:30", NEW_YORK));
        }

        @Test
        @DisplayName("should run once on each date, whatever the offset changes")
        void oncePerDate() {
            Instant after = at("2026-10-25T00:00-04:00");
            LocalDate expected = LocalDate.of(2026, 10, 25);
            for (int day = 0; day < 20; day++) {
                ZonedDateTime run = Schedule.nextRun(after, LocalTime.of(1, 30), NEW_YORK);
                assertEquals(expected.plusDays(day), run.toLocalDate());
                after = run.toInstant();
            }
        }
    }

    @Test
    @DisplayName("describe should show server time without seconds")
    void describe() {
        assertEquals("2026-09-25 03:30 (server time)",
            Schedule.describe(ZonedDateTime.of(2026, 9, 25, 3, 30, 42, 0, NEW_YORK)));
    }
}
