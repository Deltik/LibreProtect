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

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.zone.ZoneOffsetTransition;
import java.time.zone.ZoneRules;
import java.util.List;
import java.util.Locale;

/**
 * When the daily purge runs: once per local date, at a time of day in the
 * server's time zone.
 *
 * <p>Daylight saving time moves some local times. A time that a transition
 * skips runs at the first instant after the gap, and a time that happens
 * twice runs only at the first of the two.
 */
final class Schedule {

    private static final DateTimeFormatter FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm", Locale.ROOT);

    private Schedule() {
    }

    /**
     * @return the first scheduled run strictly after {@code after}
     */
    static ZonedDateTime nextRun(Instant after, LocalTime time, ZoneId zone) {
        LocalDate date = after.atZone(zone).toLocalDate();
        while (true) {
            ZonedDateTime run = runOn(date, time, zone);
            if (run.toInstant().isAfter(after)) {
                return run;
            }
            date = date.plusDays(1);
        }
    }

    /**
     * @return the one instant of {@code date} at which the purge runs
     */
    static ZonedDateTime runOn(LocalDate date, LocalTime time, ZoneId zone) {
        LocalDateTime local = LocalDateTime.of(date, time);
        ZoneRules rules = zone.getRules();
        List<ZoneOffset> offsets = rules.getValidOffsets(local);
        if (offsets.isEmpty()) {
            ZoneOffsetTransition gap = rules.getTransition(local);
            return gap.getInstant().atZone(zone);
        }
        // In an overlap, the earlier offset is the first time the clock shows this time
        return ZonedDateTime.ofLocal(local, zone, offsets.get(0));
    }

    /**
     * @return a run time for messages, such as "2026-09-25 00:00 (server time)"
     */
    static String describe(ZonedDateTime run) {
        return FORMAT.format(run) + " (server time)";
    }
}
