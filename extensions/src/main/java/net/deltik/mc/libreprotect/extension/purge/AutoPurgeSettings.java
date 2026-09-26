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

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The {@code auto-purge} and {@code auto-purge-time} settings from
 * {@code config.yml}: how much data to keep, and when to purge each day.
 *
 * <p>CoreProtect reads both as plain strings and leaves them to the
 * extension. Its own {@code TimeParser} reads {@code 6mo} as six minutes, so
 * retention is parsed here: one or more amounts with a unit, such as
 * {@code 30d}, {@code 12w}, {@code 6mo}, {@code 1mo2w} or {@code 4w,2d}. Units
 * are {@code y} (365 days), {@code mo} (30 days), {@code w}, {@code d},
 * {@code h}, {@code m} and {@code s}, and amounts may have decimals and be
 * separated by commas, as in CoreProtect's commands ({@code t:2w,5d,7h}).
 */
final class AutoPurgeSettings {

    /** The shortest retention auto-purge accepts: 30 days */
    static final long MINIMUM_RETENTION_SECONDS = 30L * 24 * 60 * 60;

    /** When auto-purge runs if {@code auto-purge-time} is absent: midnight, server time */
    static final LocalTime DEFAULT_TIME = LocalTime.MIDNIGHT;

    /** Longer retention can't select any rows, so it is capped to keep arithmetic in range */
    private static final long MAXIMUM_RETENTION_SECONDS = 1000L * 365 * 24 * 60 * 60;

    /** An amount and its unit, after a comma unless it's the first */
    private static final Pattern RETENTION_PART = Pattern.compile("\\G\\s*(,\\s*)?(\\d+(?:\\.\\d*)?|\\.\\d+)\\s*(mo|y|w|d|h|m|s)");
    private static final Pattern TIME = Pattern.compile("(\\d{1,2}):(\\d{2})");
    private static final Pattern TRAILING_COMMENT = Pattern.compile("\\s+#.*$");

    private final String retentionValue;
    private final String timeValue;
    private final long retentionSeconds;
    private final LocalTime time;
    private final String retentionProblem;
    private final String timeProblem;

    private AutoPurgeSettings(String retentionValue, String timeValue, long retentionSeconds, LocalTime time,
                              String retentionProblem, String timeProblem) {
        this.retentionValue = retentionValue;
        this.timeValue = timeValue;
        this.retentionSeconds = retentionSeconds;
        this.time = time;
        this.retentionProblem = retentionProblem;
        this.timeProblem = timeProblem;
    }

    /**
     * Read the settings. Values that can't be used turn auto-purge off (for
     * {@code auto-purge}) or fall back to midnight (for
     * {@code auto-purge-time}), with a problem to warn about.
     *
     * @param retentionValue {@code auto-purge}, as CoreProtect read it, or {@code null}
     * @param timeValue {@code auto-purge-time}, as CoreProtect read it, or {@code null}
     */
    static AutoPurgeSettings of(String retentionValue, String timeValue) {
        long retention = 0;
        String retentionProblem = null;
        try {
            retention = parseRetention(retentionValue);
            // 0d is a retention too short to purge with, not a way to turn auto-purge off
            if (!isOff(retentionValue) && retention < MINIMUM_RETENTION_SECONDS) {
                retentionProblem = "auto-purge in CoreProtect's config.yml: '" + clean(retentionValue)
                    + "' keeps less than the minimum of "
                    + describeRetention(MINIMUM_RETENTION_SECONDS) + ". Auto-purge is off.";
                retention = 0;
            }
        } catch (IllegalArgumentException e) {
            retentionProblem = "auto-purge in CoreProtect's config.yml: '" + clean(retentionValue)
                + "' isn't a retention time. "
                + "Use a time such as 30d, 12w or 6mo, or false. Auto-purge is off.";
        }

        LocalTime time = DEFAULT_TIME;
        String timeProblem = null;
        try {
            time = parseTime(timeValue);
        } catch (IllegalArgumentException e) {
            timeProblem = "auto-purge-time in CoreProtect's config.yml: '" + clean(timeValue) + "' isn't a time. "
                + "Use 24-hour HH:mm server time, such as 03:30. Auto-purge runs at midnight.";
        }
        return new AutoPurgeSettings(retentionValue, timeValue, retention, time, retentionProblem, timeProblem);
    }

    /**
     * @return whether the value is {@code false}, empty or {@code null}, which turn auto-purge off
     */
    static boolean isOff(String value) {
        String text = clean(value).toLowerCase(Locale.ROOT);
        return text.isEmpty() || text.equals("false");
    }

    /**
     * @return seconds of data to keep, or 0 for {@code false}, an empty value
     *         or {@code null}, which turn auto-purge off
     * @throws IllegalArgumentException if the value isn't a retention time
     */
    static long parseRetention(String value) {
        if (isOff(value)) {
            return 0;
        }
        String text = clean(value).toLowerCase(Locale.ROOT);
        Matcher matcher = RETENTION_PART.matcher(text);
        BigDecimal seconds = BigDecimal.ZERO;
        int end = 0;
        while (matcher.find() && matcher.start() == end && (end > 0 || matcher.group(1) == null)) {
            seconds = seconds.add(new BigDecimal(matcher.group(2)).multiply(BigDecimal.valueOf(unitSeconds(matcher.group(3)))));
            end = matcher.end();
        }
        if (end == 0 || end != text.length()) {
            throw new IllegalArgumentException("Not a retention time: " + value);
        }
        // Round up, so that at least the configured amount is kept
        BigDecimal whole = seconds.setScale(0, RoundingMode.CEILING);
        return whole.compareTo(BigDecimal.valueOf(MAXIMUM_RETENTION_SECONDS)) > 0
            ? MAXIMUM_RETENTION_SECONDS : whole.longValueExact();
    }

    private static long unitSeconds(String unit) {
        switch (unit) {
            case "y":
                return 365L * 24 * 60 * 60;
            case "mo":
                return 30L * 24 * 60 * 60;
            case "w":
                return 7L * 24 * 60 * 60;
            case "d":
                return 24L * 60 * 60;
            case "h":
                return 60L * 60;
            case "m":
                return 60L;
            default:
                return 1L;
        }
    }

    /**
     * @return the time of day, or {@link #DEFAULT_TIME} for an empty value or {@code null}
     * @throws IllegalArgumentException if the value isn't a 24-hour {@code H:mm} or {@code HH:mm} time
     */
    static LocalTime parseTime(String value) {
        String text = clean(value);
        if (text.isEmpty()) {
            return DEFAULT_TIME;
        }
        Matcher matcher = TIME.matcher(text);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Not a time: " + value);
        }
        int hour = Integer.parseInt(matcher.group(1));
        int minute = Integer.parseInt(matcher.group(2));
        if (hour > 23 || minute > 59) {
            throw new IllegalArgumentException("Not a time: " + value);
        }
        return LocalTime.of(hour, minute);
    }

    /**
     * CoreProtect keeps a YAML comment after a value as part of it; drop it.
     */
    private static String clean(String value) {
        return value == null ? "" : TRAILING_COMMENT.matcher(value.trim()).replaceFirst("").trim();
    }

    /**
     * @return a retention for messages, such as "180 days" or "30 days, 12 hours"
     */
    static String describeRetention(long seconds) {
        long[] amounts = {seconds / 86400, seconds % 86400 / 3600, seconds % 3600 / 60, seconds % 60};
        String[] units = {"day", "hour", "minute", "second"};
        List<String> parts = new ArrayList<>();
        for (int i = 0; i < amounts.length; i++) {
            if (amounts[i] != 0) {
                parts.add(String.format(Locale.ROOT, "%,d %s%s", amounts[i], units[i], amounts[i] == 1 ? "" : "s"));
            }
        }
        return parts.isEmpty() ? "0 seconds" : String.join(", ", parts);
    }

    /**
     * @return whether auto-purge is on
     */
    boolean enabled() {
        return retentionSeconds > 0;
    }

    /**
     * @return seconds of data to keep, or 0 if auto-purge is off
     */
    long retentionSeconds() {
        return retentionSeconds;
    }

    /**
     * @return the time of day to purge, server time
     */
    LocalTime time() {
        return time;
    }

    /**
     * @return a warning about {@code auto-purge}, or {@code null}
     */
    String retentionProblem() {
        return retentionProblem;
    }

    /**
     * @return a warning about {@code auto-purge-time}, or {@code null}
     */
    String timeProblem() {
        return timeProblem;
    }

    /**
     * @return whether both settings read the same as in {@code other}
     */
    boolean sameValues(AutoPurgeSettings other) {
        return other != null && Objects.equals(retentionValue, other.retentionValue)
            && Objects.equals(timeValue, other.timeValue);
    }

    /**
     * @return the raw {@code auto-purge} value
     */
    String retentionValue() {
        return retentionValue;
    }

    /**
     * @return the raw {@code auto-purge-time} value
     */
    String timeValue() {
        return timeValue;
    }
}
