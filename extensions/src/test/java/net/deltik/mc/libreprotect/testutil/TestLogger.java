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

package net.deltik.mc.libreprotect.testutil;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * A test logger that captures log messages for verification in tests.
 */
public class TestLogger extends Logger {
    private final List<LogRecord> records = new ArrayList<>();

    public TestLogger() {
        super("TestLogger", null);
        setLevel(Level.ALL);
    }

    @Override
    public void log(LogRecord record) {
        records.add(record);
    }

    /**
     * Get all captured log records.
     */
    public List<LogRecord> getRecords() {
        return new ArrayList<>(records);
    }

    /**
     * Clear all captured records.
     */
    public void clear() {
        records.clear();
    }

    /**
     * Check if any log message contains the given substring.
     */
    public boolean hasMessageContaining(String substring) {
        return records.stream()
            .anyMatch(r -> r.getMessage() != null && r.getMessage().contains(substring));
    }

    /**
     * Check if any log message at the given level contains the given substring.
     */
    public boolean hasMessageContaining(Level level, String substring) {
        return records.stream()
            .anyMatch(r -> r.getLevel().equals(level)
                && r.getMessage() != null && r.getMessage().contains(substring));
    }

    /**
     * Check if any log record has the given level.
     */
    public boolean hasLevel(Level level) {
        return records.stream()
            .anyMatch(r -> r.getLevel().equals(level));
    }

    /**
     * Get the count of records at a specific level.
     */
    public long countAtLevel(Level level) {
        return records.stream()
            .filter(r -> r.getLevel().equals(level))
            .count();
    }

    /**
     * Get all messages as a list of strings.
     */
    public List<String> getMessages() {
        List<String> messages = new ArrayList<>();
        for (LogRecord record : records) {
            if (record.getMessage() != null) {
                messages.add(record.getMessage());
            }
        }
        return messages;
    }
}
