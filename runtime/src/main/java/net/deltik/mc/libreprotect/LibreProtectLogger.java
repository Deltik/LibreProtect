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

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Logging for LibreProtect's own messages. Messages logged before
 * {@link #initialize} are buffered and written once it is called.
 *
 * <p>{@link Bootstrap} passes the server's logger, which CoreProtect uses as
 * well. Every message starts with {@value #PREFIX}, like CoreProtect's
 * {@code [CoreProtect]}, which LibreProtect's build changes to
 * {@code [LibreProtect]}.
 */
public class LibreProtectLogger {

    public static final String PREFIX = "[" + PrivacyConstants.FORK_NAME + "] ";

    private static Logger logger;
    private static final List<BufferedMessage> bufferedMessages = new ArrayList<>();
    private static boolean verboseLogging = false;

    private static class BufferedMessage {
        final Level level;
        final String message;

        BufferedMessage(Level level, String message) {
            this.level = level;
            this.message = message;
        }
    }

    private LibreProtectLogger() {
        // Prevent instantiation
    }

    /**
     * Start writing to a logger, beginning with any buffered messages.
     * This should be called as early as possible in the plugin lifecycle.
     *
     * @param logger the logger to write to
     */
    public static synchronized void initialize(Logger logger) {
        LibreProtectLogger.logger = logger;

        // Flush any buffered messages
        for (BufferedMessage msg : bufferedMessages) {
            logger.log(msg.level, msg.message);
        }
        bufferedMessages.clear();
    }

    /**
     * Set verbose logging mode
     */
    public static void setVerbose(boolean verbose) {
        verboseLogging = verbose;
    }

    /**
     * Log an info message
     */
    public static void info(String message) {
        log(Level.INFO, message);
    }

    /**
     * Log a warning message
     */
    public static void warning(String message) {
        log(Level.WARNING, message);
    }

    /**
     * Log a severe/error message
     */
    public static void severe(String message) {
        log(Level.SEVERE, message);
    }

    /**
     * Log a debug message (only shown if verbose logging is enabled)
     */
    public static void debug(String message) {
        if (verboseLogging) {
            log(Level.INFO, "[DEBUG] " + message);
        }
    }

    /**
     * Log a message at the specified level
     */
    public static synchronized void log(Level level, String message) {
        String prefixed = PREFIX + message;
        if (logger != null) {
            logger.log(level, prefixed);
        } else {
            // Buffer the message for later
            bufferedMessages.add(new BufferedMessage(level, prefixed));
        }
    }

    /**
     * Forget the logger and any buffered messages (for tests)
     */
    public static synchronized void reset() {
        logger = null;
        bufferedMessages.clear();
        verboseLogging = false;
    }

    /**
     * Check if the logger has been initialized
     */
    public static boolean isInitialized() {
        return logger != null;
    }
}
