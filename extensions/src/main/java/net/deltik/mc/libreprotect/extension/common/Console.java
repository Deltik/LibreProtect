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

package net.deltik.mc.libreprotect.extension.common;

import net.deltik.mc.libreprotect.PrivacyConstants;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;

/**
 * Messages from LibreProtect's extensions to a command sender, in
 * CoreProtect's chat style with LibreProtect's name. CoreProtect has no
 * phrases for these features, so the messages are in English.
 */
public final class Console {

    /** CoreProtect's chat prefix style, with LibreProtect's name */
    public static final String PREFIX = ChatColor.DARK_AQUA + PrivacyConstants.FORK_NAME + " " + ChatColor.WHITE + "- ";

    private final CommandSender sender;

    public Console(CommandSender sender) {
        this.sender = sender;
    }

    /**
     * Send a message with the chat prefix.
     */
    public void say(String message) {
        send(PREFIX + message);
    }

    /**
     * Send a secondary line without the prefix, in gray.
     */
    public void detail(String message) {
        send(ChatColor.GRAY + message);
    }

    /**
     * Send an error with the chat prefix, in red.
     */
    public void error(String message) {
        send(PREFIX + ChatColor.RED + message);
    }

    private void send(String message) {
        try {
            sender.sendMessage(message);
        } catch (RuntimeException e) {
            // A sender that went away can't be told anything more
        }
    }

    /**
     * Calls through at most once per interval, so progress can be reported
     * from a tight loop.
     */
    public static final class Throttle {
        private final long intervalNanos;
        private long last;
        private boolean started;

        public Throttle(long intervalMillis) {
            this.intervalNanos = intervalMillis * 1_000_000L;
        }

        /**
         * @return whether the interval has passed since the last time this returned true
         */
        public boolean ready() {
            long now = System.nanoTime();
            if (!started || now - last >= intervalNanos) {
                started = true;
                last = now;
                return true;
            }
            return false;
        }
    }
}
