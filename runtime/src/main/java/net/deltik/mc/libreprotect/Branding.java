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

import net.deltik.mc.libreprotect.update.UpdatePhrases;
import org.bukkit.command.CommandSender;

import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Makes CoreProtect's messages name LibreProtect, point to LibreProtect, and
 * leave out what doesn't apply to it, such as donation keys.
 *
 * <p>The transformer makes three changes to CoreProtect's code:
 * <ul>
 *   <li>Text constants that show the plugin name, such as the
 *       {@code "CoreProtect - "} chat prefix and {@code "----- CoreProtect -----"}
 *       headers, say LibreProtect. This happens at build time.</li>
 *   <li>Every call to CoreProtect's phrase renderer passes its result through
 *       {@link #phrase}. Phrases are identified by their names, which are
 *       also the keys of CoreProtect's {@code language.yml}.</li>
 *   <li>Every Bukkit {@code sendMessage(String)} call and every
 *       {@link Logger} call goes through {@link #sendMessage} or {@link #log},
 *       which leave out messages that contain a dropped phrase.</li>
 * </ul>
 *
 * <p>Only JDK and Bukkit types may be used here, as in {@link Bootstrap}.
 * Nothing here may throw because of a message: if anything goes wrong, the
 * message is shown unchanged.
 */
public final class Branding {

    /**
     * Marks a phrase whose whole message is left out. It is random, so text
     * written by players, which CoreProtect shows in lookups, can't contain
     * it and hide a line.
     */
    static final String DROP = "\uFDD0" + UUID.randomUUID() + "\uFDD1";

    /** Donation-key status, which LibreProtect doesn't use, and upstream's Patreon link */
    static final Set<String> DROPPED = Set.of(
        "STATUS_LICENSE", "VALID_DONATION_KEY", "INVALID_DONATION_KEY", "LINK_PATREON");

    /** Phrases in which the plugin names itself */
    static final Set<String> SELF_NAMING = Set.of(
        "ENABLE_SUCCESS", "ENABLE_FAILED", "DISABLE_SUCCESS", "STATUS_VERSION", "HELP_HEADER", "LOOKUP_HEADER",
        "UPDATE_HEADER", "VERSION_INCOMPATIBLE");

    /** Links to upstream's community and downloads, as a label and LibreProtect's replacement link */
    static final Map<String, String[]> LINKS = Map.of(
        "LINK_DISCORD", new String[] {"Website", PrivacyConstants.FORK_DISPLAY_URL},
        "LINK_DOWNLOAD", new String[] {"Download", PrivacyConstants.FORK_DISPLAY_URL + "/releases"});

    /**
     * Links whose label still fits LibreProtect's link, so a translated label
     * stays and only the link changes. "Discord" doesn't fit a website.
     */
    static final Set<String> RELINKED = Set.of("LINK_DOWNLOAD");

    /** Upstream's "Enjoy CoreProtect? Join our Discord!" startup line */
    static final String INTRODUCTION = "ENJOY_COREPROTECT";

    private Branding() {
    }

    /**
     * Called with each phrase that CoreProtect renders.
     *
     * @param phrase CoreProtect's phrase constant
     * @param params the parameters it was rendered with
     * @param rendered CoreProtect's rendering
     * @return the text to use instead
     */
    public static String phrase(Enum<?> phrase, String[] params, String rendered) {
        if (phrase == null || rendered == null) {
            return rendered;
        }
        try {
            String name = phrase.name();
            if (DROPPED.contains(name)) {
                return rendered + DROP;
            }
            // Update messages show the release that LibreProtect found, when there is one
            String update = UpdatePhrases.rewrite(name, params, rendered);
            if (update != null) {
                return update;
            }
            String[] link = LINKS.get(name);
            if (link != null) {
                return RELINKED.contains(name) ? relink(rendered, params, link[0], link[1])
                    : link[0] + ":" + leadingColor(params) + " " + link[1];
            }
            if (INTRODUCTION.equals(name)) {
                return PrivacyConstants.FORK_NAME + " is a privacy-hardened build of " + PrivacyConstants.ORIGINAL_NAME
                    + " by " + PrivacyConstants.ORIGINAL_AUTHOR + ".";
            }
            if (SELF_NAMING.contains(name)) {
                return rendered.replace(PrivacyConstants.ORIGINAL_NAME, PrivacyConstants.FORK_NAME);
            }
        } catch (RuntimeException e) {
            // Show the phrase unchanged
        }
        return rendered;
    }

    /**
     * Replace upstream's link, the phrase's last parameter after any leading
     * color, in the rendered phrase. That keeps the label as rendered, such
     * as {@code Herunterladen:}. If the rendering doesn't show the link, the
     * English label comes with the new link instead.
     */
    static String relink(String rendered, String[] params, String label, String link) {
        int first = leadingColor(params).isEmpty() ? 0 : 1;
        String upstreamLink = params != null && params.length > first ? params[params.length - 1] : null;
        if (upstreamLink != null && !upstreamLink.isEmpty() && rendered.contains(upstreamLink)) {
            return rendered.replace(upstreamLink, link);
        }
        return label + ":" + leadingColor(params) + " " + link;
    }

    /**
     * CoreProtect's convention: a color code as the first parameter colors
     * the text after the phrase's colon.
     */
    private static String leadingColor(String[] params) {
        if (params != null && params.length > 0 && params[0] != null && params[0].length() == 2
            && params[0].charAt(0) == '\u00A7') {
            return params[0];
        }
        return "";
    }

    static boolean isDropped(String message) {
        return message != null && message.contains(DROP);
    }

    /** Replaces {@code sendMessage(String)} of {@link CommandSender} and its subinterfaces */
    public static void sendMessage(CommandSender sender, String message) {
        if (!isDropped(message)) {
            sender.sendMessage(message);
        }
    }

    /** Replaces {@link Logger#log(Level, String)} */
    public static void log(Logger logger, Level level, String message) {
        if (!isDropped(message)) {
            logger.log(level, message);
        }
    }

    /** Replaces {@link Logger#info(String)} */
    public static void info(Logger logger, String message) {
        if (!isDropped(message)) {
            logger.info(message);
        }
    }

    /** Replaces {@link Logger#warning(String)} */
    public static void warning(Logger logger, String message) {
        if (!isDropped(message)) {
            logger.warning(message);
        }
    }

    /** Replaces {@link Logger#severe(String)} */
    public static void severe(Logger logger, String message) {
        if (!isDropped(message)) {
            logger.severe(message);
        }
    }
}
