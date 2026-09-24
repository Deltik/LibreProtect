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

/*
 * Portions of this file are copied or adapted from CoreProtect
 * <https://github.com/PlayPro/CoreProtect>:
 *
 * Copyright (c) Intelli and the CoreProtect contributors
 *
 * CoreProtect is licensed under the Artistic License 2.0 (see
 * LICENSES/Artistic-2.0.txt). As section 4(c)(ii) of that license
 * permits, LibreProtect distributes these portions under the
 * GNU General Public License, version 3 or later. See NOTICE.
 */

package net.deltik.mc.libreprotect.transformer.fixture;

import org.bukkit.command.CommandSender;

import java.util.EnumMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Mirrors how upstream builds and prints messages: phrases rendered by a
 * static method of their enum, colors held in fields that aren't compile-time
 * constants, and string concatenation.
 */
public class BrandingFixture {

    public static String DARK_AQUA = "\u00A73";
    public static String WHITE = "\u00A7f";

    /** A compile-time constant, stored as the field's constant value */
    public static final String CONSOLE_PREFIX = "[CoreProtect] ";

    public enum Phrase {
        CHECK_CONFIG, LINK_DISCORD, NO_PERMISSION, STATUS_LICENSE, STATUS_VERSION;

        private static final Map<Phrase, String> TEMPLATES = new EnumMap<>(Phrase.class);

        static {
            TEMPLATES.put(CHECK_CONFIG, "Please check config.yml");
            TEMPLATES.put(LINK_DISCORD, "Discord: {0}");
            TEMPLATES.put(NO_PERMISSION, "You do not have permission to do that.");
            TEMPLATES.put(STATUS_LICENSE, "License: {0}");
            TEMPLATES.put(STATUS_VERSION, "Version: {0}");
        }

        public static String build(Phrase phrase, String... params) {
            String output = TEMPLATES.get(phrase);
            String color = "";
            int index = 0;
            for (String param : params) {
                if (index == 0 && color.isEmpty() && param.startsWith("\u00A7")) {
                    color = param;
                    continue;
                }
                output = output.replace("{" + index++ + "}", param);
            }
            return color.isEmpty() ? output : output.replaceFirst(":", ":" + color);
        }
    }

    public static void status(CommandSender sender, String version) {
        sender.sendMessage(WHITE + "----- " + DARK_AQUA + "CoreProtect" + WHITE + " -----");
        sender.sendMessage(DARK_AQUA + Phrase.build(Phrase.STATUS_VERSION, WHITE, "CoreProtect v" + version + "."));
        sender.sendMessage(DARK_AQUA + Phrase.build(Phrase.STATUS_LICENSE, WHITE, "Invalid donation key.")
            + " (" + Phrase.build(Phrase.CHECK_CONFIG) + ")");
        sender.sendMessage(DARK_AQUA + Phrase.build(Phrase.LINK_DISCORD, WHITE, "www.coreprotect.net/discord/"));
    }

    public static void noPermission(CommandSender sender) {
        sender.sendMessage(DARK_AQUA + "CoreProtect " + WHITE + "- " + Phrase.build(Phrase.NO_PERMISSION));
    }

    public static void console(Logger logger, String message) {
        logger.log(Level.INFO, "[CoreProtect] " + message);
        logger.info(Phrase.build(Phrase.STATUS_LICENSE, "Invalid donation key."));
    }

    /** Uses of the name that aren't display text, which must stay as they are */
    public static String[] functional(String version) {
        return new String[] {"CoreProtect", "plugins/CoreProtect/", "CoreProtect/v" + version + " (by Intelli)",
            "# CoreProtect v" + version + " Language Cache"};
    }
}
