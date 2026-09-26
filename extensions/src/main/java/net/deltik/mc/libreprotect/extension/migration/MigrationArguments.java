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

package net.deltik.mc.libreprotect.extension.migration;

import net.deltik.mc.libreprotect.extension.common.Engine;

import java.util.Locale;
import java.util.Set;
import java.util.StringJoiner;

/**
 * The arguments of {@code /co migrate-db <engine> [--full-validation]}.
 */
final class MigrationArguments {

    static final String FULL_VALIDATION = "--full-validation";

    private final Engine target;
    private final boolean fullValidation;

    private MigrationArguments(Engine target, boolean fullValidation) {
        this.target = target;
        this.fullValidation = fullValidation;
    }

    /**
     * @param arguments the command's arguments, starting with {@code migrate-db}
     * @return the parsed arguments, or {@code null} if they don't name
     *         exactly one engine, or include anything other than
     *         {@value #FULL_VALIDATION}
     */
    static MigrationArguments parse(String[] arguments) {
        Engine target = null;
        boolean fullValidation = false;
        for (int i = 1; arguments != null && i < arguments.length; i++) {
            String argument = arguments[i] == null ? "" : arguments[i].trim();
            if (argument.isEmpty()) {
                continue;
            }
            if (argument.toLowerCase(Locale.ROOT).equals(FULL_VALIDATION)) {
                fullValidation = true;
                continue;
            }
            Engine engine = Engine.fromConfigName(argument);
            if (engine == null || target != null) {
                return null;
            }
            target = engine;
        }
        return target == null ? null : new MigrationArguments(target, fullValidation);
    }

    /**
     * @return the command's usage for the engines a migration can go to, or
     *         with a placeholder if there are none
     */
    static String usage(Set<Engine> engines) {
        StringJoiner names = new StringJoiner("|", "<", ">");
        names.setEmptyValue("<database>");
        for (Engine engine : Engine.values()) {
            if (engines.contains(engine)) {
                names.add(engine.configName());
            }
        }
        return "/co migrate-db " + names + " [" + FULL_VALIDATION + "]";
    }

    Engine target() {
        return target;
    }

    boolean fullValidation() {
        return fullValidation;
    }
}
