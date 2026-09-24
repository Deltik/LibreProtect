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

package net.deltik.mc.libreprotect.transformer;

/**
 * Upstream no longer matches an assumption that LibreProtect depends on.
 *
 * <p>The message should say what was expected, what was found, and where a
 * maintainer should look.
 */
final class ContractViolation extends RuntimeException {

    private static final long serialVersionUID = 1L;

    ContractViolation(String message) {
        super(message);
    }

    static void require(boolean condition, String message) {
        if (!condition) {
            throw new ContractViolation(message);
        }
    }
}
