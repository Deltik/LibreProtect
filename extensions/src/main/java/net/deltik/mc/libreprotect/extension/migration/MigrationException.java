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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Why a migration can't start or didn't finish, in words for the person who
 * ran the command. The message is the headline; the details are follow-up
 * lines, such as what state the databases were left in.
 */
public class MigrationException extends Exception {

    private static final long serialVersionUID = 1L;

    private final List<String> details;

    public MigrationException(String message) {
        this(message, null, Collections.emptyList());
    }

    public MigrationException(String message, Throwable cause) {
        this(message, cause, Collections.emptyList());
    }

    public MigrationException(String message, Throwable cause, List<String> details) {
        super(message, cause);
        this.details = Collections.unmodifiableList(new ArrayList<>(details));
    }

    /**
     * @return lines that explain the headline further, possibly none
     */
    public List<String> details() {
        return details;
    }
}
