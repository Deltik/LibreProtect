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

import net.deltik.mc.libreprotect.extension.upstream.Capabilities;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Skips tests that need the CoreProtect being built to use a capability in
 * one particular way, such as tests of CoreProtect 25's codecs.
 */
public final class AssumeCapability {

    private AssumeCapability() {
    }

    /**
     * @param id the capability's ID, such as {@code migrate-db.transcoding}
     * @param strategy the way the test needs, such as {@code statement-codecs}
     * @return how the CoreProtect being built supports the capability
     */
    public static Choice<?> strategy(String id, String strategy) {
        Choice<?> choice = Capabilities.current().get(id);
        assumeTrue(choice.strategy().equals(strategy),
            () -> "This CoreProtect's " + id + " is " + choice.strategy() + ", not " + strategy);
        return choice;
    }
}
