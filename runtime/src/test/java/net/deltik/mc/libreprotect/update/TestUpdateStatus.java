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

package net.deltik.mc.libreprotect.update;

/**
 * Sets and resets {@link UpdateStatus} for tests outside this package.
 * Tests that change it must reset it afterward, since it is shared.
 */
public final class TestUpdateStatus {

    private TestUpdateStatus() {
    }

    /**
     * Record a release as a check would
     *
     * @param version          a release version, such as {@code 24.1-libre2}
     * @param pageUrl          the release's page
     * @param syntheticVersion the version CoreProtect was told
     */
    public static void set(String version, String pageUrl, String syntheticVersion) {
        UpdateStatus.set(new Release(ForkVersion.parseRelease(version), pageUrl), syntheticVersion);
    }

    /** Forget every release, including those reported earlier */
    public static void reset() {
        UpdateStatus.reset();
    }
}
