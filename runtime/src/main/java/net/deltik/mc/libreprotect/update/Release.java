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

import java.util.Objects;

/**
 * A LibreProtect release that an {@link UpdateSource} reported, and the page
 * where it can be downloaded.
 */
public final class Release {

    private final ForkVersion version;
    private final String pageUrl;

    /**
     * @param version a release version
     * @param pageUrl the release's page, an {@code https://} URL
     */
    Release(ForkVersion version, String pageUrl) {
        this.version = Objects.requireNonNull(version, "version");
        this.pageUrl = Objects.requireNonNull(pageUrl, "pageUrl");
    }

    public ForkVersion version() {
        return version;
    }

    /**
     * @return the release's page, such as
     *         {@code https://modrinth.com/plugin/libreprotect/version/24.1-libre2}
     */
    public String pageUrl() {
        return pageUrl;
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof Release)) {
            return false;
        }
        Release release = (Release) other;
        return version.equals(release.version) && pageUrl.equals(release.pageUrl);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, pageUrl);
    }

    @Override
    public String toString() {
        return version + " (" + pageUrl + ")";
    }
}
