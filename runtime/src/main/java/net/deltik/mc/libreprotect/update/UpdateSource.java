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

import java.io.IOException;
import java.net.URL;
import java.util.Optional;

/**
 * Somewhere LibreProtect can ask for its newest release, configured in
 * {@code update-sources} of {@code libreprotect.yml}: {@link ModrinthSource}
 * or {@link GitHubSource}.
 *
 * <p>A source is only asked when the network policy answers CoreProtect's
 * update check (see {@link UpdateCheck}). Its request names LibreProtect
 * but carries no version, server port or key (see {@link UpdateHttp}); the
 * source sees the server's IP address, as with any request.
 */
public abstract class UpdateSource {

    /** The subclasses in this package are the only types */
    UpdateSource() {
    }

    /**
     * @return the type as written in {@code libreprotect.yml}, such as
     *         {@code modrinth}
     */
    public abstract String type();

    /**
     * @return the API's base URL, without a final slash
     */
    public abstract String api();

    /**
     * @return what this source is, for messages, such as
     *         {@code Modrinth project libreprotect}
     */
    public abstract String describe();

    /**
     * @return the URL this source requests
     */
    abstract URL requestUrl() throws IOException;

    /**
     * Ask this source for LibreProtect's newest release.
     *
     * @return the newest release, or empty if the source has none
     * @throws IOException if the source didn't answer: the request failed, its
     *         status wasn't 200, or the response wasn't what the source's API
     *         returns
     */
    abstract Optional<Release> newestRelease(UpdateHttp http) throws IOException;

    @Override
    public String toString() {
        return describe() + " at " + api();
    }
}
