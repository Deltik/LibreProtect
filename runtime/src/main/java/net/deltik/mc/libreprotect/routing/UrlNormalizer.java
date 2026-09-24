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

package net.deltik.mc.libreprotect.routing;

import java.net.URL;
import java.util.Locale;

/**
 * Produces the string that route patterns are matched against.
 *
 * <p>The scheme and host are lowercased, because they are case-insensitive
 * (bStats, for example, connects to {@code bStats.org}). A port equal to the
 * scheme's default is dropped, so {@code https://bstats.org:443/} matches the
 * same routes as {@code https://bstats.org/}. The path and query keep their
 * case. User info and the fragment are dropped, so patterns never see
 * credentials and log messages never contain them.
 */
public final class UrlNormalizer {

    private UrlNormalizer() {
    }

    public static String normalize(URL url) {
        StringBuilder normalized = new StringBuilder();
        normalized.append(url.getProtocol().toLowerCase(Locale.ROOT)).append("://");
        String host = url.getHost();
        if (host != null) {
            normalized.append(host.toLowerCase(Locale.ROOT));
        }
        if (url.getPort() != -1 && url.getPort() != url.getDefaultPort()) {
            normalized.append(':').append(url.getPort());
        }
        normalized.append(url.getFile());
        return normalized.toString();
    }
}
