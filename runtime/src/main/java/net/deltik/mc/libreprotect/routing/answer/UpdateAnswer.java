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

package net.deltik.mc.libreprotect.routing.answer;

/**
 * Answers CoreProtect's update checks with the version that is running, so
 * CoreProtect announces no update.
 *
 * <p>CoreProtect sends its version in the {@code User-Agent} header, as
 * {@code CoreProtect/v<version> (by Intelli)}. Without it, the answer is
 * {@value #NO_UPDATE}, which is never newer than the running version.
 */
public final class UpdateAnswer implements Answer {

    static final String NO_UPDATE = "0.0";

    private static final String USER_AGENT_PREFIX = "CoreProtect/v";

    @Override
    public Response answer(Request request) {
        return Response.text(runningVersion(request.header("User-Agent")));
    }

    private static String runningVersion(String userAgent) {
        if (userAgent == null || !userAgent.startsWith(USER_AGENT_PREFIX)) {
            return NO_UPDATE;
        }
        String version = userAgent.substring(USER_AGENT_PREFIX.length()).split(" ")[0];
        return version.isEmpty() ? NO_UPDATE : version;
    }
}
