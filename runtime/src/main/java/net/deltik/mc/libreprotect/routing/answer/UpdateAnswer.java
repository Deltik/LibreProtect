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

import net.deltik.mc.libreprotect.LibreProtectVersion;
import net.deltik.mc.libreprotect.update.UpdateCheck;

import java.io.IOException;
import java.util.Collections;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Answers CoreProtect's update checks from LibreProtect's update sources.
 *
 * <p>CoreProtect asks two URLs on {@code update.coreprotect.net}:
 * <ul>
 *   <li>{@code /version/}: the {@link UpdateCheck} asks the update sources
 *       and reports a newer release in a form CoreProtect understands.</li>
 *   <li>{@code /version-edge/}: CoreProtect's edge builds, which LibreProtect
 *       doesn't follow. The answer is always "no update", without asking
 *       anyone. Stock CoreProtect Community Edition ignores this answer, but
 *       LibreProtect is built without that edition check.</li>
 * </ul>
 *
 * <p>"No update" is the running upstream version, which CoreProtect never
 * sees as newer than itself. If every update source fails, the request fails
 * too, and CoreProtect carries on as if offline.
 */
public final class UpdateAnswer implements Answer {

    static final String NO_UPDATE = "0.0";

    private static final String USER_AGENT_PREFIX = "CoreProtect/v";
    /** What CoreProtect reads as a version: digits and dots, fewer than 10 characters */
    private static final Pattern VERSION = Pattern.compile("\\d+(\\.\\d+)+");

    private final UpdateCheck check;

    /**
     * Answer every update check with "no update", without asking anyone.
     */
    public UpdateAnswer() {
        this(new UpdateCheck(Collections.emptyList(), LibreProtectVersion.getForkVersion(),
            LibreProtectVersion.getUpstreamVersion(), null));
    }

    /**
     * @param check asks the update sources
     */
    public UpdateAnswer(UpdateCheck check) {
        this.check = Objects.requireNonNull(check, "check");
    }

    /**
     * @throws IOException if CoreProtect asked for its release version and
     *         every update source failed
     */
    @Override
    public Response answer(Request request) throws IOException {
        String path = request.url().getPath().toLowerCase(Locale.ROOT);
        if (path.equals("/version/") || path.equals("/version")) {
            Optional<String> synthetic = check.check();
            if (synthetic.isPresent()) {
                return Response.text(synthetic.get());
            }
        }
        return Response.text(noUpdate(request));
    }

    /**
     * @return the running upstream version, or else the version in
     *         CoreProtect's {@code User-Agent}, or else {@value #NO_UPDATE}
     */
    private String noUpdate(Request request) {
        String running = check.runningUpstreamVersion();
        if (isShortVersion(running)) {
            return running;
        }
        String userAgent = request.header("User-Agent");
        if (userAgent != null && userAgent.startsWith(USER_AGENT_PREFIX)) {
            String version = userAgent.substring(USER_AGENT_PREFIX.length()).split(" ")[0];
            if (isShortVersion(version)) {
                return version;
            }
        }
        return NO_UPDATE;
    }

    private static boolean isShortVersion(String version) {
        return version != null && version.length() < 10 && VERSION.matcher(version).matches();
    }
}
