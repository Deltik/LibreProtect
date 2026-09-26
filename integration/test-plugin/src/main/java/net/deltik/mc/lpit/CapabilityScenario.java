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

package net.deltik.mc.lpit;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Step {@code capability}, for the harness's {@code CapabilityChecks}: write
 * the capability report of the running server, which LibreProtect's
 * extensions probed with the server's own API and the libraries it
 * downloaded, to {@code capabilities.tsv} in this plugin's data folder, for
 * the harness to compare with the one the build bundled. Results, prefixed
 * {@code capability.}: {@code lines}, the report's number of lines.
 */
final class CapabilityScenario implements Scenario {

    private static final String REPORT = "net.deltik.mc.libreprotect.extension.upstream.CapabilityReport";

    @Override
    public void run(ScenarioContext ctx) throws Exception {
        if (!ctx.action().isEmpty()) {
            throw new IllegalArgumentException("Unknown step " + ctx.step());
        }
        if (ctx.coreProtect() == null || !ctx.coreProtect().isEnabled()) {
            throw new IllegalStateException("CoreProtect isn't enabled; see the server log");
        }
        String report = (String) ctx.coreProtectClass(REPORT).getMethod("current").invoke(null);
        Path file = ctx.plugin().getDataFolder().toPath().resolve("capabilities.tsv");
        Files.createDirectories(file.getParent());
        Files.writeString(file, report, StandardCharsets.UTF_8);
        ctx.put("capability.lines", report.lines().count());
    }
}
