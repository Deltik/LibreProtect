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

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Steps {@code translation} and {@code translation.*}, for the harness's
 * {@code TranslationChecks}.
 *
 * <p>{@code translation}: record CoreProtect's version as its language cache
 * names it ({@code translation.version}), wait for CoreProtect's translation
 * request, which its network thread makes as the server starts, then run
 * {@code co help}. By default, it waits until
 * {@code plugins/CoreProtect/.language} has content, for at most
 * {@code translation.wait.ticks} (default 600). With
 * {@code translation.wait=ticks}, for a server that saves no cache, it waits
 * that many ticks instead.
 */
final class TranslationScenario implements Scenario {

    @Override
    public void run(ScenarioContext ctx) throws Exception {
        // The version that CoreProtect names its cache after
        ctx.put("translation.version", ctx.coreProtectClass("net.coreprotect.utility.VersionUtils")
            .getMethod("getPluginVersion").invoke(null));

        long ticks = Long.parseLong(ctx.param("translation.wait.ticks", "600"));
        Path cache = ctx.coreProtectFolder().resolve(".language");
        ScenarioContext.Task help = () -> ctx.command("co help", 20);
        if (ctx.param("translation.wait", "cache").equals("ticks")) {
            ctx.later(ticks, help);
        } else {
            ctx.waitUntil("translation cache", ticks, () -> Files.isRegularFile(cache) && Files.size(cache) > 0, help);
        }
    }
}
