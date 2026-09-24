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

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Steps {@code update.check}, {@code update.idle} and {@code update.reload},
 * for the harness's {@code UpdateChecks}.
 *
 * <ul>
 *   <li>{@code update.check}: wait until CoreProtect's update check has found
 *       a newer version, for up to {@code update.timeout.ticks} (default
 *       1200), record it as {@code update.latestVersion}, then run
 *       {@code /co status}.</li>
 *   <li>{@code update.idle}: wait {@code update.idle.ticks} (default 200),
 *       long enough for CoreProtect's first update check to have happened
 *       if it was going to, then record {@code update.latestVersion}.</li>
 *   <li>{@code update.reload}: ask for CoreProtect's release version the
 *       way CoreProtect's hourly update check does, and record the answer as
 *       {@code update.reload.on}; then turn {@code check-updates} off in
 *       config.yml, run {@code /co reload}, ask again, and record that as
 *       {@code update.reload.off}. CoreProtect's hourly check keeps running
 *       after such a reload, but waiting an hour for it isn't practical.</li>
 * </ul>
 */
final class UpdateScenario implements Scenario {

    @Override
    public void run(ScenarioContext ctx) throws Exception {
        switch (ctx.action()) {
            case "check" -> {
                long timeout = Long.parseLong(ctx.param("update.timeout.ticks", "1200"));
                ctx.waitUntil("CoreProtect's update check", timeout, () -> latestVersion(ctx) != null, () -> {
                    ctx.put("update.latestVersion", latestVersion(ctx));
                    // /co status runs off the main thread, so let its output land before the end marker
                    ctx.command("co status", 60);
                });
            }
            case "idle" -> ctx.later(Long.parseLong(ctx.param("update.idle.ticks", "200")),
                () -> ctx.put("update.latestVersion", latestVersion(ctx)));
            case "reload" -> ctx.async(() -> {
                ctx.put("update.reload.on", askForUpdate(ctx));
                ctx.later(1, () -> {
                    turnOffCheckUpdates(ctx.coreProtectFolder().resolve("config.yml"));
                    ctx.command("co reload", 60);
                    ctx.later(80, () -> ctx.async(() -> ctx.put("update.reload.off", askForUpdate(ctx))));
                });
            });
            default -> throw new IllegalArgumentException("Unknown step " + ctx.step());
        }
    }

    /** What CoreProtect's update check found: {@code NetworkHandler.latestVersion()} */
    private static String latestVersion(ScenarioContext ctx) throws ReflectiveOperationException {
        return (String) ctx.coreProtectClass("net.coreprotect.thread.NetworkHandler")
            .getMethod("latestVersion").invoke(null);
    }

    /**
     * Open CoreProtect's update check URL through LibreProtect's network
     * gate, which is where CoreProtect's own {@code openConnection} calls go
     *
     * @return the answer, or {@code failed: <message>}
     */
    private static String askForUpdate(ScenarioContext ctx) throws Exception {
        URLConnection connection = (URLConnection) ctx.coreProtectClass("net.deltik.mc.libreprotect.Egress")
            .getMethod("openConnection", URL.class).invoke(null, new URL("http://update.coreprotect.net/version/"));
        try (InputStream in = connection.getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();
        } catch (IOException e) {
            return "failed: " + e.getMessage();
        }
    }

    private static void turnOffCheckUpdates(Path config) throws IOException {
        String text = Files.exists(config) ? Files.readString(config, StandardCharsets.UTF_8) : "";
        String off = text.replaceAll("(?m)^check-updates:.*$", "check-updates: false");
        Files.writeString(config, off.contains("check-updates: false") ? off : off + "\ncheck-updates: false\n",
            StandardCharsets.UTF_8);
    }
}
