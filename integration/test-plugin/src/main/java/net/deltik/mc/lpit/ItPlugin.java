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

import org.bukkit.Location;
import org.bukkit.Material;
import org.bukkit.World;
import org.bukkit.block.Block;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Probes CoreProtect on a live server, then shuts the server down.
 *
 * <p>Timeline, in ticks after this plugin enables:
 * <ol>
 *   <li>20: record plugin metadata, query the API, count existing rows at the
 *       probe block, log one placement, run {@code /co status},
 *       {@code /co help}, an unknown subcommand and {@code /co migrate-db}
 *       from the console, and make CoreProtect file an error report</li>
 *   <li>200: count rows at the probe block again (asynchronously, as the API
 *       recommends)</li>
 *   <li>400: write {@code results.properties} and shut the server down. The
 *       wait gives CoreProtect's network thread time for its startup
 *       requests.</li>
 * </ol>
 *
 * <p>Markers ({@code [LPIT] ...}) in the server log delimit command output
 * for the harness.
 */
public final class ItPlugin extends JavaPlugin {

    static final String USER = "lpit";

    private final Map<String, String> results = new TreeMap<>();

    @Override
    public void onEnable() {
        getServer().getScheduler().runTaskLater(this, this::probe, 20L);
        getServer().getScheduler().runTaskLater(this, () ->
            getServer().getScheduler().runTaskAsynchronously(this, () -> put("lookup.after", countRows())), 200L);
        getServer().getScheduler().runTaskLater(this, this::finish, 400L);
    }

    private void probe() {
        Plugin coreProtect = getServer().getPluginManager().getPlugin("CoreProtect");
        put("coreprotect.present", coreProtect != null);
        if (coreProtect == null) {
            return;
        }
        put("coreprotect.enabled", coreProtect.isEnabled());
        put("coreprotect.version", coreProtect.getDescription().getVersion());
        put("coreprotect.main", coreProtect.getDescription().getMain());
        put("coreprotect.class", coreProtect.getClass().getName());
        put("coreprotect.class.super", coreProtect.getClass().getSuperclass().getName());
        try {
            // The version that CoreProtect compares with its database's, its patches' and its features'
            put("coreprotect.ownVersion", Class.forName("net.coreprotect.utility.VersionUtils", true,
                coreProtect.getClass().getClassLoader()).getMethod("getPluginVersion").invoke(null));
        } catch (ReflectiveOperationException | RuntimeException e) {
            put("coreprotect.ownVersion.error", e);
        }

        try {
            Object api = api();
            put("api.enabled", call(api, "isEnabled"));
            put("api.version", call(api, "APIVersion"));
            put("lookup.before", countRows());

            Method logPlacement = api.getClass().getMethod("logPlacement",
                String.class, Location.class, Material.class, org.bukkit.block.data.BlockData.class);
            put("api.logPlacement", logPlacement.invoke(api, USER, probeLocation(), Material.STONE, null));
        } catch (ReflectiveOperationException | RuntimeException e) {
            put("api.error", e);
            getLogger().severe("[LPIT] API probe failed: " + e);
        }

        command("co status");
        command("co help");
        command("co lpit-unknown");
        command("co migrate-db");

        try {
            Class<?> errorReporter = Class.forName("net.coreprotect.utility.ErrorReporter", true,
                coreProtect.getClass().getClassLoader());
            Object queued = errorReporter.getMethod("report", Throwable.class, boolean.class)
                .invoke(null, new IllegalStateException("LPIT deliberate error report"), false);
            put("errorReporter.queued", queued);
        } catch (ClassNotFoundException e) {
            put("errorReporter.queued", "absent");
        } catch (ReflectiveOperationException | RuntimeException e) {
            put("errorReporter.error", e);
        }
    }

    private void command(String command) {
        getLogger().info("[LPIT] begin " + command);
        put("command." + command.replace(' ', '.'), getServer().dispatchCommand(getServer().getConsoleSender(), command));
        getLogger().info("[LPIT] end " + command);
    }

    private Object api() throws ReflectiveOperationException {
        Plugin coreProtect = getServer().getPluginManager().getPlugin("CoreProtect");
        return coreProtect.getClass().getMethod("getAPI").invoke(coreProtect);
    }

    private static Object call(Object target, String method) throws ReflectiveOperationException {
        return target.getClass().getMethod(method).invoke(target);
    }

    private Location probeLocation() {
        World world = getServer().getWorlds().get(0);
        return new Location(world, 7, 100, 7);
    }

    /**
     * @return rows that CoreProtect has for the probe block, or -1 on error
     */
    private int countRows() {
        try {
            Object api = api();
            Block block = probeLocation().getBlock();
            Object rows = api.getClass().getMethod("blockLookup", Block.class, int.class).invoke(api, block, 0);
            return rows == null ? -1 : ((List<?>) rows).size();
        } catch (ReflectiveOperationException | RuntimeException e) {
            put("lookup.error", e);
            return -1;
        }
    }

    private synchronized void put(String key, Object value) {
        results.put(key, String.valueOf(value).replace('\n', ' '));
    }

    private void finish() {
        StringBuilder text = new StringBuilder();
        synchronized (this) {
            results.forEach((key, value) -> text.append(key).append('=').append(value).append('\n'));
        }
        try {
            Path file = getDataFolder().toPath().resolve("results.properties");
            Files.createDirectories(file.getParent());
            Files.writeString(file, text.toString(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            getLogger().severe("[LPIT] could not write results: " + e);
        }
        getLogger().info("[LPIT] done, shutting down");
        getServer().shutdown();
    }
}
