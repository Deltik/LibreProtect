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
import java.io.Reader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

/**
 * Probes CoreProtect on a live server, then shuts the server down.
 *
 * <p>The harness names the steps for a boot in {@code scenario.properties} in
 * this plugin's data folder ({@code steps=default,translation}), along with
 * any values the steps read. Without that file, only the default step runs.
 * Steps run one after another; each starts once the work that the one before
 * it scheduled is done. Then this plugin writes {@code results.properties} and
 * shuts the server down, or after {@code timeout.ticks} (default 3600) if the
 * steps take longer. A step named {@code feature} or {@code feature.action}
 * goes to the {@link Scenario} for that feature in {@link #FEATURES}.
 *
 * <p>The default step, in ticks after it starts (when this plugin enables,
 * if it runs first):
 * <ol>
 *   <li>20: record plugin metadata, query the API, count existing rows at the
 *       probe block, log one placement, run {@code /co status},
 *       {@code /co help}, an unknown subcommand and {@code /co migrate-db}
 *       from the console, and make CoreProtect file an error report</li>
 *   <li>200: count rows at the probe block again (asynchronously, as the API
 *       recommends)</li>
 *   <li>400: done. The wait gives CoreProtect's network thread time for its
 *       startup requests.</li>
 * </ol>
 *
 * <p>Markers ({@code [LPIT] ...}) in the server log delimit command output
 * for the harness.
 */
public final class ItPlugin extends JavaPlugin {

    static final String USER = "lpit";

    /** Scenarios by feature, the part of a step's name before the first dot */
    private static final Map<String, Scenario> FEATURES = Map.of(
        "translation", new TranslationScenario(),
        "update", new UpdateScenario(),
        "migration", new MigrationScenario(),
        "auto-purge", new AutoPurgeScenario(),
        "capability", new CapabilityScenario());

    private final Map<String, String> results = new TreeMap<>();
    private final Deque<String> steps = new ArrayDeque<>();
    private final Properties scenario = new Properties();
    private String current;
    private boolean finished;

    @Override
    public void onEnable() {
        Path file = getDataFolder().toPath().resolve("scenario.properties");
        if (Files.exists(file)) {
            try (Reader in = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                scenario.load(in);
            } catch (IOException e) {
                put("scenario.error", e);
            }
        }
        for (String step : scenario.getProperty("steps", "default").split(",")) {
            if (!step.isBlank()) {
                steps.add(step.trim());
            }
        }
        put("scenario.steps", String.join(",", steps));

        long timeout = Long.parseLong(scenario.getProperty("timeout.ticks", "3600"));
        getServer().getScheduler().runTaskLater(this, () -> {
            if (!finished) {
                put("scenario.timeout", "step " + current + " still running after " + timeout + " ticks");
                finish();
            }
        }, timeout);
        nextStep();
    }

    /** Start the next step, or finish after the last one. Main thread only. */
    private void nextStep() {
        while (!finished) {
            String step = steps.poll();
            if (step == null) {
                finish();
                return;
            }
            String feature = step.contains(".") ? step.substring(0, step.indexOf('.')) : step;
            Scenario handler = step.equals("default") ? this::defaultStep : FEATURES.get(feature);
            if (handler == null) {
                put("scenario.error", "unknown step " + step);
                continue;
            }
            current = step;
            new ScenarioContext(this, step, scenario).start(handler);
            return;
        }
    }

    /** Called by a step's context once all of the step's work is done */
    void stepDone() {
        if (getServer().isPrimaryThread()) {
            nextStep();
        } else {
            getServer().getScheduler().runTask(this, this::nextStep);
        }
    }

    private void defaultStep(ScenarioContext ctx) {
        ctx.later(20, this::probe);
        ctx.later(200, () -> ctx.async(() -> put("lookup.after", countRows())));
        // Nothing to do at 400; waiting until then is the point
        ctx.later(400, () -> {
        });
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

    boolean command(String command) {
        getLogger().info("[LPIT] begin " + command);
        boolean dispatched = dispatch(command);
        getLogger().info("[LPIT] end " + command);
        return dispatched;
    }

    /** Run a console command and record whether it was dispatched */
    boolean dispatch(String command) {
        boolean dispatched = getServer().dispatchCommand(getServer().getConsoleSender(), command);
        put("command." + command.replace(' ', '.'), dispatched);
        return dispatched;
    }

    Object api() throws ReflectiveOperationException {
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

    synchronized void put(String key, Object value) {
        results.put(key, String.valueOf(value).replace('\n', ' '));
    }

    private void finish() {
        if (finished) {
            return;
        }
        finished = true;
        StringBuilder text = new StringBuilder();
        synchronized (this) {
            results.forEach((key, value) -> text.append(key.replaceAll("[\\\\=: #!]", "\\\\$0")).append('=')
                .append(value.replace("\\", "\\\\")).append('\n'));
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
