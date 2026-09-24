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

import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;

/**
 * What a step works with: its values from {@code scenario.properties}, the
 * results that go to {@code results.properties}, the scheduler, console
 * commands and CoreProtect.
 *
 * <p>The step is done once everything it scheduled through this context has
 * run. If the step or its scheduled work throws, the exception is recorded as
 * {@code <step>.error} and the rest of the step's work still runs.
 */
public final class ScenarioContext {

    /** Work that may throw; see the class comment */
    @FunctionalInterface
    public interface Task {
        void run() throws Exception;
    }

    /** A test for {@link #waitUntil} that may throw */
    @FunctionalInterface
    public interface Condition {
        boolean test() throws Exception;
    }

    private final ItPlugin plugin;
    private final String step;
    private final Properties scenario;
    private final AtomicInteger pending = new AtomicInteger();
    private final AtomicBoolean done = new AtomicBoolean();

    ScenarioContext(ItPlugin plugin, String step, Properties scenario) {
        this.plugin = plugin;
        this.step = step;
        this.scenario = scenario;
    }

    /** The step's full name, such as {@code migration.seed} */
    public String step() {
        return step;
    }

    /** The step's name after the feature and its dot, such as {@code seed}, or "" */
    public String action() {
        int dot = step.indexOf('.');
        return dot < 0 ? "" : step.substring(dot + 1);
    }

    public JavaPlugin plugin() {
        return plugin;
    }

    /** A value from scenario.properties, or null */
    public String param(String key) {
        return scenario.getProperty(key);
    }

    public String param(String key, String fallback) {
        return scenario.getProperty(key, fallback);
    }

    /** Record a result in results.properties. Prefix keys with the feature's name. */
    public void put(String key, Object value) {
        plugin.put(key, value);
    }

    /** Run on the main thread after the given number of ticks */
    public void later(long ticks, Task task) {
        hold();
        plugin.getServer().getScheduler().runTaskLater(plugin, () -> runHeld(task), ticks);
    }

    /** Run off the main thread, now */
    public void async(Task task) {
        hold();
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, () -> runHeld(task));
    }

    /**
     * Test the condition on the main thread every 10 ticks until it holds,
     * then run {@code then}. If it doesn't hold within {@code timeoutTicks},
     * record {@code <step>.timeout=<what>} instead.
     */
    public void waitUntil(String what, long timeoutTicks, Condition condition, Task then) {
        later(1, () -> {
            if (condition.test()) {
                then.run();
            } else if (timeoutTicks <= 0) {
                put(step + ".timeout", what);
            } else {
                later(9, () -> waitUntil(what, timeoutTicks - 10, condition, then));
            }
        });
    }

    /**
     * Run a console command between {@code [LPIT] begin <command>} and
     * {@code [LPIT] end <command>} in the server log, and record whether it
     * was dispatched as {@code command.<command, with dots for spaces>}.
     * Output of commands that CoreProtect runs asynchronously can land after
     * the end marker; see {@link #command(String, long)}.
     */
    public boolean command(String command) {
        return plugin.command(command);
    }

    /**
     * Like {@link #command(String)}, but write the end marker the given
     * number of ticks later, so that asynchronous output lands before it
     */
    public boolean command(String command, long settleTicks) {
        log("begin " + command);
        boolean dispatched = plugin.dispatch(command);
        later(settleTicks, () -> log("end " + command));
        return dispatched;
    }

    /** Write {@code [LPIT] <message>} to the server log, such as a marker for the harness */
    public void log(String message) {
        plugin.getLogger().info("[LPIT] " + message);
    }

    /** CoreProtect or LibreProtect, whichever is installed, or null */
    public Plugin coreProtect() {
        return plugin.getServer().getPluginManager().getPlugin("CoreProtect");
    }

    /** CoreProtect's {@code CoreProtectAPI} */
    public Object api() throws ReflectiveOperationException {
        return plugin.api();
    }

    /**
     * Call the public method with this name and number of arguments.
     * Overloads with the same number of arguments are tried in no particular
     * order until one accepts the arguments.
     */
    public static Object call(Object target, String method, Object... arguments) throws ReflectiveOperationException {
        for (Method candidate : target.getClass().getMethods()) {
            if (candidate.getName().equals(method) && candidate.getParameterCount() == arguments.length) {
                try {
                    return candidate.invoke(target, arguments);
                } catch (IllegalArgumentException e) {
                    // Wrong overload; try the next one
                }
            }
        }
        throw new NoSuchMethodException(target.getClass().getName() + "." + method + " with " + arguments.length + " arguments");
    }

    /** A class from CoreProtect's JAR, such as {@code net.coreprotect.config.ConfigHandler} */
    public Class<?> coreProtectClass(String name) throws ClassNotFoundException {
        return Class.forName(name, true, coreProtect().getClass().getClassLoader());
    }

    /** CoreProtect's data folder, which LibreProtect shares: {@code plugins/CoreProtect} */
    public Path coreProtectFolder() {
        return coreProtect().getDataFolder().toPath();
    }

    /** Run the step; {@link ItPlugin#stepDone} follows once its work is done */
    void start(Scenario scenario) {
        hold();
        runHeld(() -> scenario.run(this));
    }

    private void hold() {
        pending.incrementAndGet();
    }

    private void runHeld(Task task) {
        try {
            task.run();
        } catch (Exception | LinkageError e) {
            Throwable cause = e instanceof InvocationTargetException && e.getCause() != null ? e.getCause() : e;
            put(step + ".error", cause);
            plugin.getLogger().log(Level.SEVERE, "[LPIT] step " + step + " failed", cause);
        } finally {
            if (pending.decrementAndGet() == 0 && done.compareAndSet(false, true)) {
                plugin.stepDone();
            }
        }
    }
}
