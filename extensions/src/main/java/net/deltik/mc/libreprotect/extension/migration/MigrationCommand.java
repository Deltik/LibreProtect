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

package net.deltik.mc.libreprotect.extension.migration;

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.extension.common.Console;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.upstream.CoreProtectMigration;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;

import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * {@code /co migrate-db <engine> [--full-validation]}: copies CoreProtect's
 * data from the database it uses now to another engine and switches the
 * running server over to it. Only the console may run it, and only one
 * migration runs at a time. The work happens on its own thread.
 */
public final class MigrationCommand {

    private static final AtomicBoolean RUNNING = new AtomicBoolean();

    private MigrationCommand() {
    }

    /**
     * Handle the command. Never throws.
     *
     * @param argumentArray the command arguments: {@code argumentArray[0]} is
     *                      {@code "migrate-db"}
     */
    public static void run(CommandSender user, String[] argumentArray) {
        Console console = new Console(user);
        MigrationBridge bridge;
        try {
            bridge = CoreProtectMigration.create();
        } catch (RuntimeException | LinkageError e) {
            console.error("Database migration isn't available: " + e);
            return;
        }
        run(user, argumentArray, bridge);
    }

    /**
     * Handle the command with the given bridge, migrating on a thread of its
     * own. Never throws.
     *
     * @param argumentArray the command arguments: {@code argumentArray[0]} is
     *                      {@code "migrate-db"}
     */
    public static void run(CommandSender user, String[] argumentArray, MigrationBridge bridge) {
        run(user, argumentArray, bridge, command -> {
            Thread thread = new Thread(command, "LibreProtect migration");
            // CoreProtect's shutdown waits for the migration, which stops within seconds; after that
            // wait, nothing may keep the server from exiting. Every write is atomic or to a marked target.
            thread.setDaemon(true);
            thread.start();
        });
    }

    /**
     * Handle the command with the given bridge, running the migration
     * through {@code executor}. Never throws.
     */
    static void run(CommandSender user, String[] argumentArray, MigrationBridge bridge, Executor executor) {
        Console console = new Console(user);
        boolean claimed = false;
        MigrationSession session = null;
        try {
            if (!(user instanceof ConsoleCommandSender)) {
                console.error("Only the server console can run /co migrate-db.");
                return;
            }
            String unavailable = bridge.unavailableReason();
            if (unavailable != null) {
                console.error("/co migrate-db isn't available with this CoreProtect build: " + unavailable);
                return;
            }
            MigrationArguments arguments = MigrationArguments.parse(argumentArray);
            if (arguments == null) {
                Set<Engine> targets = targets(bridge);
                console.say("Usage: " + MigrationArguments.usage(targets));
                console.detail("Copies CoreProtect's data from the database it uses now to the one you name, then"
                    + " switches CoreProtect to it. " + MigrationArguments.FULL_VALIDATION + " compares every copied"
                    + " row instead of a sample.");
                if (targets.isEmpty()) {
                    console.detail("No database can be migrated to with this CoreProtect build: " + whyNoTargets(bridge));
                }
                return;
            }
            Engine target = arguments.target();
            if (target == bridge.activeEngine()) {
                console.error("CoreProtect already uses " + target.displayName()
                    + ". Name a different database to migrate to.");
                return;
            }
            String targetUnavailable = bridge.unavailableReason(target);
            if (targetUnavailable != null) {
                console.error("Migrating to " + target.displayName() + " isn't available with this CoreProtect build: "
                    + targetUnavailable);
                return;
            }
            if (!bridge.engines().contains(target)) {
                console.error(target.displayName() + " isn't available with this CoreProtect version. Usage: "
                    + MigrationArguments.usage(targets(bridge)));
                return;
            }
            if (!RUNNING.compareAndSet(false, true)) {
                console.error("A migration is already running.");
                return;
            }
            claimed = true;
            try {
                session = bridge.claim(target);
            } catch (MigrationException e) {
                console.error(e.getMessage());
                for (String detail : e.details()) {
                    console.detail(detail);
                }
                return;
            }
            Migration migration = new Migration(bridge, session, console, target, arguments.fullValidation(),
                System::nanoTime, new SecureRandom());
            executor.execute(() -> {
                try {
                    migration.run();
                } finally {
                    RUNNING.set(false);
                }
            });
            claimed = false;
            session = null;
        } catch (RuntimeException | Error e) {
            // Upstream calls this through reflection and only expects exceptions it can report as a missing command
            LibreProtectLogger.severe("/co migrate-db failed to start: " + e);
            console.error("The migration couldn't start: " + e);
        } finally {
            if (session != null) {
                session.close();
            }
            if (claimed) {
                RUNNING.set(false);
            }
        }
    }

    /**
     * @return the databases that a migration can go to now: those that this
     *         CoreProtect has and a migration can write, but not the one in
     *         use, nor one that migrating to from it can't work with this
     *         CoreProtect build
     */
    private static Set<Engine> targets(MigrationBridge bridge) {
        Set<Engine> targets = EnumSet.noneOf(Engine.class);
        Engine active = bridge.activeEngine();
        for (Engine engine : bridge.engines()) {
            if (engine != active && bridge.unavailableReason(engine) == null) {
                targets.add(engine);
            }
        }
        return targets;
    }

    /**
     * @return why a migration can't go to any of the databases that this
     *         CoreProtect has besides the one in use, each reason once
     */
    private static String whyNoTargets(MigrationBridge bridge) {
        Set<String> reasons = new LinkedHashSet<>();
        Engine active = bridge.activeEngine();
        for (Engine engine : bridge.engines()) {
            String reason = engine == active ? null : bridge.unavailableReason(engine);
            if (reason != null) {
                reasons.add(reason);
            }
        }
        return reasons.isEmpty() ? "CoreProtect has no other database that a migration can write"
            : String.join("; ", reasons);
    }
}
