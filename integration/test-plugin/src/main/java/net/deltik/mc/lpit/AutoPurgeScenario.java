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

import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

/**
 * Step {@code auto-purge}, for the harness's {@code AutoPurgeChecks}: log a
 * block placement A, wait until it is stored, wait 2 seconds, log B and then
 * C, have LibreProtect purge everything before B, and look all three up
 * again. C makes B an ordinary row rather than its table's newest, which
 * SQLite and MySQL would keep anyway.
 *
 * <p>With {@code auto-purge.orphans=true} (CoreProtect 25, not ClickHouse),
 * it also adds two {@code entity_spawn} rows before purging: a despawned
 * entity as old as A that nothing refers to, which the purge's orphan
 * cleanup must remove, and a newer one linked to A's block row, whose link
 * it must clear once A is gone.
 *
 * <p>The purge goes through {@code AutoPurgeService.runNow}, LibreProtect's
 * hook for this test, which runs on the auto-purge thread with every stop
 * rule but without the 30-day minimum. Results, prefixed
 * {@code auto-purge.}: {@code time.a}, {@code time.b} and {@code time.c} as
 * stored, {@code cutoff}, {@code removed} (runNow's count), {@code rows.a},
 * {@code rows.b} and {@code rows.c} (lookups afterward), and for orphans
 * {@code orphan.rows} and {@code linked.block}. {@code /co status} runs
 * last, between {@code [LPIT]} markers.
 *
 * <p>Step {@code auto-purge.interrupt} (SQLite) seeds
 * {@code auto-purge.interrupt.rows} (default 30,000) block rows from long
 * ago and one of now, has auto-purge remove the old ones through the same
 * hook, and ends once some are gone, so that the server stops while the
 * purge runs. Results: {@code seeded}, {@code cutoff}, {@code remaining}
 * (old rows left then) and {@code running} (whether the purge still ran),
 * prefixed {@code auto-purge.interrupt.}. Step {@code auto-purge.resume}, on
 * the next boot, purges the rest: {@code before} and {@code after} (old rows),
 * {@code removed} and {@code newer} (rows of now), prefixed
 * {@code auto-purge.resume.}.
 */
final class AutoPurgeScenario implements Scenario {

    private static final String SERVICE = "net.deltik.mc.libreprotect.extension.purge.AutoPurgeService";
    private static final long STORE_TIMEOUT_MILLIS = 60_000;
    /** What {@code auto-purge.interrupt} purges before: its seeded rows, and nothing CoreProtect logged */
    private static final long INTERRUPT_CUTOFF = 1_000_000;

    @Override
    public void run(ScenarioContext ctx) throws Exception {
        if (ctx.coreProtect() == null || !ctx.coreProtect().isEnabled()) {
            throw new IllegalStateException("CoreProtect isn't enabled; see the server log");
        }
        switch (ctx.action()) {
            case "" -> purge(ctx);
            case "interrupt" -> interrupt(ctx);
            case "resume" -> resume(ctx);
            default -> throw new IllegalArgumentException("Unknown step " + ctx.step());
        }
    }

    private void purge(ScenarioContext ctx) throws Exception {
        World world = ctx.plugin().getServer().getWorlds().get(0);
        Block a = world.getBlockAt(3, 100, 3);
        Block b = world.getBlockAt(5, 100, 5);
        Block c = world.getBlockAt(7, 100, 3);
        boolean orphans = Boolean.parseBoolean(ctx.param("auto-purge.orphans", "false"));
        Object api = ctx.api();

        ctx.later(20, () -> {
            ctx.put("auto-purge.logged.a", log(api, a));
            ctx.async(() -> {
                long timeA = awaitStored(api, a);
                ctx.put("auto-purge.time.a", timeA);
                // Rows logged in different seconds, so that a cutoff can fall between them
                Thread.sleep(2000);
                ctx.later(1, () -> {
                    ctx.put("auto-purge.logged.b", log(api, b));
                    ctx.async(() -> {
                        long cutoff = awaitStored(api, b);
                        ctx.put("auto-purge.time.b", cutoff);
                        ctx.later(1, () -> {
                            ctx.put("auto-purge.logged.c", log(api, c));
                            ctx.async(() -> {
                                ctx.put("auto-purge.time.c", awaitStored(api, c));
                                if (orphans) {
                                    addEntitySpawns(ctx, timeA, cutoff);
                                }
                                ctx.put("auto-purge.cutoff", cutoff);
                                ctx.put("auto-purge.removed", runNow(ctx, cutoff));
                                ctx.put("auto-purge.rows.a", rows(api, a));
                                ctx.put("auto-purge.rows.b", rows(api, b));
                                ctx.put("auto-purge.rows.c", rows(api, c));
                                if (orphans) {
                                    checkEntitySpawns(ctx);
                                }
                                ctx.later(1, () -> ctx.command("co status", 40));
                            });
                        });
                    });
                });
            });
        });
    }

    /**
     * Seed old rows, have auto-purge remove them, and end the step once it
     * has removed some, so that the server stops while it purges.
     */
    private void interrupt(ScenarioContext ctx) throws Exception {
        int seeded = Integer.parseInt(ctx.param("auto-purge.interrupt.rows", "30000"));
        if (seeded >= INTERRUPT_CUTOFF) {
            throw new IllegalArgumentException("Seed fewer rows than " + INTERRUPT_CUTOFF + ", the cutoff");
        }
        String prefix = prefix(ctx);
        try (Connection connection = connection(ctx); Statement statement = connection.createStatement()) {
            // Rows at times 1 to the count, before the cutoff; then one of now, which the purge keeps
            statement.executeUpdate("WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < "
                + seeded + ") INSERT INTO " + prefix + "block (time, user, wid, x, y, z, type, data, action,"
                + " rolled_back) SELECT n, 1, 1, n % 1000, 1, n / 1000, 1, 0, 0, 0 FROM r");
            statement.executeUpdate("INSERT INTO " + prefix + "block (time, user, wid, x, y, z, type, data, action,"
                + " rolled_back) VALUES (" + System.currentTimeMillis() / 1000 + ", 1, 1, 0, 2, 0, 1, 0, 0, 0)");
        }
        ctx.put("auto-purge.interrupt.seeded", seeded);
        ctx.put("auto-purge.interrupt.cutoff", INTERRUPT_CUTOFF);
        // Not the step's own work: the step ends while this still purges
        Thread purge = new Thread(() -> {
            try {
                runNow(ctx, INTERRUPT_CUTOFF);
                ctx.log("auto-purge finished before the server stopped");
            } catch (ReflectiveOperationException | RuntimeException e) {
                ctx.log("auto-purge ended: " + (e.getCause() != null ? e.getCause() : e));
            }
        }, "LPIT auto-purge interrupt");
        purge.setDaemon(true);
        purge.start();
        ctx.async(() -> {
            long deadline = System.currentTimeMillis() + STORE_TIMEOUT_MILLIS;
            long remaining;
            while ((remaining = oldRows(ctx)) >= seeded) {
                if (System.currentTimeMillis() > deadline || !purge.isAlive()) {
                    throw new IllegalStateException("Auto-purge didn't start removing the seeded rows");
                }
                Thread.sleep(20);
            }
            ctx.put("auto-purge.interrupt.remaining", remaining);
            ctx.put("auto-purge.interrupt.running", purge.isAlive());
        });
    }

    /**
     * On the boot after {@link #interrupt}: have auto-purge remove the rest
     * of the seeded rows, and count what's left.
     */
    private void resume(ScenarioContext ctx) {
        ctx.async(() -> {
            ctx.put("auto-purge.resume.before", oldRows(ctx));
            ctx.put("auto-purge.resume.removed", runNow(ctx, INTERRUPT_CUTOFF));
            ctx.put("auto-purge.resume.after", oldRows(ctx));
            ctx.put("auto-purge.resume.newer", count(ctx, "time >= " + INTERRUPT_CUTOFF));
        });
    }

    /**
     * @return the block rows before {@link #INTERRUPT_CUTOFF}
     */
    private static long oldRows(ScenarioContext ctx) throws Exception {
        return count(ctx, "time < " + INTERRUPT_CUTOFF);
    }

    private static long count(ScenarioContext ctx, String condition) throws Exception {
        try (Connection connection = connection(ctx); Statement statement = connection.createStatement();
             ResultSet results = statement.executeQuery("SELECT COUNT(*) FROM " + prefix(ctx) + "block WHERE "
                 + condition)) {
            results.next();
            return results.getLong(1);
        }
    }

    private static Object log(Object api, Block block) throws ReflectiveOperationException {
        Method logPlacement = api.getClass().getMethod("logPlacement", String.class, Location.class, Material.class,
            org.bukkit.block.data.BlockData.class);
        return logPlacement.invoke(api, ItPlugin.USER, block.getLocation(), Material.STONE, null);
    }

    /**
     * @return the stored time of the block's only row, once the consumer has written it
     */
    private static long awaitStored(Object api, Block block) throws Exception {
        long deadline = System.currentTimeMillis() + STORE_TIMEOUT_MILLIS;
        while (true) {
            List<?> rows = lookup(api, block);
            if (!rows.isEmpty()) {
                return Long.parseLong(((String[]) rows.get(0))[0]);
            }
            if (System.currentTimeMillis() > deadline) {
                throw new IllegalStateException("The placement at " + block.getLocation() + " wasn't stored within "
                    + STORE_TIMEOUT_MILLIS + " ms");
            }
            Thread.sleep(250);
        }
    }

    private static int rows(Object api, Block block) throws ReflectiveOperationException {
        return lookup(api, block).size();
    }

    private static List<?> lookup(Object api, Block block) throws ReflectiveOperationException {
        Object rows = api.getClass().getMethod("blockLookup", Block.class, int.class).invoke(api, block, 0);
        return rows == null ? List.of() : (List<?>) rows;
    }

    /**
     * Add a despawned entity as old as A that nothing refers to, and after
     * it one linked to A's block row, far from anything loaded.
     */
    private static void addEntitySpawns(ScenarioContext ctx, long timeA, long cutoff) throws Exception {
        String prefix = prefix(ctx);
        try (Connection connection = connection(ctx)) {
            long blockA;
            try (PreparedStatement statement = connection.prepareStatement(
                "SELECT rowid FROM " + prefix + "block WHERE x = 3 AND y = 100 AND z = 3")) {
                try (ResultSet results = statement.executeQuery()) {
                    if (!results.next()) {
                        throw new IllegalStateException("A's block row isn't there");
                    }
                    blockA = results.getLong(1);
                }
            }
            String insert = "INSERT INTO " + prefix + "entity_spawn (time, block_rowid, uuid, wid, current_wid, x, y, z, removed)"
                + " VALUES (?, ?, ?, 1, 1, 100000, 100, 100000, ?)";
            try (PreparedStatement statement = connection.prepareStatement(insert)) {
                statement.setLong(1, timeA);
                statement.setNull(2, java.sql.Types.BIGINT);
                statement.setString(3, "lpit-orphan");
                statement.setInt(4, 1);
                statement.executeUpdate();
                statement.setLong(1, cutoff);
                statement.setLong(2, blockA);
                statement.setString(3, "lpit-linked");
                statement.setInt(4, 0);
                statement.executeUpdate();
            }
        }
    }

    private static void checkEntitySpawns(ScenarioContext ctx) throws Exception {
        String prefix = prefix(ctx);
        try (Connection connection = connection(ctx)) {
            try (PreparedStatement statement = connection.prepareStatement(
                "SELECT COUNT(*) FROM " + prefix + "entity_spawn WHERE uuid = 'lpit-orphan'");
                 ResultSet results = statement.executeQuery()) {
                results.next();
                ctx.put("auto-purge.orphan.rows", results.getLong(1));
            }
            try (PreparedStatement statement = connection.prepareStatement(
                "SELECT block_rowid FROM " + prefix + "entity_spawn WHERE uuid = 'lpit-linked'");
                 ResultSet results = statement.executeQuery()) {
                ctx.put("auto-purge.linked.block", results.next() ? String.valueOf(results.getObject(1)) : "missing");
            }
        }
    }

    /** A connection from CoreProtect itself, to its active database */
    private static Connection connection(ScenarioContext ctx) throws ReflectiveOperationException {
        Object connection = ctx.coreProtectClass("net.coreprotect.database.Database")
            .getMethod("getConnection", boolean.class, int.class).invoke(null, true, 1000);
        if (connection == null) {
            throw new IllegalStateException("CoreProtect gave no database connection");
        }
        return (Connection) connection;
    }

    private static String prefix(ScenarioContext ctx) throws ReflectiveOperationException {
        return (String) ctx.coreProtectClass("net.coreprotect.config.ConfigHandler").getField("prefix").get(null);
    }

    /**
     * Purge rows older than the cutoff through LibreProtect's test hook.
     */
    private static Object runNow(ScenarioContext ctx, long cutoff) throws ReflectiveOperationException {
        Class<?> service = ctx.coreProtectClass(SERVICE);
        Method runNow = service.getDeclaredMethod("runNow", long.class);
        runNow.setAccessible(true);
        return runNow.invoke(null, cutoff);
    }
}
