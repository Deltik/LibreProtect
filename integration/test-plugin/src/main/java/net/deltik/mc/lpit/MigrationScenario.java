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
import org.bukkit.command.CommandSender;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.sql.Blob;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * Steps {@code migration.*}, for the harness's {@code MigrationChecks}:
 * <ul>
 *   <li>{@code migration.seed}: log {@code migration.seed.count} block
 *       placements in lane {@code migration.seed.lane} and wait until
 *       CoreProtect has saved them. Before them, with
 *       {@code migration.seed.encoded}, log values that CoreProtect 25
 *       encodes per engine, and with {@code migration.seed.indexed}, rows in
 *       every table that CoreProtect 25's ClickHouse lookup index indexes.</li>
 *   <li>{@code migration.config}: change config.yml while the server runs,
 *       as CoreProtect 24's migration docs have users do: each
 *       {@code key: value} of {@code migration.config.lines}, separated by
 *       {@code |}.</li>
 *   <li>{@code migration.archive}: move {@code database.db} and its
 *       companion files away.</li>
 *   <li>{@code migration.check}: record the engine in use, and look up the
 *       first, middle and last placement of each lane in
 *       {@code migration.check.lanes} ({@code lane:count,...}) through the API.</li>
 *   <li>{@code migration.interrupt}: run {@code co migrate-db
 *       <migration.interrupt.target>}, log {@code migration.interrupt.during}
 *       placements in lane {@code migration.interrupt.lane}, and end once the
 *       target, a MySQL database read through {@code migration.mysql.*}, has
 *       the lock row of table prefix {@code migration.interrupt.prefix},
 *       within {@code migration.interrupt.timeout.seconds}, so that the
 *       server stops while the migration writes the target.</li>
 *   <li>{@code migration.run*}, such as {@code migration.run-mysql}: run
 *       {@code co migrate-db <step>.target} with {@code <step>.options},
 *       log {@code <step>.during} placements in lane {@code <step>.lane}
 *       while it runs, wait for it to finish and for the queued placements
 *       to be saved, then record a digest of every table of the source and
 *       of the same row IDs in the target, so the harness can compare them.
 *       {@code migration.mysql.*} and {@code migration.clickhouse.*} say how
 *       to read a MySQL or ClickHouse source. With {@code <step>.lookups},
 *       also count the user's rows with CoreProtect's lookup by user, on the
 *       source before the migration and on the target after the switch, up
 *       to when the migration started.</li>
 * </ul>
 * Each lane of placements fills a column of a few chunks, a chunk apart from the next lane.
 */
final class MigrationScenario implements Scenario {

    /** Columns whose encoding differs between relational and columnar engines */
    private static final Set<String> TRANSCODED = Set.of("block.meta", "entity.data", "entity_spawn.data");
    /** Binary columns, which ClickHouse keeps as strings and its driver returns as text unless asked for bytes */
    private static final Set<String> BINARY = Set.of("block.meta", "block.blockdata", "container.metadata",
        "entity_container.metadata", "entity_interaction.metadata", "item.data", "entity.data", "entity_spawn.data");

    @Override
    public void run(ScenarioContext ctx) throws Exception {
        String action = ctx.action();
        if (action.equals("seed")) {
            seed(ctx);
        } else if (action.equals("config")) {
            config(ctx);
        } else if (action.equals("archive")) {
            archive(ctx);
        } else if (action.equals("check")) {
            check(ctx);
        } else if (action.equals("interrupt")) {
            interrupt(ctx);
        } else if (action.startsWith("run")) {
            migrate(ctx);
        } else {
            throw new IllegalArgumentException("Unknown migration step " + ctx.step());
        }
    }

    private void seed(ScenarioContext ctx) throws Exception {
        int lane = Integer.parseInt(ctx.param("migration.seed.lane", "0"));
        int count = Integer.parseInt(ctx.param("migration.seed.count", "1000"));
        // Queued before the placements, so they're saved once the last placement is
        if (Boolean.parseBoolean(ctx.param("migration.seed.encoded", "false"))) {
            logEncoded(ctx);
        }
        // CoreProtect dates a dropped item a second ahead and holds it until then, so
        // its row can be saved after the placements, and even to the next database
        if (Boolean.parseBoolean(ctx.param("migration.seed.indexed", "false"))) {
            logIndexed(ctx);
        }
        log(ctx, lane, count);
        ctx.put("migration.seed.logged", count);
        awaitSaved(ctx, lane, count, "migration.seed");
    }

    /**
     * Log what CoreProtect stores in the columns that CoreProtect 25 encodes
     * differently for columnar engines: block metadata from removed blocks
     * with state (a command block, a shulker box with items, a banner), and
     * entity data from a named cow that dies. On CoreProtect 25, also a cow
     * that a dispenser spawns from an egg, which CoreProtect tracks.
     */
    private static void logEncoded(ScenarioContext ctx) throws Exception {
        Object api = ctx.api();
        Method logRemoval = api.getClass().getMethod("logRemoval", String.class, org.bukkit.block.BlockState.class);
        World world = ctx.plugin().getServer().getWorlds().get(0);
        int y = world.getHighestBlockYAt(0, 0) + 2;

        Block commandBlock = world.getBlockAt(1, y, 1);
        commandBlock.setType(Material.COMMAND_BLOCK);
        org.bukkit.block.CommandBlock command = (org.bukkit.block.CommandBlock) commandBlock.getState();
        command.setCommand("say Logged for the migration test, ünïcödé 🙂");
        command.update();
        logRemoval.invoke(api, ItPlugin.USER, commandBlock.getState());

        Block shulkerBlock = world.getBlockAt(2, y, 1);
        shulkerBlock.setType(Material.SHULKER_BOX);
        org.bukkit.block.ShulkerBox shulker = (org.bukkit.block.ShulkerBox) shulkerBlock.getState();
        org.bukkit.inventory.ItemStack named = new org.bukkit.inventory.ItemStack(Material.DIAMOND_SWORD);
        org.bukkit.inventory.meta.ItemMeta meta = named.getItemMeta();
        meta.setDisplayName("Migrated sword");
        named.setItemMeta(meta);
        shulker.getSnapshotInventory().setItem(0, new org.bukkit.inventory.ItemStack(Material.DIAMOND, 3));
        shulker.getSnapshotInventory().setItem(5, named);
        logRemoval.invoke(api, ItPlugin.USER, shulker);

        try {
            Block bannerBlock = world.getBlockAt(3, y, 1);
            bannerBlock.setType(Material.RED_BANNER);
            org.bukkit.block.Banner banner = (org.bukkit.block.Banner) bannerBlock.getState();
            banner.addPattern(new org.bukkit.block.banner.Pattern(org.bukkit.DyeColor.BLUE,
                org.bukkit.block.banner.PatternType.CROSS));
            banner.update();
            logRemoval.invoke(api, ItPlugin.USER, bannerBlock.getState());
            ctx.put("migration.seed.banner", true);
        } catch (RuntimeException | LinkageError e) {
            // Banner patterns became a registry in newer servers; the other blocks carry metadata too
            ctx.put("migration.seed.banner", e.toString());
        }

        org.bukkit.entity.Cow cow = world.spawn(new Location(world, 5.5, y, 5.5), org.bukkit.entity.Cow.class);
        cow.setCustomName("Migrated cow 🐄");
        cow.setCustomNameVisible(true);
        cow.damage(1000);
        ctx.put("migration.seed.killed", cow.isDead());

        // CoreProtect 25 tracks entities that dispensers spawn from eggs, in entity_spawn
        if (hasField(ctx, "net.coreprotect.config.ConfigHandler", "databaseType")) {
            Block dispenserBlock = world.getBlockAt(4, y, 1);
            dispenserBlock.setType(Material.DISPENSER);
            org.bukkit.block.Dispenser dispenser = (org.bukkit.block.Dispenser) dispenserBlock.getState();
            dispenser.getInventory().addItem(new org.bukkit.inventory.ItemStack(Material.COW_SPAWN_EGG));
            ctx.put("migration.seed.dispensed", dispenser.dispense());
        }
    }

    /**
     * Log a row by the user in each table that CoreProtect 25's ClickHouse
     * lookup index indexes, besides the block and container rows of the
     * placements and of {@link #logEncoded}: an item that the user dropped,
     * in item, and a chested donkey that the user leashed and put wheat in,
     * in entity_interaction and entity_container. The interaction comes
     * first, since it records the donkey that the container row refers to.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static void logIndexed(ScenarioContext ctx) throws Exception {
        World world = ctx.plugin().getServer().getWorlds().get(0);
        int y = world.getHighestBlockYAt(8, 5) + 2;
        ctx.coreProtectClass("net.coreprotect.listener.player.PlayerDropItemListener")
            .getMethod("playerDropItem", Location.class, String.class, org.bukkit.inventory.ItemStack.class)
            .invoke(null, new Location(world, 7.5, y, 1.5), ItPlugin.USER,
                new org.bukkit.inventory.ItemStack(Material.DIAMOND, 2));

        org.bukkit.entity.Donkey donkey = world.spawn(new Location(world, 8.5, y, 5.5), org.bukkit.entity.Donkey.class);
        donkey.setCarryingChest(true);
        Class<?> queue = ctx.coreProtectClass("net.coreprotect.consumer.Queue");
        Class<? extends Enum> action = (Class<? extends Enum>) ctx.coreProtectClass(
            "net.coreprotect.model.entity.EntityInteractionAction");
        queue.getMethod("queueEntityInteraction", String.class, org.bukkit.entity.Entity.class, action)
            .invoke(null, ItPlugin.USER, donkey, Enum.valueOf(action, "LEASH"));
        queue.getMethod("queueEntityContainerTransaction", String.class, UUID.class, Location.class,
                org.bukkit.inventory.ItemStack[].class, org.bukkit.inventory.ItemStack[].class)
            .invoke(null, ItPlugin.USER, donkey.getUniqueId(), donkey.getLocation(),
                new org.bukkit.inventory.ItemStack[1],
                new org.bukkit.inventory.ItemStack[]{new org.bukkit.inventory.ItemStack(Material.WHEAT, 3)});
        ctx.put("migration.seed.indexed", true);
    }

    private static boolean hasField(ScenarioContext ctx, String className, String field) throws ClassNotFoundException {
        try {
            ctx.coreProtectClass(className).getField(field);
            return true;
        } catch (NoSuchFieldException e) {
            return false;
        }
    }

    private void config(ScenarioContext ctx) throws IOException {
        Path file = ctx.coreProtectFolder().resolve("config.yml");
        List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
        for (String setting : ctx.param("migration.config.lines", "").split("\\|")) {
            if (setting.isBlank()) {
                continue;
            }
            String key = setting.substring(0, setting.indexOf(':')).trim();
            boolean replaced = false;
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                if (!line.startsWith("#") && line.contains(":") && line.substring(0, line.indexOf(':')).trim().equals(key)) {
                    lines.set(i, setting);
                    replaced = true;
                }
            }
            if (!replaced) {
                lines.add(setting);
            }
        }
        Files.write(file, lines, StandardCharsets.UTF_8);
    }

    private void archive(ScenarioContext ctx) throws IOException {
        for (String suffix : new String[]{"", "-wal", "-shm", "-journal"}) {
            Path file = ctx.coreProtectFolder().resolve("database.db" + suffix);
            if (Files.exists(file)) {
                Files.move(file, file.resolveSibling("archived-database.db" + suffix), StandardCopyOption.REPLACE_EXISTING);
            }
        }
        ctx.put("migration.archive.done", true);
    }

    private void check(ScenarioContext ctx) throws Exception {
        ctx.put("migration.check.active", activeEngine(ctx));
        Map<Integer, Integer> lanes = lanes(ctx.param("migration.check.lanes", ""));
        ctx.async(() -> ctx.put("migration.check.lookups", lookups(ctx, lanes)));
    }

    private void migrate(ScenarioContext ctx) throws Exception {
        String step = ctx.step();
        if (!Boolean.parseBoolean(ctx.param(step + ".lookups", "false"))) {
            migrate(ctx, 0);
            return;
        }
        // Up to a second before the migration starts, so the placements logged while it runs aren't counted
        long until = System.currentTimeMillis() / 1000L - 1;
        ctx.async(() -> {
            ctx.put(step + ".lookups.before", countByUser(ctx, until));
            ctx.later(1, () -> migrate(ctx, until));
        });
    }

    /**
     * @param until the time up to which to count the user's rows with
     *              CoreProtect's lookup again after the switch, or 0 not to
     */
    private void migrate(ScenarioContext ctx, long until) throws Exception {
        String step = ctx.step();
        String target = ctx.param(step + ".target");
        int during = Integer.parseInt(ctx.param(step + ".during", "0"));
        int lane = Integer.parseInt(ctx.param(step + ".lane", "9"));
        String sourceEngine = activeEngine(ctx);
        String sourcePrefix = (String) staticField(ctx, "net.coreprotect.config.ConfigHandler", "prefix");
        ctx.put(step + ".active.before", sourceEngine);

        ctx.command(("co migrate-db " + target + " " + ctx.param(step + ".options", "")).trim());
        long timeout = Long.parseLong(ctx.param(step + ".timeout.ticks", "4800"));
        // The migration checks its target first, then pauses CoreProtect; log while it holds the database
        everyTickUntil(ctx, step + " pausing CoreProtect", 1200, () -> persistencePaused(ctx) || !migrationRunning(ctx),
            () -> {
                ctx.put(step + ".loggedWhilePaused", persistencePaused(ctx));
                log(ctx, lane, during);
                ctx.put(step + ".logged", during);
                ctx.waitUntil(step + " finishing", timeout, () -> !migrationRunning(ctx), () -> {
                    String active = activeEngine(ctx);
                    ctx.put(step + ".active.after", active);
                    String targetPrefix = (String) staticField(ctx, "net.coreprotect.config.ConfigHandler", "prefix");
                    ctx.async(() -> {
                        if (during > 0) {
                            ctx.put(step + ".saved", saved(ctx, lane, during));
                        }
                        if (!active.equals(sourceEngine)) {
                            if (until > 0) {
                                ctx.put(step + ".lookups.after", countByUser(ctx, until));
                            }
                            digests(ctx, step, sourceEngine, sourcePrefix, active, targetPrefix);
                        }
                    });
                });
            });
    }

    /**
     * Like {@link ScenarioContext#waitUntil}, but testing the condition every tick
     */
    private static void everyTickUntil(ScenarioContext ctx, String what, long timeoutTicks,
                                       ScenarioContext.Condition condition, ScenarioContext.Task then) {
        ctx.later(1, () -> {
            if (condition.test()) {
                then.run();
            } else if (timeoutTicks <= 0) {
                ctx.put(ctx.step() + ".timeout", what);
            } else {
                everyTickUntil(ctx, what, timeoutTicks - 1, condition, then);
            }
        });
    }

    private static boolean migrationRunning(ScenarioContext ctx) throws ReflectiveOperationException {
        return (Boolean) staticField(ctx, "net.coreprotect.config.ConfigHandler", "migrationRunning");
    }

    /**
     * @return whether CoreProtect holds its queue for a migration: CoreProtect
     *         25's database reload, or CoreProtect 24's purge flag
     */
    private static boolean persistencePaused(ScenarioContext ctx) throws ReflectiveOperationException {
        Class<?> consumer = ctx.coreProtectClass("net.coreprotect.consumer.Consumer");
        try {
            return (Boolean) consumer.getMethod("isDatabaseReloadPaused").invoke(null);
        } catch (NoSuchMethodException e) {
            return (Boolean) staticField(ctx, "net.coreprotect.config.ConfigHandler", "purgeRunning");
        }
    }

    /**
     * Start a migration and log placements, then end the step as soon as the
     * migration has marked the target unfinished, which it does right before
     * it creates CoreProtect's tables there and copies the rows, so that the
     * server stops while the migration writes the target.
     */
    private void interrupt(ScenarioContext ctx) throws Exception {
        String target = ctx.param("migration.interrupt.target");
        // Not CoreProtect's prefix: CoreProtect 25 uses co_ on SQLite, and table-prefix on the target
        String prefix = ctx.param("migration.interrupt.prefix");
        long timeout = Long.parseLong(ctx.param("migration.interrupt.timeout.seconds", "120"));
        ctx.put("migration.interrupt.active.before", activeEngine(ctx));
        ctx.command("co migrate-db " + target);
        int during = Integer.parseInt(ctx.param("migration.interrupt.during", "0"));
        log(ctx, Integer.parseInt(ctx.param("migration.interrupt.lane", "1")), during);
        ctx.async(() -> {
            long deadline = System.nanoTime() + timeout * 1_000_000_000L;
            // The target, read the way the migration steps read a source
            try (Connection connection = openSource(ctx, target.toUpperCase(Locale.ROOT))) {
                while (!hasLockRow(connection, prefix)) {
                    if (!migrationRunning(ctx) && !hasLockRow(connection, prefix)) {
                        ctx.put("migration.interrupt.error", "the migration ended without a row in the target's "
                            + prefix + "database_lock");
                        return;
                    }
                    if (System.nanoTime() > deadline) {
                        ctx.put("migration.interrupt.timeout", "a row in the target's " + prefix + "database_lock");
                        return;
                    }
                    Thread.sleep(10);
                }
            }
            // On the main thread, which stops the server right after this step
            ctx.later(1, () -> ctx.put("migration.interrupt.running", migrationRunning(ctx)));
        });
    }

    private static boolean hasLockRow(Connection connection, String prefix) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("SELECT 1 FROM " + prefix
            + "database_lock WHERE rowid = 1"); ResultSet result = statement.executeQuery()) {
            return result.next();
        } catch (SQLException e) {
            if ("42S02".equals(e.getSQLState())) {
                // The migration hasn't created the table yet
                return false;
            }
            throw e;
        }
    }

    /**
     * Log placements 0 to count - 1 of a lane.
     */
    private static void log(ScenarioContext ctx, int lane, int count) throws ReflectiveOperationException {
        Object api = ctx.api();
        Method logPlacement = api.getClass().getMethod("logPlacement", String.class, Location.class, Material.class,
            org.bukkit.block.data.BlockData.class);
        World world = ctx.plugin().getServer().getWorlds().get(0);
        for (int index = 0; index < count; index++) {
            logPlacement.invoke(api, ItPlugin.USER, position(world, lane, index), Material.STONE, null);
        }
    }

    /**
     * @return where a lane's placement goes: lanes are a chunk apart, and
     *         each fills a column of 64 blocks, 360 high, so that tens of
     *         thousands of placements stay within a few chunks
     */
    private static Location position(World world, int lane, int index) {
        return new Location(world, index % 64, -60 + index / 64 % 360, lane * 16 + index / (64 * 360));
    }

    /**
     * Wait until the last placement of a lane can be looked up, so CoreProtect saved the lane.
     */
    private static void awaitSaved(ScenarioContext ctx, int lane, int count, String step) {
        if (count > 0) {
            ctx.async(() -> ctx.put(step + ".saved", saved(ctx, lane, count)));
        }
    }

    /**
     * @return whether the last placement of a lane could be looked up within two minutes; blocks
     */
    private static boolean saved(ScenarioContext ctx, int lane, int count) throws Exception {
        long deadline = System.nanoTime() + 120_000_000_000L;
        while (lookup(ctx, lane, count - 1) < 1) {
            if (System.nanoTime() > deadline) {
                return false;
            }
            Thread.sleep(250);
        }
        return true;
    }

    /**
     * @return how many of the user's rows up to a time CoreProtect's lookup
     *         by user counts, in every world, as {@code /co lookup u:<user>}
     *         does: on ClickHouse, through CoreProtect's lookup index
     */
    private static long countByUser(ScenarioContext ctx, long until) throws Exception {
        Method getConnection = ctx.coreProtectClass("net.coreprotect.database.Database")
            .getMethod("getConnection", boolean.class, int.class);
        Method count = ctx.coreProtectClass("net.coreprotect.database.Lookup").getMethod("countLookupRows",
            Statement.class, CommandSender.class, List.class, List.class, List.class, Map.class, List.class,
            List.class, Location.class, Integer[].class, Long[].class, long.class, long.class, boolean.class,
            boolean.class);
        try (Connection connection = (Connection) getConnection.invoke(null, true, 0);
             Statement statement = connection.createStatement()) {
            return (Long) count.invoke(null, statement, ctx.plugin().getServer().getConsoleSender(),
                new ArrayList<String>(), new ArrayList<>(List.of(ItPlugin.USER)), new ArrayList<>(),
                new HashMap<>(), new ArrayList<String>(), new ArrayList<Integer>(), null, null, null, 0L, until,
                false, true);
        }
    }

    private static int lookup(ScenarioContext ctx, int lane, int index) throws ReflectiveOperationException {
        Object api = ctx.api();
        World world = ctx.plugin().getServer().getWorlds().get(0);
        Block block = position(world, lane, index).getBlock();
        Object rows = api.getClass().getMethod("blockLookup", Block.class, int.class).invoke(api, block, 0);
        return rows == null ? -1 : ((List<?>) rows).size();
    }

    /**
     * @return {@code lane:placement=rows} for the first, middle and last placement of each lane
     */
    private static String lookups(ScenarioContext ctx, Map<Integer, Integer> lanes) throws ReflectiveOperationException {
        List<String> found = new ArrayList<>();
        for (Map.Entry<Integer, Integer> lane : lanes.entrySet()) {
            int count = lane.getValue();
            for (int index : new TreeSet<>(List.of(0, count / 2, count - 1))) {
                found.add(lane.getKey() + ":" + index + "=" + lookup(ctx, lane.getKey(), index));
            }
        }
        return String.join(",", found);
    }

    private static Map<Integer, Integer> lanes(String spec) {
        Map<Integer, Integer> lanes = new LinkedHashMap<>();
        for (String lane : spec.split(",")) {
            if (!lane.isBlank()) {
                String[] parts = lane.split(":");
                lanes.put(Integer.parseInt(parts[0].trim()), Integer.parseInt(parts[1].trim()));
            }
        }
        return lanes;
    }

    /**
     * @return the engine CoreProtect uses, as CoreProtect 25 names it: {@code SQLITE}, {@code MYSQL}, ...
     */
    static String activeEngine(ScenarioContext ctx) throws ReflectiveOperationException {
        Class<?> handler = ctx.coreProtectClass("net.coreprotect.config.ConfigHandler");
        try {
            return String.valueOf(handler.getField("databaseType").get(null));
        } catch (NoSuchFieldException e) {
            Object config = ctx.coreProtectClass("net.coreprotect.config.Config").getMethod("getGlobal").invoke(null);
            return (Boolean) config.getClass().getField("MYSQL").get(config) ? "MYSQL" : "SQLITE";
        }
    }

    private static Object staticField(ScenarioContext ctx, String className, String name) throws ReflectiveOperationException {
        Field field = ctx.coreProtectClass(className).getField(name);
        return field.get(null);
    }

    /**
     * Record, for every CoreProtect table, the row count, the smallest and
     * largest row IDs and a digest of the rows of the source, and the same of
     * the target's rows up to the source's largest row ID.
     */
    private static void digests(ScenarioContext ctx, String step, String sourceEngine, String sourcePrefix,
                                String targetEngine, String targetPrefix) throws Exception {
        @SuppressWarnings("unchecked")
        List<String> tables = new ArrayList<>((List<String>) staticField(ctx, "net.coreprotect.config.ConfigHandler",
            "databaseTables"));
        if (targetEngine.equals("CLICKHOUSE")) {
            // A ClickHouse database keeps only its own version row, which the harness checks itself
            tables.remove("version");
        }
        // Between relational and columnar engines, compare the encoded columns in CoreProtect's canonical encoding
        Canonical canonical = isColumnar(sourceEngine) != isColumnar(targetEngine) ? canonical(ctx) : null;
        Method getConnection = ctx.coreProtectClass("net.coreprotect.database.Database")
            .getMethod("getConnection", boolean.class, int.class);
        List<String> coverage = new ArrayList<>();
        try (Connection source = openSource(ctx, sourceEngine);
             Connection target = (Connection) getConnection.invoke(null, true, 0)) {
            for (String table : tables) {
                if (table.equals("database_lock")) {
                    continue;
                }
                List<Map<String, String>> sourceRows = rows(source, sourcePrefix, table, canonical,
                    sourceEngine.equals("CLICKHOUSE"));
                List<Map<String, String>> targetRows = rows(target, targetPrefix, table, canonical,
                    targetEngine.equals("CLICKHOUSE"));
                Set<String> columns = new TreeSet<>(sourceRows.isEmpty() ? Set.of() : sourceRows.get(0).keySet());
                if (!targetRows.isEmpty()) {
                    columns.retainAll(targetRows.get(0).keySet());
                }
                for (String column : columns) {
                    if (TRANSCODED.contains(table + "." + column)) {
                        coverage.add(table + "." + column + "=" + sourceRows.stream()
                            .filter(row -> !"NULL".equals(row.get(column))).count());
                    }
                }
                long sourceMax = sourceRows.isEmpty() ? 0 : Long.parseLong(sourceRows.get(sourceRows.size() - 1).get("lpit_rowid"));
                List<Map<String, String>> copied = new ArrayList<>();
                for (Map<String, String> row : targetRows) {
                    if (Long.parseLong(row.get("lpit_rowid")) <= sourceMax) {
                        copied.add(row);
                    }
                }
                ctx.put(step + ".table." + table + ".source", digest(sourceRows, columns));
                ctx.put(step + ".table." + table + ".target", digest(copied, columns));
                ctx.put(step + ".table." + table + ".rows", sourceRows.size() + ">" + targetRows.size());
            }
        }
        ctx.put(step + ".coverage", String.join(",", coverage));
        ctx.put(step + ".digests", tables.size());
    }

    /** Converts an encoded column's value to one encoding */
    @FunctionalInterface
    private interface Canonical {
        Object apply(String table, String column, byte[] value) throws Exception;
    }

    /**
     * @return CoreProtect 25's own conversion of block metadata and entity data
     *         to the canonical encoding of its columnar engines
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Canonical canonical(ScenarioContext ctx) throws Exception {
        Class<? extends Enum> type = (Class<? extends Enum>) ctx.coreProtectClass("net.coreprotect.database.DatabaseType");
        Class<? extends Enum> kind = (Class<? extends Enum>) ctx.coreProtectClass(
            "net.coreprotect.utility.serialize.EntityDataCodec$Kind");
        Object columnar = Enum.valueOf(type, "DUCKDB");
        Method metadata = ctx.coreProtectClass("net.coreprotect.database.statement.BlockStatement")
            .getMethod("transcodeMetadata", byte[].class, type);
        Method data = ctx.coreProtectClass("net.coreprotect.database.statement.EntityStatement")
            .getMethod("transcodeData", byte[].class, kind, type);
        Object entity = Enum.valueOf(kind, "ENTITY");
        Object spawn = Enum.valueOf(kind, "ENTITY_SPAWN");
        return (table, column, value) -> switch (table + "." + column) {
            case "block.meta" -> metadata.invoke(null, value, columnar);
            case "entity.data" -> data.invoke(null, value, entity, columnar);
            case "entity_spawn.data" -> data.invoke(null, value, spawn, columnar);
            default -> value;
        };
    }

    private static boolean isColumnar(String engine) {
        return engine.equals("DUCKDB") || engine.equals("CLICKHOUSE");
    }

    private static Connection openSource(ScenarioContext ctx, String engine) throws Exception {
        Path folder = ctx.coreProtectFolder();
        switch (engine) {
            case "SQLITE":
                return DriverManager.getConnection("jdbc:sqlite:" + folder.resolve("database.db"));
            case "MYSQL":
                Properties properties = new Properties();
                properties.setProperty("user", ctx.param("migration.mysql.username"));
                properties.setProperty("password", ctx.param("migration.mysql.password"));
                properties.setProperty("useSSL", "false");
                properties.setProperty("allowPublicKeyRetrieval", "true");
                properties.setProperty("useServerPrepStmts", "true");
                return DriverManager.getConnection("jdbc:mysql://" + ctx.param("migration.mysql.host") + ":"
                    + ctx.param("migration.mysql.port") + "/" + ctx.param("migration.mysql.database"), properties);
            case "DUCKDB":
                // DuckDB comes from CoreProtect's plugin libraries, which DriverManager won't hand to this plugin
                Driver driver = (Driver) ctx.coreProtectClass("org.duckdb.DuckDBDriver").getDeclaredConstructor()
                    .newInstance();
                Properties readOnly = new Properties();
                readOnly.setProperty("duckdb.read_only", "true");
                return driver.connect("jdbc:duckdb:" + folder.resolve("database.duckdb").toAbsolutePath(), readOnly);
            case "CLICKHOUSE":
                // CoreProtect's JAR has ClickHouse's driver without its JDBC service entry, so connect through CoreProtect
                Class<?> config = ctx.coreProtectClass("net.coreprotect.database.clickhouse.ClickHouseJdbcConfig");
                Object settings = config.getConstructor(String.class, int.class, String.class, String.class,
                        String.class, boolean.class)
                    .newInstance(ctx.param("migration.clickhouse.host"),
                        Integer.parseInt(ctx.param("migration.clickhouse.port")),
                        ctx.param("migration.clickhouse.database"), ctx.param("migration.clickhouse.username"),
                        ctx.param("migration.clickhouse.password"), false);
                return (Connection) ctx.coreProtectClass("net.coreprotect.database.clickhouse.ClickHouseJdbc")
                    .getMethod("openPatchConnection", config).invoke(null, settings);
            default:
                throw new IllegalArgumentException("Can't read a " + engine + " source");
        }
    }

    /**
     * @param canonical converts encoded columns, or {@code null} to leave them
     * @param clickHouse whether the connection is to ClickHouse, whose views
     *                   keep binary data as strings and show a missing user
     *                   UUID as empty
     * @return a table's rows in row ID order, each column's value rendered
     *         the same whatever the engine; the row ID as {@code lpit_rowid}
     */
    private static List<Map<String, String>> rows(Connection connection, String prefix, String table, Canonical canonical,
                                                  boolean clickHouse) throws Exception {
        List<Map<String, String>> rows = new ArrayList<>();
        // A prepared statement, so that MySQL answers in its binary protocol, which keeps FLOAT values exact
        try (PreparedStatement statement = connection.prepareStatement("SELECT t.rowid AS lpit_rowid, t.* FROM "
            + prefix + table + " t ORDER BY t.rowid"); ResultSet result = statement.executeQuery()) {
            ResultSetMetaData meta = result.getMetaData();
            while (result.next()) {
                Map<String, String> row = new LinkedHashMap<>();
                for (int i = 1; i <= meta.getColumnCount(); i++) {
                    String name = meta.getColumnLabel(i).toLowerCase(Locale.ROOT);
                    if (i > 1 && name.equals("rowid")) {
                        continue;
                    }
                    Object value = clickHouse && BINARY.contains(table + "." + name) ? result.getBytes(i)
                        : bytes(result.getObject(i));
                    if (clickHouse && table.equals("user") && name.equals("uuid") && "".equals(value)) {
                        value = null;
                    }
                    if (canonical != null && value instanceof byte[] encoded && TRANSCODED.contains(table + "." + name)) {
                        value = canonical.apply(table, name, encoded);
                    }
                    row.put(name, render(value));
                }
                rows.add(row);
            }
        }
        return rows;
    }

    private static Object bytes(Object value) throws SQLException {
        return value instanceof Blob blob ? blob.getBytes(1, (int) blob.length()) : value;
    }

    private static String render(Object value) {
        if (value == null) {
            return "NULL";
        }
        if (value instanceof byte[] bytes) {
            return "x" + HexFormat.of().formatHex(bytes);
        }
        if (value instanceof Float || value instanceof Double) {
            return Double.toString(((Number) value).doubleValue());
        }
        if (value instanceof Number number) {
            return Long.toString(number.longValue());
        }
        return "'" + value + "'";
    }

    /**
     * @return {@code count;min;max;sha256} of the rows' row IDs and columns
     */
    private static String digest(List<Map<String, String>> rows, Set<String> columns) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        for (Map<String, String> row : rows) {
            StringBuilder line = new StringBuilder(row.get("lpit_rowid"));
            for (String column : columns) {
                if (!column.equals("lpit_rowid")) {
                    line.append('|').append(column).append('=').append(row.get(column));
                }
            }
            sha.update(line.append('\n').toString().getBytes(StandardCharsets.UTF_8));
        }
        String min = rows.isEmpty() ? "0" : rows.get(0).get("lpit_rowid");
        String max = rows.isEmpty() ? "0" : rows.get(rows.size() - 1).get("lpit_rowid");
        return rows.size() + ";" + min + ";" + max + ";" + HexFormat.of().formatHex(sha.digest()).substring(0, 16);
    }
}
