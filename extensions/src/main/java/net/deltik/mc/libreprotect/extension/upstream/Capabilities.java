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

package net.deltik.mc.libreprotect.extension.upstream;

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * How LibreProtect's extensions use this CoreProtect: every capability,
 * probed once. The build probes the upstream JAR it bundles the same way and
 * writes the outcome to {@code capabilities.tsv} (see
 * {@link CapabilityReport}), so a capability that would be unavailable at
 * run time stops the release first.
 */
public final class Capabilities {

    /** Every capability, probed in this order; a new one is one more line */
    private static final List<Capability<?>> KNOWN = Collections.unmodifiableList(Arrays.asList(
        ActiveDatabase.CAPABILITY,
        Flags.CAPABILITY,
        ConsumerGate.CAPABILITY,
        ConfigLock.CAPABILITY,
        ServerThread.CAPABILITY,
        StartResult.CAPABILITY,
        Hooks.AUTO_PURGE_COUNTER,
        Hooks.LOCK_HEARTBEAT,
        Hooks.ENTITY_SPAWN_VERIFICATION,
        Hooks.DUCKDB_RECOVERY,
        Hooks.PURGE_WORKER,
        IncompleteMarks.CAPABILITY,
        Schema.CAPABILITY,
        Codecs.CAPABILITY,
        DuckDBWrites.CAPABILITY,
        MigrationProtocol.CAPABILITY,
        CoreProtectMigration.source(Engine.SQLITE),
        CoreProtectMigration.source(Engine.MYSQL),
        CoreProtectMigration.source(Engine.DUCKDB),
        CoreProtectMigration.source(Engine.CLICKHOUSE),
        CoreProtectMigration.target(Engine.SQLITE),
        CoreProtectMigration.target(Engine.MYSQL),
        CoreProtectMigration.target(Engine.DUCKDB),
        CoreProtectMigration.target(Engine.CLICKHOUSE),
        PurgeSettings.RETENTION,
        PurgeSettings.CAPABILITY,
        PurgeTables.CAPABILITY,
        Leases.CAPABILITY,
        PurgeEngine.SQLITE,
        PurgeEngine.MYSQL,
        PurgeEngine.DUCKDB,
        PurgeEngine.CLICKHOUSE));

    private static volatile Capabilities current;

    private final Map<String, Choice<?>> choices;

    private Capabilities(Map<String, Choice<?>> choices) {
        this.choices = Collections.unmodifiableMap(choices);
    }

    /**
     * @return the capabilities of the CoreProtect that shares LibreProtect's
     *         class loader, probed on first use; each migration they leave
     *         unavailable is logged as a warning then
     */
    public static Capabilities current() {
        Capabilities capabilities = current;
        if (capabilities == null) {
            synchronized (Capabilities.class) {
                capabilities = current;
                if (capabilities == null) {
                    capabilities = probe(Upstream.coreProtect());
                    warnAboutUnavailable(capabilities);
                    current = capabilities;
                }
            }
        }
        return capabilities;
    }

    /**
     * @return the capabilities of an upstream, such as one that a test hid
     *         parts of
     */
    public static Capabilities probe(Upstream upstream) {
        Map<String, Choice<?>> choices = new LinkedHashMap<>();
        for (Capability<?> capability : KNOWN) {
            choices.put(capability.id(), capability.probe(upstream));
        }
        return new Capabilities(choices);
    }

    /**
     * @return every capability there is, in the order they're probed
     */
    public static List<Capability<?>> known() {
        return KNOWN;
    }

    /**
     * @return how this CoreProtect supports a capability
     */
    @SuppressWarnings("unchecked")
    public <T> Choice<T> get(Capability<T> capability) {
        Choice<?> choice = choices.get(capability.id());
        if (choice == null) {
            throw new IllegalArgumentException("Unknown capability " + capability.id());
        }
        return (Choice<T>) choice;
    }

    /**
     * @return what a capability gives
     * @throws Missing why this CoreProtect doesn't support it
     */
    public <T> T require(Capability<T> capability) throws Missing {
        return get(capability).require();
    }

    /**
     * @return how this CoreProtect supports a capability, by its ID
     * @throws IllegalArgumentException for an unknown ID
     */
    public Choice<?> get(String id) {
        Choice<?> choice = choices.get(id);
        if (choice == null) {
            throw new IllegalArgumentException("Unknown capability " + id);
        }
        return choice;
    }

    /**
     * @return every capability's outcome, in the order they're probed
     */
    public Collection<Choice<?>> all() {
        return choices.values();
    }

    /**
     * Warn once about each migration that this CoreProtect has but
     * LibreProtect can't do with it, naming it as users know it and what
     * CoreProtect lacks. Auto-purge says so itself when it's on (see
     * {@link CoreProtectPurge#unavailableReason()}), and the steps that do
     * without a hook say so when they skip it.
     */
    private static void warnAboutUnavailable(Capabilities capabilities) {
        CoreProtectMigration.unavailableFeatures(capabilities).forEach((feature, reason) ->
            LibreProtectLogger.warning(feature + " won't work with this CoreProtect build: " + reason + "."));
    }
}
