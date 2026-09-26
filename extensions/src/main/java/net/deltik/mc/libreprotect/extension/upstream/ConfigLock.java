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

import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The lock that CoreProtect 25 holds on {@code ConfigHandler} itself, in its
 * {@code static synchronized} methods, while it resolves an identifier that
 * its cache lacks, such as a material's ID, by allocating a new one, reading
 * it from ClickHouse or reloading that kind's whole cache; while it reloads
 * a kind's cache to look one up, when {@code database-lock} is off; and
 * while it drops one from its cache. Those read the active database's type,
 * so changing it under this lock keeps a resolution from seeing half of the
 * change. CoreProtect 24 has no such lock.
 *
 * <p>The lock doesn't cover the bulk cache loaders, such as
 * {@code loadWorlds} and {@code loadTypes}, which allocate and replace
 * identifiers and their counters without it: at startup, on
 * {@code /co reload}, and on the consumer thread as it inserts new
 * identifiers. So hold it only while CoreProtect's consumer is paused and
 * its reloads are locked out, as while a migration holds CoreProtect's
 * database reload; then only the locked resolutions, from event listeners,
 * can change identifiers.
 */
public final class ConfigLock {

    public static final Capability<ConfigLock> CAPABILITY = Capability.of("config.lock",
        Choice.way("class-monitor", "CoreProtect's lock on ConfigHandler", ConfigLock::new));

    /** What each of CoreProtect 25's static synchronized methods does while it holds the lock */
    private static final Map<String, String> HOLDERS = new HashMap<>();

    static {
        HOLDERS.put("resolveMissingIdentifierId", "resolves an identifier that its cache lacks, allocating a new"
            + " one, reading it from ClickHouse or reloading that kind's whole cache, while holding the lock on"
            + " ConfigHandler");
        HOLDERS.put("reloadAndGetId", "reloads a kind's whole identifier cache to look one up, when database-lock"
            + " is off, while holding the lock on ConfigHandler");
        HOLDERS.put("loadMissingIdentifierValue", "reads the value of an identifier that its cache lacks from"
            + " ClickHouse, while holding the lock on ConfigHandler");
        HOLDERS.put("uncacheIdentifier", "drops an identifier from its cache while holding the lock on"
            + " ConfigHandler");
    }

    private final Object monitor;

    private ConfigLock(Upstream upstream) throws Missing {
        UpstreamClass handler = upstream.type(Names.CONFIG_HANDLER);
        List<String> methods = handler.staticSynchronizedMethods();
        if (methods.isEmpty()) {
            Designs.MULTI_ENGINE.requireIn(upstream);
            throw new Missing(upstream.name() + "'s ConfigHandler has no static synchronized method any more");
        }
        for (String method : methods) {
            String name = method.substring(0, method.indexOf('('));
            upstream.relyOn(HOLDERS.getOrDefault(name, "changes identifiers or their caches while holding the lock"
                + " on ConfigHandler"), Names.CONFIG_HANDLER, method);
        }
        monitor = handler.type();
    }

    /**
     * @return the object to synchronize on, as {@code synchronized (ConfigHandler.class)}
     *         would; only while CoreProtect's consumer is paused and its
     *         reloads are locked out (see the class comment)
     */
    public Object monitor() {
        return monitor;
    }

    /**
     * Run an action while holding the lock; only while CoreProtect's
     * consumer is paused and its reloads are locked out (see the class
     * comment).
     */
    public void run(Runnable action) {
        synchronized (monitor) {
            action.run();
        }
    }
}
