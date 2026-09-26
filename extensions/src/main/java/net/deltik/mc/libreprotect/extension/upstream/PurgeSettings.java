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
import net.deltik.mc.libreprotect.extension.upstream.reflect.InstanceField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;

/**
 * Automatic purging's settings, as CoreProtect read them from
 * {@code config.yml}, which {@code /co reload} rereads: {@code auto-purge},
 * a capability of its own, so that whether automatic purging is on is
 * known whatever else CoreProtect renames; then {@code auto-purge-time} and
 * the table prefix of the database CoreProtect uses. ClickHouse's
 * {@code database-lock} is part of {@link PurgeEngine#CLICKHOUSE}.
 */
public final class PurgeSettings {

    public static final Capability<Retention> RETENTION = Capability.of("auto-purge.retention",
        Choice.way("config-field", "CoreProtect's auto-purge setting", Retention::new));

    public static final Capability<PurgeSettings> CAPABILITY = Capability.of("auto-purge.settings",
        Choice.way("config-fields", "CoreProtect's auto-purge-time and table prefix settings", PurgeSettings::new));

    private final StaticMethod<?, RuntimeException> global;
    private final InstanceField time;
    private final StaticField prefix;

    private PurgeSettings(Upstream upstream) throws Missing {
        UpstreamClass config = upstream.type(Names.CONFIG);
        global = config.staticMethod("getGlobal", config.type());
        time = config.field("AUTO_PURGE_TIME", String.class);
        prefix = upstream.type(Names.CONFIG_HANDLER).staticField("prefix", String.class);
    }

    /**
     * @return {@code auto-purge-time}, or {@code null}
     */
    public String time() {
        return (String) time.get(global.call());
    }

    /**
     * @return the table prefix of the database CoreProtect uses, such as {@code co_}
     */
    public String tablePrefix() {
        return (String) prefix.get();
    }

    /**
     * {@code auto-purge}: how much data to keep, which also turns automatic
     * purging on or off.
     */
    public static final class Retention {
        private final StaticMethod<?, RuntimeException> global;
        private final InstanceField retention;

        private Retention(Upstream upstream) throws Missing {
            UpstreamClass config = upstream.type(Names.CONFIG);
            global = config.staticMethod("getGlobal", config.type());
            retention = config.field("AUTO_PURGE", String.class);
            upstream.doc("docs/auto-purge.md", "auto-purge keeps that much data, at least 30 days, and is off unless"
                + " set; older rows are removed daily at auto-purge-time, in small chunks with pauses between them;"
                + " a shutdown, manual purge, migration, conversion or paused consumer stops a run until the next");
        }

        /**
         * @return {@code auto-purge}, or {@code null}
         */
        public String value() {
            return (String) retention.get(global.call());
        }
    }
}
