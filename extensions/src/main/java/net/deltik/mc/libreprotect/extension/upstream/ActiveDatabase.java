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

import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.InstanceField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.InstanceMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticField;
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamEnum;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Which database engines CoreProtect has, and which one it uses now.
 * CoreProtect 25 selects one of its engine types with {@code database-type};
 * CoreProtect 24 has only SQLite and MySQL, selected by {@code use-mysql},
 * which CoreProtect 25 still reads but only as a fallback.
 */
public abstract class ActiveDatabase {

    public static final Capability<ActiveDatabase> CAPABILITY = Capability.of("database.selector",
        Choice.way("database-type", "CoreProtect's database-type setting", Designs.MULTI_ENGINE,
            ByDatabaseType::new),
        Choice.way("use-mysql", "CoreProtect's use-mysql setting", ByUseMySQL::new));

    ActiveDatabase() {
    }

    /**
     * @return the engines CoreProtect has that LibreProtect knows
     */
    public abstract Set<Engine> engines();

    /**
     * @return every engine CoreProtect has, by config name in CoreProtect's
     *         order, with {@code (unsupported)} after those LibreProtect
     *         doesn't know, such as {@code postgresql(unsupported)}
     */
    public abstract List<String> engineNames();

    /**
     * @return the engine CoreProtect uses now, or {@code null} if it's one
     *         LibreProtect doesn't know
     */
    public abstract Engine activeEngine();

    /**
     * @return what CoreProtect calls an engine in messages, such as {@code MySQL}
     */
    public String displayName(Engine engine) {
        return engine.displayName();
    }

    @Override
    public String toString() {
        return String.join(", ", engineNames());
    }

    /**
     * CoreProtect 25: {@code ConfigHandler.databaseType}, one of its engine
     * enum's constants, which map to LibreProtect's engines by name.
     */
    private static final class ByDatabaseType extends ActiveDatabase {
        private final StaticField databaseType;
        private final UpstreamEnum types;
        private final InstanceMethod<String, RuntimeException> displayName;
        private final Set<Engine> engines = EnumSet.noneOf(Engine.class);
        private final List<String> names = new ArrayList<>();

        ByDatabaseType(Upstream upstream) throws Missing {
            databaseType = upstream.type(Names.CONFIG_HANDLER).staticField("databaseType", Enum.class);
            UpstreamClass type = upstream.type(databaseType.type());
            types = type.asEnum();
            displayName = type.methodIfPresent("getDisplayName", String.class);
            for (String name : types.names()) {
                Optional<Engine> engine = Engine.fromUpstreamName(name);
                engine.ifPresent(engines::add);
                names.add(engine.map(Engine::configName)
                    .orElse(name.toLowerCase(Locale.ROOT) + "(unsupported)"));
            }
            if (engines.isEmpty()) {
                throw new Missing(upstream.name() + "'s engine types " + types.names()
                    + " have none that LibreProtect knows");
            }
            upstream.doc("docs/config.md", "database-type selects the database, and takes precedence over use-mysql");
        }

        @Override
        public Set<Engine> engines() {
            return Collections.unmodifiableSet(engines);
        }

        @Override
        public List<String> engineNames() {
            return Collections.unmodifiableList(names);
        }

        @Override
        public Engine activeEngine() {
            Object active = databaseType.get();
            return active instanceof Enum ? Engine.fromUpstreamName(((Enum<?>) active).name()).orElse(null) : null;
        }

        @Override
        public String displayName(Engine engine) {
            Optional<Enum<?>> type = types.find(engine.name());
            String name = type.isPresent() ? displayName.call(type.get()) : null;
            return name != null ? name : engine.displayName();
        }
    }

    /**
     * CoreProtect 24: {@code Config.getGlobal().MYSQL}, from {@code use-mysql}.
     * CoreProtect 25 still has it, but derives it from its engine type.
     */
    private static final class ByUseMySQL extends ActiveDatabase {
        private static final Set<Engine> ENGINES = Collections.unmodifiableSet(EnumSet.of(Engine.SQLITE,
            Engine.MYSQL));

        private final StaticMethod<?, RuntimeException> global;
        private final InstanceField mySQL;

        ByUseMySQL(Upstream upstream) throws Missing {
            UpstreamClass config = upstream.type(Names.CONFIG);
            global = config.staticMethod("getGlobal", config.type());
            mySQL = config.field("MYSQL", boolean.class);
        }

        @Override
        public Set<Engine> engines() {
            return ENGINES;
        }

        @Override
        public List<String> engineNames() {
            List<String> names = new ArrayList<>();
            for (Engine engine : ENGINES) {
                names.add(engine.configName());
            }
            return names;
        }

        @Override
        public Engine activeEngine() {
            return mySQL.getBoolean(global.call()) ? Engine.MYSQL : Engine.SQLITE;
        }
    }
}
