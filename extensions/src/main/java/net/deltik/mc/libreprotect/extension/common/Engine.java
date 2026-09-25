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

package net.deltik.mc.libreprotect.extension.common;

import java.util.Locale;
import java.util.Optional;

/**
 * A database engine that CoreProtect can store its data in. CoreProtect 24
 * has SQLite and MySQL; CoreProtect 25 adds DuckDB and ClickHouse.
 */
public enum Engine {
    SQLITE("sqlite", "SQLite", true, false),
    MYSQL("mysql", "MySQL", false, false),
    DUCKDB("duckdb", "DuckDB", true, true),
    CLICKHOUSE("clickhouse", "ClickHouse", false, true);

    private final String configName;
    private final String displayName;
    private final boolean embedded;
    private final boolean columnar;

    Engine(String configName, String displayName, boolean embedded, boolean columnar) {
        this.configName = configName;
        this.displayName = displayName;
        this.embedded = embedded;
        this.columnar = columnar;
    }

    /**
     * @return the name used in config.yml's {@code database-type} and in commands
     */
    public String configName() {
        return configName;
    }

    /**
     * @return the engine's name for messages, such as {@code MySQL}
     */
    public String displayName() {
        return displayName;
    }

    /**
     * @return whether the database is a file in CoreProtect's data folder
     */
    public boolean isEmbedded() {
        return embedded;
    }

    /**
     * @return whether CoreProtect stores entity and block metadata in its
     *         columnar encoding for this engine, rather than the legacy one
     */
    public boolean isColumnar() {
        return columnar;
    }

    /**
     * @param name the name of a constant of CoreProtect's engine enum, such
     *             as {@code DUCKDB}, exactly, as enum constants are looked up
     * @return the engine it stands for, or empty for an engine LibreProtect
     *         doesn't know, such as one that a newer CoreProtect added
     */
    public static Optional<Engine> fromUpstreamName(String name) {
        if (name != null) {
            for (Engine engine : values()) {
                if (engine.name().equals(name)) {
                    return Optional.of(engine);
                }
            }
        }
        return Optional.empty();
    }

    /**
     * @return the engine with this config name, ignoring case, or {@code null}
     */
    public static Engine fromConfigName(String name) {
        if (name == null) {
            return null;
        }
        String normalized = name.trim().toLowerCase(Locale.ROOT);
        for (Engine engine : values()) {
            if (engine.configName.equals(normalized)) {
                return engine;
            }
        }
        return null;
    }
}
