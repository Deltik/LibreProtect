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

package net.deltik.mc.libreprotect.extension.purge;

/**
 * Why an automatic purge stopped before it finished. Each one ends the run
 * safely; the next scheduled run starts over.
 */
public enum StopReason {
    /** The server or plugin is shutting down */
    SHUTDOWN("the server is shutting down"),
    /** Someone ran {@code /co purge} */
    MANUAL_PURGE("a manual purge started"),
    /** Someone ran {@code /co migrate-db} */
    MIGRATION("a database migration started"),
    /** CoreProtect is converting the database to a new schema */
    CONVERSION("a database conversion started"),
    /** Someone ran {@code /co consumer pause} */
    CONSUMER_PAUSED("the consumer is paused"),
    /** CoreProtect stopped writing to the database after a failure */
    PERSISTENCE_HALTED("CoreProtect stopped writing to the database"),
    /** CoreProtect is reopening a DuckDB database after a failure */
    DATABASE_RECOVERY("CoreProtect is recovering the database"),
    /** The engine, table prefix or database file changed during the run */
    DATABASE_CHANGED("the database changed"),
    /** {@code auto-purge} changed during the run */
    SETTINGS_CHANGED("its settings changed"),
    /** ClickHouse purges need {@code database-lock: true} */
    DATABASE_LOCK_DISABLED("ClickHouse purges need database-lock: true in CoreProtect's config.yml"),
    /**
     * This CoreProtect build lacks something that purging its database
     * needs, or uses a database engine LibreProtect doesn't know
     */
    UNSUPPORTED_DATABASE("LibreProtect can't purge this database with this CoreProtect build"),
    /** Other database work kept the purge from running for too long */
    DATABASE_BUSY("the database stayed busy"),
    /** A statement kept failing */
    ERROR("of a database error");

    private final String because;

    StopReason(String because) {
        this.because = because;
    }

    /**
     * @return the reason for messages, to follow "because", such as "a manual purge started"
     */
    public String because() {
        return because;
    }
}
