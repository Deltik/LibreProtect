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

import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.MigrationException;

import java.util.List;
import java.util.function.Function;

/**
 * How CoreProtect selects its database, and how a migration switches that
 * over: the other half of a {@link MigrationProtocol}. Where each engine's
 * database is, as CoreProtect has its settings loaded, is the engine's own
 * (see {@link EngineSide}); the selection says which table prefix a target
 * gets, and where CoreProtect takes a target's settings from. Only the
 * thread that holds CoreProtect's database work (see {@link Pause}) may
 * change the selection.
 */
interface Selection {

    /**
     * @param loaded where CoreProtect has the target's database, as it
     *               loaded its settings, given a table prefix
     * @return the target's settings as CoreProtect has them loaded now, to
     *         compare later ones with, or {@code null} if the target's
     *         settings are read from config.yml, which may be slow
     */
    DatabaseSettings loadedTargetSettings(Engine source, Engine target, Function<String, DatabaseSettings> loaded);

    /**
     * @param loaded where CoreProtect has the target's database, as it
     *               loaded its settings, given a table prefix
     * @return where the target's database is, as CoreProtect will use it
     *         after the switch
     * @throws MigrationException if they can't be read
     */
    DatabaseSettings targetSettings(Engine source, Engine target, Function<String, DatabaseSettings> loaded)
        throws MigrationException;

    /**
     * @return the start of a message saying that the target's settings
     *         changed, such as "CoreProtect's MySQL settings changed after the
     *         migration began, such as on /co reload"
     */
    String targetSettingsChanged(Engine target);

    /**
     * @return the table prefix of the database that CoreProtect uses now
     */
    String activePrefix();

    /**
     * @return whether CoreProtect checks a database's lock when it starts on
     *         it, which keeps it off an unfinished target
     */
    boolean databaseLockEnabled();

    /**
     * Check that the switch will be able to select the target in config.yml.
     *
     * @throws MigrationException saying what's in the way
     */
    void preflight() throws MigrationException;

    /**
     * Once CoreProtect is held: make sure that a restart during the copy
     * keeps using the source.
     *
     * @return notes for the person who ran the command; possibly none
     */
    List<String> whileCopying(Engine source, Engine target) throws MigrationException;

    /**
     * @return the selection as it is now, to switch back to
     */
    Selected current();

    /**
     * Make CoreProtect select the target, with its settings, as if it had
     * started with them. Nothing connects to it yet.
     */
    void select(Engine target, DatabaseSettings settings) throws Exception;

    /**
     * Make CoreProtect connect anew to the database it selects, keeping its
     * caches of identifiers.
     */
    void load() throws Exception;

    /**
     * Select the target in config.yml, so that CoreProtect starts on it.
     *
     * @return a note saying so
     */
    String persist(Engine target) throws Exception;

    /**
     * After a failure: make config.yml select the database that CoreProtect
     * uses, where the migration may have changed that. Never throws.
     *
     * @return notes for the person who ran the command; possibly none
     */
    List<String> afterFailure();

    /**
     * @return the note that a target whose switch failed is marked as an
     *         unfinished migration again, saying what CoreProtect does with it
     */
    String markedAgain();

    /**
     * A selection as it was, which can be put back.
     */
    interface Selected {
        void restore();
    }
}
