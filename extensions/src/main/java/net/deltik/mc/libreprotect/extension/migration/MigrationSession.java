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

import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;

import java.sql.SQLException;
import java.util.Collections;
import java.util.List;

/**
 * One claimed migration, from {@link MigrationBridge#claim}. Every method
 * except {@link #stopReason()} and {@link #close()} runs on the migration's
 * own thread, and so must {@link #close()} once {@link #pause()} was called:
 * CoreProtect 25 requires the thread that paused persistence to be the one
 * that resumes it.
 *
 * <p>The migration uses a session in this order: the settings,
 * {@link #preflight()}, the target's checks through {@link #openSink}, then
 * {@link #pause()}, the copy, {@link #activate}, and finally
 * {@link #close()}, with {@link #afterFailure()} before it if anything failed.
 */
public interface MigrationSession {

    /**
     * @return the engine CoreProtect used when the migration was claimed
     */
    Engine source();

    /**
     * @return where CoreProtect's active database is
     */
    DatabaseSettings sourceSettings();

    /**
     * @return where the target database is, as CoreProtect will use it
     *         after the switch
     * @throws MigrationException if the target isn't configured
     */
    DatabaseSettings targetSettings() throws MigrationException;

    /**
     * Check what the switch at the end will need, such as being able to
     * replace config.yml, so that the migration fails before the copy
     * rather than after it. CoreProtect keeps working meanwhile.
     *
     * @throws MigrationException saying what's in the way
     */
    default void preflight() throws MigrationException {
    }

    /**
     * Wait until CoreProtect has finished the database work in progress and
     * writes nothing more to the source. New events wait in CoreProtect's
     * queue.
     *
     * @return notes for the person who ran the command, such as a change to
     *         config.yml; possibly none
     * @throws MigrationException if CoreProtect didn't settle in time, or the
     *                            server is stopping
     */
    List<String> pause() throws MigrationException, InterruptedException;

    /**
     * @return why the migration has to stop now, such as the server
     *         shutting down, or {@code null} to carry on. Called from any
     *         thread; never throws.
     */
    String stopReason();

    /**
     * @return a reader of CoreProtect's active database; call after {@link #pause()}
     */
    RowSource openSource() throws SQLException;

    /**
     * @return a writer of the target database; nothing is written until
     *         {@link RowSink#prepare}
     */
    RowSink openSink(DatabaseSettings target) throws SQLException;

    /**
     * Switch CoreProtect to the target: clear the target's unfinished-migration
     * mark, close the sink or hand it over to CoreProtect, make CoreProtect
     * use the target without reloading its caches, and select the target in
     * config.yml. If any of that fails, switch CoreProtect back to the source,
     * mark the target unfinished again where possible, and throw. If the
     * source can't be restored either, CoreProtect 25 stops persisting events.
     *
     * <p>The source reader must be closed before this is called.
     *
     * @return notes about the switch for the person who ran the command,
     *         such as the config.yml change
     * @throws MigrationException if CoreProtect isn't using the target; the
     *                            details say what it's using instead
     */
    List<String> activate(RowSink sink, DatabaseSettings target) throws MigrationException;

    /**
     * Tidy up after a failed migration, such as making config.yml select the
     * database that CoreProtect uses again.
     *
     * @return what the person who ran the command should know about it;
     *         possibly nothing. Never throws.
     */
    default List<String> afterFailure() {
        return Collections.emptyList();
    }

    /**
     * Release the claim: CoreProtect resumes its database work on whichever
     * database is active, which is the target after a successful
     * {@link #activate} and the source otherwise. Never throws, and does
     * nothing when called again.
     */
    void close();
}
