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

import net.deltik.mc.libreprotect.extension.common.Engine;

import java.sql.SQLException;
import java.util.List;

/**
 * The parts of automatic purging that depend on CoreProtect's internals.
 * Implemented by
 * {@code net.deltik.mc.libreprotect.extension.upstream.CoreProtectPurge},
 * which adapts to whichever CoreProtect runs, by capability.
 *
 * <p>Everything but {@link #abandon} is called on the auto-purge thread.
 */
public interface PurgeBridge {

    /**
     * @return why automatic purging can't work with this CoreProtect build,
     *         or with the database it uses now, for the console; or
     *         {@code null} if it can
     */
    default String unavailableReason() {
        return null;
    }

    /**
     * @return why {@code auto-purge} can't be read from this CoreProtect
     *         build, so that whether automatic purging is on is unknown, for
     *         the console; or {@code null} if it can
     */
    default String settingsUnavailableReason() {
        return null;
    }

    /**
     * @return the engine CoreProtect is using now
     */
    Engine activeEngine();

    /**
     * @return {@code auto-purge} as CoreProtect read it from config.yml, or
     *         {@code null}, also if {@link #settingsUnavailableReason} says it
     *         can't be read
     */
    String retentionSetting();

    /**
     * @return {@code auto-purge-time} as CoreProtect read it from config.yml, or {@code null}
     */
    String timeSetting();

    /**
     * @return whether {@code database-lock} is on, which ClickHouse purges need
     */
    boolean databaseLock();

    /**
     * @return the table prefix of the active database, such as {@code co_}
     */
    String tablePrefix();

    /**
     * @return the unprefixed tables whose rows are purged by their {@code time} column
     */
    List<String> purgeableTables();

    /**
     * @return whether the schema links rows to {@code entity_spawn}
     *         (CoreProtect 25), whose orphans a purge cleans up
     */
    boolean tracksEntitySpawns();

    /**
     * @return what {@link #tracksEntitySpawns} says, or {@code null} if the
     *         bridge can't tell right now, such as while CoreProtect refills
     *         its list of tables; orphan cleanup then waits for a later run
     */
    default Boolean entitySpawnTracking() {
        return tracksEntitySpawns();
    }

    /**
     * @return something that changes when the active database is replaced,
     *         such as the SQLite file's identity, which a manual purge
     *         changes by swapping in a rebuilt file; or {@code null} if unknown
     */
    Object databaseIdentity();

    /**
     * @return why purging must stop now, or {@code null} to go on; for
     *         {@link StopReason#UNSUPPORTED_DATABASE}, {@link #unavailableReason}
     *         says why
     */
    StopReason stopReason();

    /**
     * Take what CoreProtect needs held for one unit of purge work and open a
     * connection for it. Returns a lease that says why not instead, if the
     * purge must stop or wait.
     *
     * @param exclusive whether the work needs other database users to wait:
     *                  orphan cleanup and a DuckDB checkpoint need every
     *                  connection closed; a ClickHouse purge needs the
     *                  consumer paused, and gets no connection
     */
    Lease lease(PurgeContext context, boolean exclusive) throws InterruptedException;

    /**
     * Delete rows older than {@code cutoff} with CoreProtect's ClickHouse
     * retention: drop covered monthly partitions, then delete the rest.
     * Called while holding an exclusive lease.
     *
     * @return rows removed
     */
    long purgeClickHouse(long cutoff) throws SQLException;

    /**
     * Hand a failure to CoreProtect's database recovery, if it is one that
     * needs the database reopened (DuckDB).
     *
     * @return whether it was; the purge must stop
     */
    boolean requestRecovery(SQLException failure);

    /**
     * Count rows removed toward {@code /co status}.
     */
    void rowsPurged(long rows);

    /**
     * Called after a purge removed rows, so CoreProtect can recheck what it
     * caches about them. Also called while a lease is still held: after a
     * ClickHouse purge, and after chunks that removed {@code entity_spawn}
     * rows, at most every 30 seconds and once more at the end.
     */
    void purged();

    /**
     * @return how long stopping may wait for the purge to end, in
     *         milliseconds; 0 if CoreProtect itself waits for its claims
     */
    long stopTimeoutMillis();

    /**
     * Called on the stopping thread if the purge didn't end within
     * {@link #stopTimeoutMillis}: give back anything shutdown can't do
     * without, such as the cooperative gate.
     */
    void abandon();
}
