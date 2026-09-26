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

import net.deltik.mc.libreprotect.extension.common.Engine;

import java.sql.SQLException;
import java.util.Set;

/**
 * The parts of {@code /co migrate-db} that depend on CoreProtect's internals.
 * Implemented by
 * {@code net.deltik.mc.libreprotect.extension.upstream.CoreProtectMigration},
 * which adapts to whichever CoreProtect runs, by capability.
 */
public interface MigrationBridge {

    /**
     * @return the engines that this CoreProtect has and a migration can write
     */
    Set<Engine> engines();

    /**
     * @return the engine CoreProtect is using now, which is the migration's
     *         source, or {@code null} if it's one that LibreProtect doesn't
     *         know or can't tell
     */
    Engine activeEngine();

    /**
     * @return why {@code /co migrate-db} can't work with this CoreProtect at
     *         all, such as a part of CoreProtect it needs that changed, or
     *         {@code null} if it can
     */
    default String unavailableReason() {
        return null;
    }

    /**
     * @return why migrating to {@code target} from the database CoreProtect
     *         uses now can't work with this CoreProtect, or {@code null} if it
     *         can, or if CoreProtect doesn't have that engine at all
     */
    default String unavailableReason(Engine target) {
        return null;
    }

    /**
     * Claim CoreProtect's database for a migration to {@code target}, or
     * explain why that isn't possible now: another migration, a purge, a
     * rollback or a conversion is running, or CoreProtect's configuration
     * doesn't allow it. On success, CoreProtect stops starting new database
     * work until {@link MigrationSession#close()}.
     *
     * <p>Called on the thread that runs the command, which is the server's
     * main thread, so that the claim can't interleave with a shutdown.
     * Never blocks on I/O.
     *
     * @param target an engine from {@link #engines()} other than {@link #activeEngine()}
     * @throws MigrationException with the reason the migration can't start
     */
    MigrationSession claim(Engine target) throws MigrationException;

    /**
     * Convert a value from one engine's encoding to another's. CoreProtect
     * encodes entity data and block metadata differently for columnar
     * engines; everything else passes through unchanged.
     *
     * @param table the unprefixed table the value belongs to
     * @param column the column the value belongs to
     * @throws SQLException if the value can't be converted
     */
    Object transcode(String table, String column, Object value, Engine from, Engine to) throws SQLException;

    /**
     * @return the value in one encoding that doesn't depend on the engine it
     *         came from, for comparing values across engines that encode it
     *         differently; unchanged for values that aren't encoded
     * @throws SQLException if the value can't be decoded
     */
    Object canonical(String table, String column, Object value) throws SQLException;
}
