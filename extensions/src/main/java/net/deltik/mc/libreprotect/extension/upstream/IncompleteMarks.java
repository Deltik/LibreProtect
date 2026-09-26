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

import net.deltik.mc.libreprotect.extension.migration.jdbc.IncompleteMarker;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;

import java.util.function.IntSupplier;

/**
 * How a migration's target says, in its {@code database_lock} row, that it
 * holds an unfinished migration, so that CoreProtect refuses to use it.
 */
public final class IncompleteMarks {

    public static final Capability<IncompleteMarks> CAPABILITY = Capability.of("migrate-db.incomplete-mark",
        Choice.way("dedicated-status", "CoreProtect's own status for an unfinished migration", Designs.MULTI_ENGINE,
            IncompleteMarks::dedicatedStatus),
        Choice.way("locked-forever", "a database lock that never expires, which CoreProtect refuses to start on",
            IncompleteMarks::lockedForever));

    /** CoreProtect 24's status of a database in use by a server */
    private static final int ACTIVE = 1;

    private final IntSupplier incomplete;
    private final IntSupplier inactive;

    private IncompleteMarks(IntSupplier incomplete, IntSupplier inactive) {
        this.incomplete = incomplete;
        this.inactive = inactive;
    }

    /**
     * CoreProtect 25 has a status for an unfinished migration, and refuses to
     * load a database with it, which {@code hasIncompleteMigrationMarker}
     * shows.
     */
    private static IncompleteMarks dedicatedStatus(Upstream upstream) throws Missing {
        requireProtocol(upstream);
        UpstreamClass database = upstream.type(Names.DATABASE);
        IntSupplier incomplete = database.intConstant("DATABASE_LOCK_MIGRATION_INCOMPLETE");
        IntSupplier inactive = database.intConstant("DATABASE_LOCK_INACTIVE");
        upstream.relyOn("finds the unfinished migration's status in the active database's lock row",
            database.staticMethod("hasIncompleteMigrationMarker", boolean.class));
        upstream.relyOn("loads the database as CoreProtect's own, not as a migration's activation, so that the"
            + " unfinished migration's status is checked", Names.CONFIG_HANDLER, "loadDatabase()V");
        upstream.relyOn("refuses to load a database with the unfinished migration's status, unless a migration"
            + " activates it", DatabaseTypeSelection.checkedLoad(upstream.type(Names.CONFIG_HANDLER)));
        relyOnStartupCheck(upstream, "treats a database whose lock row has the unfinished migration's status as"
            + " locked");
        return new IncompleteMarks(incomplete, inactive);
    }

    /**
     * CoreProtect 24 has no such status. It waits at startup for a database
     * that another server holds, then disables itself; a lock whose time
     * never passes holds it forever.
     */
    private static IncompleteMarks lockedForever(Upstream upstream) throws Missing {
        requireProtocol(upstream);
        relyOnStartupCheck(upstream, "waits for a database whose lock row is active and recent, then treats it as"
            + " locked");
        return new IncompleteMarks(null, () -> 0);
    }

    /**
     * Only migrations mark their targets, and every migration needs the
     * protocol, so the capability report says that marking doesn't work
     * whenever migrations don't.
     */
    private static void requireProtocol(Upstream upstream) throws Missing {
        MigrationProtocol.CAPABILITY.probe(upstream).require();
    }

    /**
     * The chain that makes CoreProtect disable itself at startup when the
     * database lock check finds the database locked, with
     * {@code database-lock: true}, which migrations require.
     *
     * @param check what the lock check does with the mark
     */
    private static void relyOnStartupCheck(Upstream upstream, String check) throws Missing {
        upstream.relyOn(check, Names.CONFIG_HANDLER, "checkDatabaseLock(Ljava/sql/Statement;)Z");
        upstream.relyOn("fails CoreProtect's start when the database lock check finds the database locked",
            Names.CONFIG_HANDLER, "performInitialization(Z)Z");
        upstream.relyOn("reports CoreProtect's start as failed when its initialization fails",
            Names.PLUGIN_INITIALIZATION, "initializePlugin(" + Names.descriptor(Names.CORE_PROTECT) + ")Z");
        upstream.relyOn("disables CoreProtect when its start fails", Names.CORE_PROTECT, "onEnable()V");
    }

    /**
     * @return the mark to write into a migration's target until it's complete
     */
    public IncompleteMarker marker() {
        return incomplete != null ? IncompleteMarker.status(incomplete.getAsInt())
            : IncompleteMarker.lockedForever(ACTIVE);
    }

    /**
     * @return the status of a database that no server holds
     */
    public int inactiveStatus() {
        return inactive.getAsInt();
    }
}
