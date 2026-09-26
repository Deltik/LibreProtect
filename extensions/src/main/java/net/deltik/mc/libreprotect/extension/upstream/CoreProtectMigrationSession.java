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

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.MigrationException;
import net.deltik.mc.libreprotect.extension.migration.MigrationSession;
import net.deltik.mc.libreprotect.extension.migration.RowSink;
import net.deltik.mc.libreprotect.extension.migration.RowSource;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Future;

/**
 * One claimed migration, the same for every CoreProtect: its
 * {@link MigrationProtocol} says how CoreProtect is held and switched, and
 * the source's and target's {@link EngineSide}s how they're read and
 * written and where CoreProtect has them.
 *
 * <p>Until {@link #pause()}, CoreProtect keeps working, and a
 * {@code /co reload} may still switch it to another database or change the
 * settings that the switch will use; so once CoreProtect is held, and again
 * at the switch, the migration checks that it still has the settings that
 * the migration began with.
 *
 * <p>The switch keeps CoreProtect's caches of identifiers, since the copy
 * kept every ID and queued events already use them. Whatever goes wrong
 * during the switch, even an error such as running out of memory,
 * CoreProtect is switched back before it may save events again, and the
 * target is marked unfinished again once its mark may have been cleared.
 * If CoreProtect can't use the source either, it stops saving events where
 * it can.
 */
final class CoreProtectMigrationSession implements MigrationSession {

    private static final long DRAIN_TIMEOUT_MILLIS = 120_000;
    private static final String NOTHING_COPIED = "Nothing was copied.";
    private static final String NOT_SWITCHED = "CoreProtect didn't switch to the target.";

    private final MigrationProtocol protocol;
    private final Pause pause;
    private final Selection selection;
    private final Flags flags;
    private final Engine source;
    private final Engine target;
    private final EngineSide sourceSide;
    private final EngineSide targetSide;
    /** CoreProtect's shutdown signal as it was at the claim, which also completes when CoreProtect restarts */
    private final Future<?> claimSignal;
    /** The source, as CoreProtect used it when the migration began */
    private final DatabaseSettings sourceAtClaim;
    private final String prefixAtClaim;
    /** The target, as CoreProtect had it loaded when the migration began, or as first read */
    private DatabaseSettings targetAtClaim;
    /** Guarded by this */
    private Pause.Hold hold;
    private boolean halted;
    /** Guarded by this */
    private boolean closed;

    /**
     * Called on the thread that claims the migration.
     *
     * @param sourceSide how the source is read, and where CoreProtect has it
     * @param targetSide how the target is written, and where CoreProtect has it
     */
    CoreProtectMigrationSession(MigrationProtocol protocol, Engine source, Engine target, EngineSide sourceSide,
                                EngineSide targetSide) {
        this.protocol = protocol;
        this.pause = protocol.pause();
        this.selection = protocol.selection();
        this.flags = protocol.flags();
        this.source = source;
        this.target = target;
        this.sourceSide = sourceSide;
        this.targetSide = targetSide;
        this.claimSignal = pause.shutdownSignal();
        this.sourceAtClaim = sourceSettings();
        this.prefixAtClaim = selection.activePrefix();
        this.targetAtClaim = selection.loadedTargetSettings(source, target, targetSide::settings);
    }

    @Override
    public Engine source() {
        return source;
    }

    @Override
    public DatabaseSettings sourceSettings() {
        return sourceSide.settings(selection.activePrefix());
    }

    @Override
    public DatabaseSettings targetSettings() throws MigrationException {
        DatabaseSettings settings = selection.targetSettings(source, target, targetSide::settings);
        if (targetAtClaim == null) {
            targetAtClaim = settings;
        }
        return settings;
    }

    @Override
    public void preflight() throws MigrationException {
        selection.preflight();
    }

    /**
     * Hold CoreProtect on this thread, the way its protocol does, then check
     * that it still has the settings that the migration began with, and make
     * sure that a restart during the copy keeps using the source. A session
     * that was closed holds nothing any more.
     */
    @Override
    public List<String> pause() throws MigrationException, InterruptedException {
        Pause.Hold held;
        synchronized (this) {
            requireOpen();
            if (hold != null) {
                throw new IllegalStateException("The migration already paused CoreProtect");
            }
            held = pause.hold(this::stopReason);
            hold = held;
        }
        held.acquire();
        checkSettingsUnchanged(targetAtClaim, NOTHING_COPIED);
        return selection.whileCopying(source, target);
    }

    /**
     * Refuse to go on once CoreProtect no longer has the settings loaded that
     * the migration began with: it may have saved events to another
     * database, even the target, and the switch would load another target
     * than the one copied to.
     *
     * @param expectedTarget the target's settings the migration uses, or
     *                       {@code null} if none were read yet
     * @param outcome what that means for the migration, for the message
     */
    private void checkSettingsUnchanged(DatabaseSettings expectedTarget, String outcome) throws MigrationException {
        Engine inUse = activeEngine();
        if (inUse != source) {
            throw new MigrationException("CoreProtect switched to " + describeEngine(inUse) + " after the migration"
                + " began, such as on /co reload, and may have saved events there. " + outcome + " Check which"
                + " database config.yml selects, and try again.");
        }
        DatabaseSettings sourceNow = sourceSettings();
        if (!sourceNow.sameAs(sourceAtClaim) || !selection.activePrefix().equals(prefixAtClaim)) {
            throw new MigrationException("CoreProtect's " + source.displayName() + " settings changed after the"
                + " migration began, such as on /co reload: it now uses the " + sourceNow.describe() + " instead of"
                + " the " + sourceAtClaim.describe() + ". " + outcome + " Try again.");
        }
        DatabaseSettings targetNow = targetSettings();
        if (expectedTarget != null && !targetNow.sameAs(expectedTarget)) {
            throw new MigrationException(selection.targetSettingsChanged(target) + ": they now point to the "
                + targetNow.describe() + " instead of the " + expectedTarget.describe() + ". " + outcome
                + " Try again.");
        }
    }

    /**
     * @return why the migration has to stop now: CoreProtect's shutdown, by
     *         every signal it has, or a restart of CoreProtect since the claim
     */
    @Override
    public String stopReason() {
        try {
            if (flags.shuttingDown() || (claimSignal != null && claimSignal.isDone())) {
                return "the server is stopping";
            }
            return null;
        } catch (RuntimeException | LinkageError e) {
            return "LibreProtect can't tell whether the server is stopping (" + e + ")";
        }
    }

    @Override
    public RowSource openSource() throws SQLException {
        return sourceSide.endpoints().openSource(sourceSettings());
    }

    @Override
    public RowSink openSink(DatabaseSettings settings) throws SQLException {
        return targetSide.endpoints().openSink(settings);
    }

    /**
     * The switch, in the order CoreProtect's docs imply: the selector changes
     * only once the target is ready, and config.yml only once CoreProtect
     * uses the target.
     *
     * <p>CoreProtect refuses to load a database that is marked unfinished,
     * and connects to a target of the migration's JDBC code anew, so its
     * mark is cleared first. A target that CoreProtect takes over as it is,
     * such as ClickHouse, keeps its mark until CoreProtect uses it.
     */
    @Override
    public List<String> activate(RowSink sink, DatabaseSettings settings) throws MigrationException {
        synchronized (this) {
            requireOpen();
        }
        String stop = stopReason();
        if (stop != null) {
            throw new MigrationException("CoreProtect didn't switch to the target because " + stop + ".");
        }
        checkSettingsUnchanged(settings, NOT_SWITCHED);
        Selection.Selected previous = selection.current();
        Object prepared = null;
        Object detached = null;
        boolean markCleared = false;
        boolean selected = false;
        List<String> notes = new ArrayList<>();
        try {
            if (targetSide.handsOver()) {
                prepared = targetSide.endpoints().handOver(sink);
            } else {
                // Set first, here and below: clearing may reach the target even when its answer doesn't
                markCleared = true;
                sink.markComplete();
                sink.close();
            }
            if (!protocol.awaitDrain(DRAIN_TIMEOUT_MILLIS)) {
                throw new SQLException("CoreProtect's database connections didn't close");
            }
            // Keep a source that CoreProtect takes over, such as ClickHouse's with its writer lock, to switch back to
            detached = sourceSide.detach();
            selected = true;
            selection.select(target, settings);
            if (prepared != null) {
                targetSide.takeOver(prepared);
            } else {
                selection.load();
            }
            Engine inUse = activeEngine();
            if (inUse != target) {
                throw new SQLException("CoreProtect couldn't initialize " + target.displayName() + " and fell back to "
                    + (inUse == null ? "a database LibreProtect doesn't know" : inUse.displayName()));
            }
            checkActive();
            if (prepared != null) {
                markCleared = true;
                sink.markComplete();
            }
            afterSwitch(protocol.heartbeat(), Hooks.LockHeartbeat::reset, "write the target's lock soon", notes);
            notes.add(selection.persist(target));
        } catch (Throwable e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            List<String> details = new ArrayList<>();
            // A target that CoreProtect took over is still open here, so its own sink can mark it again
            boolean marked = markCleared && prepared != null && markIncomplete(sink);
            if (selected) {
                details.add(switchBack(previous, detached));
            }
            if (prepared != null) {
                // Release it, such as ClickHouse's writer lock; CoreProtect may have closed it already
                closeQuietly(targetSide, prepared);
            }
            if (marked) {
                details.add(selection.markedAgain());
            } else if (markCleared) {
                details.add(markIncompleteAgain(settings));
            }
            if (e instanceof Error) {
                LibreProtectLogger.severe("/co migrate-db couldn't switch to the " + settings.describe() + ": " + e
                    + ". " + String.join(" ", details));
                throw (Error) e;
            }
            throw new MigrationException("CoreProtect couldn't switch to the " + settings.describe() + ": "
                + message(e), e, details);
        }
        afterSwitch(protocol.spawnVerification(), Hooks.EntitySpawnVerification::invalidate, "check its tracked"
            + " entities against the target", notes);
        afterSwitch(protocol.recovery(), Hooks.DuckDBRecovery::reset, "forget a recovery of the source", notes);
        if (detached != null) {
            try {
                sourceSide.close(detached);
            } catch (SQLException | RuntimeException e) {
                notes.add("Closing the connection to the old " + source.displayName() + " database failed: "
                    + message(e));
            }
        }
        return notes;
    }

    /**
     * Take a step that tidies up after CoreProtect uses the target, through a
     * hook where CoreProtect has it. Without the hook, or when it fails, the
     * switch stands, and the note says what CoreProtect wasn't told.
     *
     * @param what what CoreProtect was to do, following "CoreProtect couldn't be told to"
     */
    private static <T> void afterSwitch(Choice<T> hook, java.util.function.Consumer<T> step, String what,
                                        List<String> notes) {
        if (hook.isAbsent()) {
            return;
        }
        String failure;
        if (!hook.isAvailable()) {
            failure = hook.reason();
        } else {
            try {
                step.accept(hook.orElse(null));
                return;
            } catch (RuntimeException | LinkageError e) {
                failure = e.toString();
            }
        }
        String note = "CoreProtect couldn't be told to " + what + ": " + failure;
        LibreProtectLogger.warning("/co migrate-db: " + note);
        notes.add(note);
    }

    /**
     * Restore the source's selection and load it.
     *
     * @return what happened, for the failure message
     */
    private String switchBack(Selection.Selected previous, Object detached) {
        try {
            previous.restore();
            if (detached != null) {
                sourceSide.takeOver(detached);
            } else {
                selection.load();
            }
            Engine inUse = activeEngine();
            checkActive();
            if (inUse == source) {
                return "CoreProtect switched back to the " + sourceSettings().describe() + ".";
            }
            // CoreProtect 24 falls back to SQLite when MySQL's pool connects but its tables can't be created
            return "CoreProtect couldn't reconnect to the " + sourceSettings().describe() + ", so it fell back to "
                + (inUse == target ? "its " + targetSide.settings(selection.activePrefix()).describe()
                + ", the migration's target," : describeEngine(inUse)) + " and saves events there until the server"
                + " restarts.";
        } catch (Throwable restoreFailure) {
            try {
                halted = pause.haltPersistence();
            } catch (RuntimeException | LinkageError e) {
                // It may have halted before it failed; resuming onto no database is worse than staying paused
                halted = true;
                LibreProtectLogger.severe("/co migrate-db couldn't stop CoreProtect from saving events: " + e);
            }
            if (restoreFailure instanceof VirtualMachineError) {
                throw (VirtualMachineError) restoreFailure;
            }
            if (halted) {
                return "CoreProtect couldn't switch back to the " + sourceSettings().describe() + " either ("
                    + message(restoreFailure) + "), so it stopped saving events. Fix the problem and restart the"
                    + " server; events it hasn't saved yet are lost then.";
            }
            return "CoreProtect couldn't switch back to the " + sourceSettings().describe() + " either: "
                + message(restoreFailure) + ". It can't save events until the problem is fixed and the server"
                + " restarts.";
        }
    }

    @Override
    public List<String> afterFailure() {
        try {
            return selection.afterFailure();
        } catch (RuntimeException | LinkageError e) {
            return Collections.emptyList();
        }
    }

    /**
     * Release what {@link #pause()} held, on the thread that holds it, and
     * the claim. After a failed switch back, persistence stays halted. From
     * any other thread, nothing is released: that thread has to close the
     * session itself.
     */
    @Override
    public void close() {
        Pause.Hold held;
        synchronized (this) {
            if (closed) {
                return;
            }
            if (hold != null && !hold.ownedByCurrentThread()) {
                LibreProtectLogger.severe("/co migrate-db was asked to release CoreProtect from the thread "
                    + Thread.currentThread().getName() + ", but only the migration's thread may. CoreProtect stays"
                    + " held until it does.");
                return;
            }
            closed = true;
            held = hold;
        }
        try {
            if (held != null) {
                held.release(!halted);
            }
        } catch (RuntimeException | LinkageError e) {
            LibreProtectLogger.severe("/co migrate-db couldn't release CoreProtect: " + e);
        } finally {
            try {
                flags.setMigrationRunning(false);
            } catch (RuntimeException | LinkageError e) {
                LibreProtectLogger.severe("/co migrate-db couldn't end its claim on CoreProtect: " + e);
            }
        }
    }

    /**
     * @throws MigrationException once the session is closed, which released
     *                            its claim: it may hold CoreProtect no more
     */
    private void requireOpen() throws MigrationException {
        if (closed) {
            throw new MigrationException("The migration ended already, so it doesn't hold or switch CoreProtect any"
                + " more.");
        }
    }

    private Engine activeEngine() {
        return protocol.database().activeEngine();
    }

    /**
     * Check that CoreProtect can use its database now. On CoreProtect 25, this
     * thread holds the reload lock, so it's the only one that can.
     */
    private void checkActive() throws SQLException {
        try (Connection connection = protocol.connection()) {
            if (connection == null) {
                throw new SQLException("CoreProtect couldn't connect to its database");
            }
            try (Statement statement = connection.createStatement();
                 ResultSet result = statement.executeQuery("SELECT COUNT(*) FROM " + selection.activePrefix()
                     + "database_lock")) {
                if (!result.next()) {
                    throw new SQLException("CoreProtect's database didn't answer");
                }
            }
        }
    }

    /**
     * @return whether the sink marked its target unfinished again
     */
    private static boolean markIncomplete(RowSink sink) {
        try {
            sink.markIncomplete();
            return true;
        } catch (SQLException | RuntimeException e) {
            return false;
        }
    }

    private String markIncompleteAgain(DatabaseSettings settings) {
        try (RowSink again = openSink(settings)) {
            again.markIncomplete();
            return selection.markedAgain();
        } catch (SQLException | RuntimeException e) {
            return "The target couldn't be marked as an unfinished migration again (" + message(e) + "). Don't let"
                + " CoreProtect use it before cleaning it.";
        }
    }

    private static String describeEngine(Engine engine) {
        return engine == null ? "a database engine that LibreProtect doesn't know" : "its " + engine.displayName()
            + " database";
    }

    static String message(Throwable e) {
        return e.getMessage() == null ? e.toString() : e.getMessage();
    }

    private static void closeQuietly(EngineSide side, Object database) {
        try {
            side.close(database);
        } catch (SQLException | RuntimeException | LinkageError e) {
            // Switching already failed; that's the error to report
        }
    }
}
