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
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamEnum;

import java.util.Objects;

/**
 * What CoreProtect 25 answered when asked to start database maintenance,
 * such as a reload or a purge claim: its {@code Consumer.OperationStartResult},
 * by name. A result LibreProtect doesn't know, which a newer CoreProtect
 * could add, is {@link Kind#OTHER}, with its name kept for messages.
 */
public final class StartResult {

    /** The results LibreProtect knows */
    public enum Kind {
        STARTED, PURGE_RUNNING, ROLLBACK_RUNNING, RELOAD_RUNNING, PERSISTENCE_HALTED, INTERRUPTED, OTHER
    }

    /** Probes CoreProtect's results, for the report; mapping them needs nothing but their names */
    public static final Capability<UpstreamEnum> CAPABILITY = Capability.of("consumer.start-result",
        Choice.way("named-results", "CoreProtect's answers to starting database maintenance", StartResult::probe));

    private final Kind kind;
    private final String name;

    private StartResult(Kind kind, String name) {
        this.kind = kind;
        this.name = name;
    }

    private static UpstreamEnum probe(Upstream upstream) throws Missing {
        Designs.MULTI_ENGINE.requireIn(upstream);
        UpstreamEnum results = upstream.type(Names.OPERATION_START_RESULT).asEnum();
        results.require(Kind.STARTED.name());
        return results;
    }

    /**
     * @param result a constant of CoreProtect's {@code OperationStartResult}
     */
    public static StartResult of(Object result) {
        String name = result instanceof Enum ? ((Enum<?>) result).name() : String.valueOf(result);
        for (Kind kind : Kind.values()) {
            if (kind.name().equals(name)) {
                return new StartResult(kind, name);
            }
        }
        return new StartResult(Kind.OTHER, name);
    }

    public Kind kind() {
        return kind;
    }

    /**
     * @return CoreProtect's name of the result
     */
    public String name() {
        return name;
    }

    public boolean started() {
        return kind == Kind.STARTED;
    }

    /**
     * @return why the maintenance couldn't start, for the person who asked
     *         for it, or {@code null} if it started
     */
    public String refusal() {
        switch (kind) {
            case STARTED:
                return null;
            case PURGE_RUNNING:
                // Automatic purges of ClickHouse set purgeRunning as well, for as long as they run
                return "A purge is running, perhaps an automatic one. Try again once it has finished.";
            case ROLLBACK_RUNNING:
                return "A rollback or restore is running. Wait for it to finish.";
            case RELOAD_RUNNING:
                return "CoreProtect is reloading its database. Wait for it to finish.";
            case PERSISTENCE_HALTED:
                return "CoreProtect stopped saving events after a database failure. Restart the server before"
                    + " migrating.";
            case INTERRUPTED:
                return "The server is stopping.";
            default:
                return "CoreProtect's database is busy (" + name + ").";
        }
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof StartResult && kind == ((StartResult) other).kind
            && name.equals(((StartResult) other).name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kind, name);
    }

    @Override
    public String toString() {
        return name;
    }
}
