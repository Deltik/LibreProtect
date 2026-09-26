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
import net.deltik.mc.libreprotect.extension.upstream.reflect.StaticMethod;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.extension.upstream.reflect.UpstreamClass;

import java.util.concurrent.Executor;

/**
 * The thread where CoreProtect runs commands and its shutdown: the server's
 * main thread, or on Folia the global region, whose ticks stop before
 * plugins are disabled. Reached through CoreProtect's scheduler, which knows
 * which one it is.
 */
public final class ServerThread {

    public static final Capability<ServerThread> CAPABILITY = Capability.of("server.thread",
        Choice.way("scheduler", "CoreProtect's scheduler, on the server's main thread", ServerThread::new));

    private final StaticMethod<?, RuntimeException> instance;
    private final StaticMethod<Void, RuntimeException> runTask;

    private ServerThread(Upstream upstream) throws Missing {
        UpstreamClass plugin = upstream.type(Names.CORE_PROTECT);
        instance = plugin.staticMethod("getInstance", plugin.type());
        runTask = upstream.type(Names.SCHEDULER).staticMethod("runTask", void.class, plugin.type(), Runnable.class);
    }

    /**
     * Run a task on the server's thread, soon.
     */
    public void run(Runnable task) {
        runTask.call(instance.call(), task);
    }

    /**
     * @return an executor of tasks on the server's thread
     */
    public Executor executor() {
        return this::run;
    }
}
