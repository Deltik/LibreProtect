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

package net.coreprotect.utility.extensions;

import net.deltik.mc.libreprotect.extension.purge.AutoPurgeService;

/**
 * CoreProtect's background service, which runs automatic purging
 * ({@code auto-purge} in {@code config.yml}).
 *
 * <p>Since v24.0, upstream CoreProtect's
 * {@code net.coreprotect.utility.Extensions} loads this class by name through
 * reflection. It calls the static {@link #start()} when the plugin enables and
 * {@link #stop()} when it disables. Upstream's own implementation is only in
 * its paid (Patreon) builds: its {@code .gitignore} excludes this package from
 * the public source. LibreProtect's implementation is {@link AutoPurgeService}.
 *
 * <p>The class name, package, method names and signatures are a contract with
 * upstream. LibreProtect's build checks that upstream still references them.
 * Keep this class to the two entry points: the build reports any other class
 * or public method in this package that upstream doesn't ask for.
 *
 * @see <a href="https://github.com/Deltik/LibreProtect">LibreProtect</a>
 */
public final class BackgroundService {

    private BackgroundService() {
    }

    /**
     * Called reflectively when CoreProtect starts its background services.
     */
    public static void start() {
        AutoPurgeService.start();
    }

    /**
     * Called reflectively when CoreProtect shuts down.
     */
    public static void stop() {
        AutoPurgeService.stop();
    }
}
