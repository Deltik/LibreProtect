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

package net.deltik.mc.lpit;

/**
 * One feature's steps. {@link ItPlugin} calls {@link #run} for each step in
 * {@code scenario.properties} whose name is the feature's name, or starts
 * with it and a dot ({@code migration}, {@code migration.seed}).
 *
 * <p>{@code run} is called on the main thread. It schedules its work through
 * the context, and the step is done once all of that work is done; the next
 * step starts after it.
 */
@FunctionalInterface
interface Scenario {

    void run(ScenarioContext ctx) throws Exception;
}
