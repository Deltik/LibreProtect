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
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * One thing LibreProtect's extensions need from CoreProtect, with the ways
 * to get it, newest first. Its constant is the key to what
 * {@link Capabilities} probed for it.
 *
 * @param <T> what it gives its users
 */
public final class Capability<T> {

    private final String id;
    private final List<Choice.Way<? extends T>> ways;

    private Capability(String id, List<Choice.Way<? extends T>> ways) {
        this.id = Objects.requireNonNull(id, "id");
        this.ways = Collections.unmodifiableList(ways);
    }

    /**
     * @param id the capability's ID in the capability report, such as
     *           {@code database.selector}
     * @param ways its ways, newest first
     * @throws IllegalArgumentException if a way with an older way after it
     *                                  has no design (see {@link Choice#requireDesigns})
     */
    @SafeVarargs
    public static <T> Capability<T> of(String id, Choice.Way<? extends T>... ways) {
        List<Choice.Way<? extends T>> list = new ArrayList<>();
        for (Choice.Way<? extends T> way : ways) {
            list.add(way);
        }
        Choice.requireDesigns(list);
        return new Capability<>(id, list);
    }

    public String id() {
        return id;
    }

    /**
     * @return its ways, newest first
     */
    public List<Choice.Way<? extends T>> ways() {
        return ways;
    }

    /**
     * @return how this upstream supports the capability
     */
    public Choice<T> probe(Upstream upstream) {
        return Choice.first(upstream, id, ways);
    }

    @Override
    public String toString() {
        return id;
    }
}
