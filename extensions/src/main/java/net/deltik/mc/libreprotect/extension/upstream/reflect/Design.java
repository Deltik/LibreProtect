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

package net.deltik.mc.libreprotect.extension.upstream.reflect;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A design of upstream's that replaced older ways of doing things, known by
 * many independent traces from different parts of upstream: any one of them
 * shows that upstream has the design, even when others were renamed or
 * removed. So no single rename makes a newer upstream look old.
 *
 * <p>A way declared with a design keeps every older way after it from
 * being taken while upstream has any trace of the design (see
 * {@link Choice}). Members that the design brought are required while
 * upstream has it and absent before (see
 * {@link UpstreamClass#staticMethodSince}).
 */
public final class Design {

    private final String name;
    private final List<String> traces;

    private Design(String name, List<String> traces) {
        this.name = Objects.requireNonNull(name, "name");
        this.traces = Collections.unmodifiableList(traces);
    }

    /**
     * @param name what messages call it, such as "multi-engine database layer"
     * @param traces classes or members, as for {@link Upstream#has}, that
     *               only an upstream with the design has
     */
    public static Design of(String name, String... traces) {
        if (traces.length == 0) {
            throw new IllegalArgumentException("A design needs traces");
        }
        return new Design(name, Arrays.asList(traces.clone()));
    }

    public String name() {
        return name;
    }

    public List<String> traces() {
        return traces;
    }

    /**
     * @return a trace of the design that upstream has, or empty if it has none
     */
    public Optional<String> traceIn(Upstream upstream) {
        for (String trace : traces) {
            if (upstream.has(trace)) {
                return Optional.of(trace);
            }
        }
        return Optional.empty();
    }

    public boolean isIn(Upstream upstream) {
        return traceIn(upstream).isPresent();
    }

    /**
     * @throws Missing an {@linkplain Missing#absentFeature() absent feature}
     *                 if upstream has no trace of the design, for
     *                 capabilities that only the design has
     */
    public void requireIn(Upstream upstream) throws Missing {
        if (!isIn(upstream)) {
            throw Missing.absentFeature(upstream.name() + " has no " + name);
        }
    }

    /**
     * @return how upstream shows that it has the design, for messages, such
     *         as "CoreProtect has class DuckDBDatabase, part of its ...", or
     *         empty if it has no trace of it
     */
    public Optional<String> evidenceIn(Upstream upstream) {
        return traceIn(upstream).map(trace -> upstream.name() + " has " + Missing.readableTrace(trace)
            + ", part of its " + name);
    }

    @Override
    public String toString() {
        return name;
    }
}
