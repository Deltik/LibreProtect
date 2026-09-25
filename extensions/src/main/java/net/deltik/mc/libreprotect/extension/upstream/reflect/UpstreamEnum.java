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

import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * An upstream enum, by the names of its constants. The names come from its
 * class file, in declaration order, without initializing it; looking up a
 * constant initializes the enum, and only the enum.
 */
public final class UpstreamEnum {

    private final String upstream;
    private final String upstreamName;
    private final Class<?> type;
    private final List<String> names;

    /**
     * @param upstream upstream's name, for messages
     */
    UpstreamEnum(String upstream, String upstreamName, Class<?> type, List<String> names) {
        this.upstream = upstream;
        this.upstreamName = upstreamName;
        this.type = type;
        this.names = Collections.unmodifiableList(names);
    }

    /**
     * @return upstream's binary name of the enum
     */
    public String name() {
        return upstreamName;
    }

    /**
     * @return the enum's class, or its stand-in in tests
     */
    public Class<?> type() {
        return type;
    }

    /**
     * @return the names of the constants, in declaration order
     */
    public List<String> names() {
        return names;
    }

    public boolean has(String constant) {
        return names.contains(constant);
    }

    /**
     * Check that the enum has these constants, which a way refers to by name.
     */
    public void require(String... constants) throws Missing {
        for (String constant : constants) {
            if (!has(constant)) {
                throw new Missing(upstream + "'s " + Descriptors.simpleName(upstreamName) + " has no " + constant);
            }
        }
    }

    /**
     * @return the constant with this name
     * @throws IllegalArgumentException if the enum has none
     */
    public Enum<?> constant(String constant) {
        return find(constant).orElseThrow(() -> new IllegalArgumentException(
            Descriptors.simpleName(upstreamName) + " has no constant " + constant));
    }

    /**
     * @return the constant with this name, or empty if the enum has none
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    public Optional<Enum<?>> find(String constant) {
        if (!has(constant)) {
            return Optional.empty();
        }
        return Optional.of(Enum.valueOf((Class) type, constant));
    }

    @Override
    public String toString() {
        return Descriptors.simpleName(upstreamName) + names;
    }
}
