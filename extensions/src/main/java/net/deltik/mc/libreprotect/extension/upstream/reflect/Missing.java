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

/**
 * Upstream lacks something that a way of using it needs, such as
 * "CoreProtect has no Consumer.lockDatabaseReload(long)". The message says
 * exactly what, in plain words, for the capability report and the console.
 *
 * <p>Probing a way throws this; {@link Choice} then tries the next way. Most
 * of these mean the capability can't be used: upstream has the feature, but
 * not the way LibreProtect knows. An {@linkplain #absentFeature() absent
 * feature} means upstream doesn't have the feature at all, so nothing is
 * missing that LibreProtect could have used.
 */
public final class Missing extends Exception {

    private static final long serialVersionUID = 1L;

    private final boolean absentFeature;
    private final boolean newerDesign;

    public Missing(String message) {
        this(message, false, false);
    }

    private Missing(String message, boolean absentFeature, boolean newerDesign) {
        // Probing throws these to try the next way, where a stack trace would only cost time
        super(message, null, false, false);
        this.absentFeature = absentFeature;
        this.newerDesign = newerDesign;
    }

    /**
     * @return a {@link Missing} saying that upstream doesn't have the feature
     *         at all, such as DuckDB on CoreProtect 24
     */
    public static Missing absentFeature(String message) {
        return new Missing(message, true, false);
    }

    /**
     * @return a {@link Missing} refusing an older way because upstream shows
     *         signs of the newer design that replaced it
     */
    static Missing newerDesign(String message) {
        return new Missing(message, false, true);
    }

    /**
     * @return whether upstream doesn't have the feature at all, which is
     *         expected, rather than having it in a way LibreProtect can't use
     */
    public boolean absentFeature() {
        return absentFeature;
    }

    boolean newerDesign() {
        return newerDesign;
    }

    /**
     * @param member a member as the capability report writes it, such as
     *               {@code net/coreprotect/consumer/Consumer#lockDatabaseReload(J)Z},
     *               a field such as {@code owner#name:Z}, or a class
     * @return the member as messages write it, such as
     *         {@code Consumer.lockDatabaseReload(long)}, or
     *         {@code constructor ClickHouseJdbc(ClickHouseJdbcConfig)}
     */
    public static String readable(String member) {
        int hash = member.indexOf('#');
        if (hash < 0) {
            return Descriptors.simpleName(member);
        }
        String name = readableName(member);
        int parenthesis = member.indexOf('(', hash);
        return parenthesis < 0 ? name : name + Descriptors.readableParameters(member.substring(parenthesis));
    }

    /**
     * @param trace a class, or a member of one by name, as for {@link Upstream#has}
     * @return it as messages write it, such as {@code class DuckDBDatabase}
     *         or {@code Consumer.claimBackgroundPurge}
     */
    static String readableTrace(String trace) {
        int hash = trace.indexOf('#');
        return hash < 0 ? "class " + Descriptors.simpleName(trace)
            : Descriptors.simpleName(trace.substring(0, hash)) + "." + trace.substring(hash + 1);
    }

    /**
     * @return a member's class and name as messages write them, without the
     *         parameters, such as {@code Consumer.lockDatabaseReload}, or
     *         {@code constructor ClickHouseJdbc}; a class's simple name
     */
    public static String readableName(String member) {
        int hash = member.indexOf('#');
        if (hash < 0) {
            return Descriptors.simpleName(member);
        }
        String name = member.substring(hash + 1);
        int end = name.length();
        for (char delimiter : new char[]{'(', ':'}) {
            int at = name.indexOf(delimiter);
            if (at >= 0 && at < end) {
                end = at;
            }
        }
        String owner = Descriptors.simpleName(member.substring(0, hash));
        String simple = name.substring(0, end);
        return simple.equals("<init>") ? "constructor " + owner : owner + "." + simple;
    }
}
