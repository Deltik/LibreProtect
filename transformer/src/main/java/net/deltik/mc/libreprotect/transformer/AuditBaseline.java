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

package net.deltik.mc.libreprotect.transformer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Function;

/**
 * The reviewed state of upstream, checked in as {@code audit/baseline.json}.
 *
 * <p>The audit compares what it observes against this baseline. Anything new
 * needs a maintainer's review. The baseline keeps the reviewed state of each
 * upstream line that LibreProtect builds, such as the release that
 * {@code upstream.lock} pins and upstream's default branch, and accepts what
 * any of them has. Accepting a reviewed build replaces its line's state with
 * what the build observed ({@code audit-observed.json}), which
 * {@code scripts/lp accept} does.
 */
final class AuditBaseline {

    /** A reviewed exception to a FAIL or REVIEW rule at one call site. */
    static final class Allowance {
        String rule;
        String site;
        String reason;

        Allowance() {
        }

        Allowance(String rule, String site, String reason) {
            this.rule = rule;
            this.site = site;
            this.reason = reason;
        }
    }

    /** Which upstream build a line's state was observed in */
    static final class Upstream {
        /** The upstream ref that was built, such as a tag, a branch or a commit */
        String ref;
        /** The upstream commit that was built */
        String commit;
        /**
         * SHA-256 of the upstream JAR, as the capability report's
         * {@code upstream sha256} line gives it. The extensions' unit tests
         * expect the exact ways of the JARs that the baseline's lines name.
         * Not audited: an upstream that no line names only skips those
         * tests, so a bump to a new release needs no review for it.
         */
        String jarSha256;
    }

    /**
     * What the audit observed in one upstream build, written as
     * {@code audit-observed.json}; in the baseline, the reviewed state of an
     * upstream line: what the audit observed in the build of it that a
     * maintainer last accepted.
     */
    static final class Line {
        Upstream upstream = new Upstream();
        /** Hosts in URL-like string constants in upstream-authored code */
        TreeSet<String> hosts = new TreeSet<>();
        /** Classes that upstream loads by name from its closed-source extensions package */
        TreeSet<String> extensionPoints = new TreeSet<>();
        /** Packages of classes that upstream's build shades in from libraries */
        TreeSet<String> libraryPackages = new TreeSet<>();
        /** groupId:artifactId:scope of upstream's Maven dependencies */
        TreeSet<String> dependencies = new TreeSet<>();
        /** Maven repository URLs in upstream's pom */
        TreeSet<String> repositories = new TreeSet<>();
        /** groupId:artifactId of upstream's Maven build plugins */
        TreeSet<String> buildPlugins = new TreeSet<>();
        /** ids of upstream's Maven profiles */
        TreeSet<String> profiles = new TreeSet<>();
        /** Libraries that plugin.yml asks the server to download */
        TreeSet<String> pluginLibraries = new TreeSet<>();
        /**
         * Upstream methods, as {@code owner#name(descriptor)}, that read a
         * plugin's version or full name ({@code getVersion}, {@code getFullName}
         * or {@code getDisplayName} of {@code PluginDescriptionFile} or
         * {@code PluginMeta}), or that have a string constant naming
         * {@code plugin.yml}, as code that reads it itself does. CoreProtect
         * compares its own version with others in
         * {@code VersionUtils.getPluginVersion()}, which the transformer has read
         * upstream's version; the others only show it, read another plugin's, or
         * read another key.
         */
        TreeSet<String> versionReads = new TreeSet<>();
        /**
         * How the extensions work with upstream, from the capability report,
         * as {@code key=value} lines:
         * {@code capability <id>=<strategy|absent|unavailable>}, and under the
         * capability's way, {@code optional <id>/<way> <member>=<present|absent>},
         * {@code code <id>/<way> <owner#name(descriptor)>=<fingerprint|absent>},
         * {@code enum <id>/<way> <owner>=<constants>} and
         * {@code doc <id>/<way> <path>=<hash|absent>}. The baseline accepts a
         * key with the value of any line.
         *
         * <p>An {@link #allow} entry for the {@code capability-change} rule names
         * the whole {@code key=value} that it accepts as its site, so that it
         * doesn't accept later changes to the key. A capability that is no longer
         * reported has an empty value.
         */
        TreeSet<String> capabilities = new TreeSet<>();
        /**
         * Upstream's licensing, as {@code key=value} lines:
         * {@code file <path>=<sha256>} for each license-like file in
         * upstream's source tree, such as {@code LICENSE}, {@code COPYING.md},
         * {@code THIRD_PARTY_NOTICES.txt} or a file in a {@code LICENSES/}
         * directory (a symbolic link gives where it points, and the SHA-256 of
         * that file); {@code pom licenses=} the fields of each license that
         * upstream's pom declares, joined by {@code "; "}, or {@code absent}; and
         * {@code header=<sha256>} for each distinct header of upstream's Java
         * files, as {@link Audit#header} reads it. The baseline accepts a key
         * with the value of any line.
         *
         * <p>Any observed {@code key=value} that isn't accepted fails the build,
         * a development build too, since LibreProtect may no longer be allowed
         * to distribute it. An {@link #allow} entry for the
         * {@code license-change} rule names the whole {@code key=value} that it
         * accepts as its site.
         */
        TreeSet<String> licenses = new TreeSet<>();
    }

    List<String> comment = new ArrayList<>();
    List<Allowance> allow = new ArrayList<>();

    /**
     * Internal-name prefixes of bundled libraries whose network calls are
     * deliberately NOT routed through Egress, such as database drivers that
     * must reach the server's configured database.
     */
    TreeSet<String> egressExemptPrefixes = new TreeSet<>();

    /** The reviewed state of each upstream line, by name, such as {@code release} and {@code development} */
    TreeMap<String, Line> lines = new TreeMap<>();

    /**
     * @return what any line accepts of what one field of a line holds
     */
    Set<String> accepted(Function<Line, Set<String>> field) {
        Set<String> accepted = new TreeSet<>();
        for (Line line : lines.values()) {
            Set<String> values = line == null ? null : field.apply(line);
            if (values != null) {
                accepted.addAll(values);
            }
        }
        return accepted;
    }

    /**
     * A field of {@code key=value} lines is accepted entry by entry, whole,
     * since a key may have an {@code =} of its own, as a license file's path
     * may, and so may a value, as a URL in a pom's license may.
     *
     * @return the values that the lines have for a key of such a field, each
     *         with the names of the lines that have it, to tell a reviewer
     *         what the key was: the rest of each entry that starts with the
     *         key and {@code =}
     */
    Map<String, List<String>> acceptedValues(Function<Line, Set<String>> field, String key) {
        String prefix = key + "=";
        Map<String, List<String>> values = new TreeMap<>();
        lines.forEach((name, line) -> {
            Set<String> entries = line == null ? null : field.apply(line);
            for (String entry : entries == null ? Set.<String>of() : entries) {
                if (entry.startsWith(prefix)) {
                    values.computeIfAbsent(entry.substring(prefix.length()), value -> new ArrayList<>()).add(name);
                }
            }
        });
        return values;
    }
}
