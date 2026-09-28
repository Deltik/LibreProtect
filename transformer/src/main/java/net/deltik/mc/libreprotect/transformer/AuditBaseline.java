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
import java.util.TreeSet;

/**
 * The reviewed state of upstream, checked in as {@code audit/baseline.json}.
 *
 * <p>The audit compares what it observes against this baseline. Anything new
 * needs a maintainer's review. Accepting a change means copying the observed
 * values (from {@code audit-observed.json}) into this file in a reviewed pull
 * request.
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

    List<String> comment = new ArrayList<>();
    List<Allowance> allow = new ArrayList<>();

    /**
     * Internal-name prefixes of bundled libraries whose network calls are
     * deliberately NOT routed through Egress, such as database drivers that
     * must reach the server's configured database.
     */
    TreeSet<String> egressExemptPrefixes = new TreeSet<>();

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
     * How the extensions may work with upstream, from the capability report,
     * as the {@code key=value} lines accepted after review:
     * {@code capability <id>=<strategy|absent|unavailable>}, and under the
     * capability's way, {@code optional <id>/<way> <member>=<present|absent>},
     * {@code code <id>/<way> <owner#name(descriptor)>=<fingerprint|absent>},
     * {@code enum <id>/<way> <owner>=<constants>} and
     * {@code doc <id>/<way> <path>=<hash|absent>}. A key may be accepted with
     * several values, one for each upstream line that LibreProtect builds. In
     * {@code audit-observed.json}, it's what one build observed.
     *
     * <p>An {@link #allow} entry for the {@code capability-change} rule names
     * the whole {@code key=value} that it accepts as its site, so that it
     * doesn't accept later changes to the key. A capability that is no longer
     * reported has an empty value.
     */
    TreeSet<String> capabilities = new TreeSet<>();
    /**
     * Upstream's licensing, as the {@code key=value} lines accepted after
     * review: {@code file <path>=<sha256>} for each license-like file in
     * upstream's source tree, such as {@code LICENSE}, {@code COPYING.md},
     * {@code THIRD_PARTY_NOTICES.txt} or a file in a {@code LICENSES/}
     * directory (a symbolic link gives where it points, and the SHA-256 of
     * that file); {@code pom licenses=} the fields of each license that
     * upstream's pom declares, joined by {@code "; "}, or {@code absent}; and
     * {@code header=<sha256>} for each distinct header of upstream's Java
     * files, as {@link Audit#header} reads it. A key may be accepted with
     * several values, one for each upstream line that LibreProtect builds. In
     * {@code audit-observed.json}, it's what one build observed.
     *
     * <p>Any observed {@code key=value} that isn't listed fails the build, a
     * development build too, since LibreProtect may no longer be allowed to
     * distribute it. An {@link #allow} entry for the {@code license-change}
     * rule names the whole {@code key=value} that it accepts as its site.
     */
    TreeSet<String> licenses = new TreeSet<>();
    /**
     * SHA-256 of the upstream JARs whose ways the extensions' unit tests
     * expect exactly, as their capability report's {@code upstream sha256}
     * line gives it. Not audited: an upstream that isn't listed only skips
     * those tests, so a bump to a new release needs no review for it.
     */
    TreeSet<String> reviewedUpstreams = new TreeSet<>();
}
