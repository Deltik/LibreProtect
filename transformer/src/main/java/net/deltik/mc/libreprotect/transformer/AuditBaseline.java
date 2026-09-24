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
    /** SHA-256 of upstream's LICENSE file */
    String licenseSha256;
}
