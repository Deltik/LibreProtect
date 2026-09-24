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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Everything the transformer changed, written out as {@code transform-report.json}
 * and summarized in {@code DIFFERENCES.md}.
 */
final class TransformReport {

    record EgressSite(String entry, String className, String method, String api, String kind, Origin origin) {
    }

    record EditionGate(String entry, String className, String method, boolean value) {
    }

    /**
     * @param version the version that CoreProtect's method reads instead of plugin.yml's
     */
    record PluginVersionRead(String entry, String className, String method, String version) {
    }

    record ValueChange(String before, String after) {
    }

    /**
     * @param className a class that LibreProtect provides for upstream to load by name
     * @param requestedBy upstream's classes that load it
     */
    record ExtensionPoint(String className, List<String> requestedBy) {
    }

    /**
     * @param member the method or field
     * @param kind one of {@link BrandingRewriter}'s {@code KIND_} values
     * @param before the original text, or what was hooked
     * @param after the rebranded text, for text changes
     */
    record BrandingSite(String entry, String className, String member, String kind, String before, String after) {
    }

    String upstreamRef;
    String upstreamCommit;
    String upstreamVersion;
    String forkVersion;
    String forkCommit;

    String upstreamMainClass;
    String generatedMainClass;

    int upstreamClassCount;
    int libraryClassCount;
    int exemptLibraryClassCount;
    List<String> exemptPrefixes = new ArrayList<>();

    final List<EgressSite> egressSites = new ArrayList<>();
    final List<EditionGate> editionGates = new ArrayList<>();
    /** Where CoreProtect reads its own version, which now reads upstream's */
    final List<PluginVersionRead> pluginVersionReads = new ArrayList<>();
    final List<String> phraseRenderers = new ArrayList<>();
    final List<BrandingSite> brandingSites = new ArrayList<>();
    final Map<String, ValueChange> pluginYmlChanges = new LinkedHashMap<>();
    final List<String> injectedEntries = new ArrayList<>();
    final List<ExtensionPoint> extensionPoints = new ArrayList<>();
    /** LibreProtect extension classes or methods that upstream no longer asks for; the audit reports these */
    final List<String> unrequestedExtensions = new ArrayList<>();

    long countBranding(String kind) {
        return brandingSites.stream().filter(site -> site.kind().equals(kind)).count();
    }
}
