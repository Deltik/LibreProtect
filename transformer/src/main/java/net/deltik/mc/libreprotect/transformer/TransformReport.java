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

    /**
     * @param language the language code, as CoreProtect's {@code language} setting names it
     * @param phrases  how many of upstream's phrases it translates
     * @param missing  upstream's phrases that it doesn't translate, which stay in English
     * @param unknown  its keys that aren't upstream's phrases, which are never used
     */
    record Translation(String language, int phrases, List<String> missing, List<String> unknown) {
    }

    /**
     * How the extensions do one thing with this upstream JAR, as the
     * extensions' build found by probing it.
     *
     * @param id          what the extensions do, such as {@code consumer.gate}
     * @param value       the strategy they use, or {@value CapabilityReport#ABSENT} or
     *                    {@value CapabilityReport#UNAVAILABLE}
     * @param description what the strategy does, if there is one
     * @param reason      why there is none, otherwise
     * @param members     upstream classes, methods and fields that the strategy looks up by name
     * @param optionals   upstream members that the strategy uses if they exist
     * @param relies      upstream methods whose behavior the strategy relies on
     * @param enums       upstream enums whose constants the strategy uses
     * @param docs        upstream documentation that the strategy follows
     * @param rejected    other strategies, and why the extensions don't use them with this upstream
     */
    record Capability(String id, String value, String description, String reason, List<String> members,
                      List<OptionalMember> optionals, List<Reliance> relies, List<EnumConstants> enums,
                      List<Doc> docs, List<Rejected> rejected) {

        boolean available() {
            return !value.equals(CapabilityReport.ABSENT) && !value.equals(CapabilityReport.UNAVAILABLE);
        }

        /**
         * @return the description, or the reason if there is none
         */
        String text() {
            return description != null ? description : reason;
        }
    }

    /**
     * @param state {@value CapabilityReport#PRESENT} or {@value CapabilityReport#ABSENT}
     */
    record OptionalMember(String member, String state) {
    }

    /**
     * @param member      the method, as {@code owner#name(descriptor)}
     * @param why         what the extensions rely on, which probing can't prove
     * @param fingerprint the method's {@link CodeFingerprint}, or {@value CodeFingerprint#ABSENT}
     */
    record Reliance(String member, String why, String fingerprint) {
    }

    record EnumConstants(String owner, List<String> constants) {
    }

    /**
     * @param path a file in upstream's source tree
     * @param what what it documents
     * @param hash the start of its SHA-256, or {@value CapabilityReport#ABSENT} if upstream's source tree doesn't
     *             have it
     */
    record Doc(String path, String what, String hash) {
    }

    record Rejected(String strategy, String why) {
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
    /** How the extensions work with this upstream JAR, from the capability report of their build */
    final List<Capability> capabilities = new ArrayList<>();
    /** How many distinct upstream members the extensions find by name for the capabilities they use */
    int upstreamMemberCount;
    /** How many phrases upstream has */
    int phraseCount;
    /** Upstream's translations that LibreProtect bundles, by language code */
    final List<Translation> translations = new ArrayList<>();
    /** Upstream's phrases with no built-in English found in its code, which are never translated */
    final List<String> phrasesWithoutDefault = new ArrayList<>();
    /** Phrases whose text in upstream's en.yml differs from its code's built-in English, which is what counts */
    final List<String> englishDifferences = new ArrayList<>();

    long countBranding(String kind) {
        return brandingSites.stream().filter(site -> site.kind().equals(kind)).count();
    }
}
