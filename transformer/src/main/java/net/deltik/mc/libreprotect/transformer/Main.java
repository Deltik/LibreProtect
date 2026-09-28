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

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Command-line entry point, run by {@code scripts/lp build}.
 *
 * <p>Exit status: 0 on success (check {@code audit-report.json} for
 * {@code reviewRequired}), 2 if upstream broke a contract or failed the audit
 * (no JAR is written), 1 on any other error.
 */
public final class Main {

    private static final List<String> REQUIRED = List.of(
        "upstream-jar", "original-jar", "runtime-jar", "translations", "upstream-dir", "baseline", "output", "version",
        "upstream-ref", "upstream-commit", "fork-commit", "timestamp", "report", "differences", "audit-report",
        "observed");
    private static final List<String> OPTIONAL = List.of("extensions-jar", "capabilities", "description", "website");

    private Main() {
    }

    public static void main(String[] args) {
        try {
            Map<String, List<String>> arguments = parse(args);
            for (String required : REQUIRED) {
                if (!arguments.containsKey(required)) {
                    throw new IllegalArgumentException("Missing --" + required);
                }
            }
            for (String name : arguments.keySet()) {
                if (!REQUIRED.contains(name) && !OPTIONAL.contains(name)) {
                    throw new IllegalArgumentException("Unknown option --" + name);
                }
            }

            Path baselineFile = Path.of(single(arguments, "baseline"));
            AuditBaseline baseline = Files.exists(baselineFile)
                ? Reports.fromJson(Files.readString(baselineFile, StandardCharsets.UTF_8), AuditBaseline.class)
                : new AuditBaseline();

            Transformer.Options options = new Transformer.Options(
                Path.of(single(arguments, "upstream-jar")),
                Path.of(single(arguments, "original-jar")),
                Path.of(single(arguments, "runtime-jar")),
                arguments.containsKey("extensions-jar") ? Path.of(single(arguments, "extensions-jar")) : null,
                arguments.containsKey("capabilities") ? Path.of(single(arguments, "capabilities")) : null,
                Path.of(single(arguments, "upstream-dir")),
                Path.of(single(arguments, "translations")),
                Path.of(single(arguments, "output")),
                single(arguments, "version"),
                arguments.containsKey("description") ? single(arguments, "description") : null,
                arguments.containsKey("website") ? single(arguments, "website") : "https://github.com/Deltik/LibreProtect",
                single(arguments, "upstream-ref"),
                single(arguments, "upstream-commit"),
                single(arguments, "fork-commit"),
                Long.parseLong(single(arguments, "timestamp")),
                List.copyOf(baseline.egressExemptPrefixes));

            Transformer transformer = new Transformer(options);
            TransformReport report = transformer.run();
            Files.writeString(Path.of(single(arguments, "report")), Reports.toJson(report), StandardCharsets.UTF_8);
            Files.writeString(Path.of(single(arguments, "differences")), Differences.render(report), StandardCharsets.UTF_8);

            AuditReport audit = new Audit(transformer.upstream(), transformer.origins(), report,
                Path.of(single(arguments, "upstream-dir")), baseline).run();
            Files.writeString(Path.of(single(arguments, "audit-report")), Reports.toJson(audit), StandardCharsets.UTF_8);
            Files.writeString(Path.of(single(arguments, "observed")), Reports.toJson(audit.observed), StandardCharsets.UTF_8);

            System.out.println("Transformed CoreProtect " + report.upstreamRef + " into LibreProtect " + options.version());
            System.out.println("  " + report.egressSites.size() + " network call sites redirected through Egress");
            System.out.println("  " + report.editionGates.size() + " donation-key checks unlocked");
            System.out.println("  CoreProtect compares its own version as " + report.upstreamVersion
                + ", as upstream's build declared it");
            System.out.println("  " + report.countBranding(BrandingRewriter.KIND_TEXT) + " texts rebranded, "
                + report.countBranding(BrandingRewriter.KIND_PHRASE) + " phrase renderings and "
                + report.countBranding(BrandingRewriter.KIND_OUTPUT) + " message outputs hooked");
            System.out.println("  " + report.translations.size() + " translations bundled: " + report.translations.stream()
                .map(TransformReport.Translation::language).collect(Collectors.joining(", ")) + "; built-in English "
                + "for " + (report.phraseCount - report.phrasesWithoutDefault.size()) + " of " + report.phraseCount
                + " phrases" + (report.englishDifferences.isEmpty() ? ""
                : ", which en.yml differs from for " + String.join(", ", report.englishDifferences)));
            System.out.println("  main class " + report.upstreamMainClass + " -> " + report.generatedMainClass);
            System.out.println("  " + capabilitySummary(report));
            System.out.println("  " + report.upstreamClassCount + " upstream classes, "
                + report.libraryClassCount + " bundled library classes, "
                + report.exemptLibraryClassCount + " exempt library classes");
            printAudit(audit);

            if (audit.failed) {
                System.err.println("AUDIT FAILED: upstream uses APIs that LibreProtect can't make private, "
                    + "or changed its license. No JAR written.");
                System.exit(2);
            }
            transformer.write(audit);
            System.out.println("Wrote " + options.outputJar());
            if (audit.reviewRequired) {
                System.out.println("REVIEW REQUIRED before release: compare " + single(arguments, "observed")
                    + " with " + baselineFile + " and update the baseline in a reviewed pull request.");
            }
        } catch (ContractViolation e) {
            System.err.println("CONTRACT VIOLATION: " + e.getMessage());
            System.exit(2);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static final int DETAIL_LIMIT = 25;

    /**
     * @return how the extensions work with this upstream, such as "extension
     *         capabilities: 12 available, 3 absent, 1 unavailable; 40 upstream
     *         members found by name; 5 upstream methods fingerprinted"
     */
    private static String capabilitySummary(TransformReport report) {
        if (report.capabilities.isEmpty()) {
            return "no extension capabilities";
        }
        long available = report.capabilities.stream().filter(TransformReport.Capability::available).count();
        long absent = report.capabilities.stream()
            .filter(capability -> capability.value().equals(CapabilityReport.ABSENT)).count();
        long fingerprinted = report.capabilities.stream().flatMap(capability -> capability.relies().stream())
            .map(TransformReport.Reliance::member).distinct().count();
        return "extension capabilities: " + available + " available, " + absent + " absent, "
            + (report.capabilities.size() - available - absent) + " unavailable; "
            + count(report.upstreamMemberCount, "upstream member") + " found by name; "
            + count(fingerprinted, "upstream method") + " fingerprinted";
    }

    private static String count(long count, String noun) {
        return count + " " + noun + (count == 1 ? "" : "s");
    }

    /**
     * Print counts per rule and package, then the first findings in detail.
     * The full list is in the audit report.
     */
    private static void printAudit(AuditReport audit) {
        System.out.println("Audit: " + audit.count(AuditReport.Severity.FAIL) + " fail, "
            + audit.count(AuditReport.Severity.REVIEW) + " review, "
            + audit.count(AuditReport.Severity.INFO) + " info");

        Map<String, Integer> groups = new TreeMap<>();
        for (AuditReport.Finding finding : audit.findings) {
            if (finding.severity() != AuditReport.Severity.INFO) {
                groups.merge(finding.severity() + " " + finding.rule() + " in " + group(finding.site()), 1, Integer::sum);
            }
        }
        groups.forEach((group, count) -> System.out.println("  " + count + " x " + group));

        int shown = 0;
        for (AuditReport.Severity severity : List.of(AuditReport.Severity.FAIL, AuditReport.Severity.REVIEW)) {
            for (AuditReport.Finding finding : audit.findings) {
                if (finding.severity() == severity && shown++ < DETAIL_LIMIT) {
                    System.out.println("  " + finding.severity() + " " + finding.rule() + " at " + finding.site()
                        + ": " + finding.detail());
                }
            }
        }
        if (shown > DETAIL_LIMIT) {
            System.out.println("  ... and " + (shown - DETAIL_LIMIT) + " more in the audit report");
        }
    }

    /**
     * @return a class's top three package segments, the kind of a capability
     *         key, or an inventory item as is
     */
    private static String group(String site) {
        if (site.contains(" ")) {
            return site.substring(0, site.indexOf(' '));
        }
        int hash = site.indexOf('#');
        String className = hash < 0 ? site : site.substring(0, hash);
        if (!className.contains("/") || className.contains(":")) {
            return site;
        }
        String[] segments = className.split("/");
        return String.join("/", Arrays.copyOfRange(segments, 0, Math.min(3, segments.length - 1))) + "/**";
    }

    private static Map<String, List<String>> parse(String[] args) {
        Map<String, List<String>> arguments = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            if (!args[i].startsWith("--") || i + 1 >= args.length) {
                throw new IllegalArgumentException("Expected --name value, got: " + args[i]);
            }
            arguments.computeIfAbsent(args[i].substring(2), key -> new ArrayList<>()).add(args[++i]);
        }
        return arguments;
    }

    private static String single(Map<String, List<String>> arguments, String name) {
        List<String> values = arguments.get(name);
        if (values.size() != 1) {
            throw new IllegalArgumentException("--" + name + " given " + values.size() + " times");
        }
        return values.get(0);
    }
}
