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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Reads {@code capabilities.tsv}, which the extensions' build writes after
 * probing every capability against the exact upstream JAR that LibreProtect
 * bundles: how the extensions do each thing with this upstream, the members
 * they find by name, and what they rely on that probing can't prove.
 *
 * <p>Each line is a record of tab-separated fields. The {@code upstream} line
 * comes first; the others are sorted by their UTF-8 bytes:
 *
 * <pre>
 * upstream   sha256 &lt;SHA-256 of the probed JAR&gt;
 * capability &lt;id&gt; &lt;strategy|absent|unavailable&gt; &lt;description, or reason&gt;
 * member     &lt;id&gt; &lt;owner#name(descriptor)|owner#name:descriptor|owner&gt;
 * optional   &lt;id&gt; &lt;member&gt; &lt;present|absent&gt;
 * relies     &lt;id&gt; &lt;owner#name(descriptor)&gt; &lt;why&gt;
 * enum       &lt;id&gt; &lt;owner&gt; &lt;CONSTANT,CONSTANT,...&gt;
 * doc        &lt;id&gt; &lt;path in upstream's source tree&gt; &lt;what it documents&gt;
 * rejected   &lt;id&gt; &lt;strategy&gt; &lt;why&gt;
 * </pre>
 *
 * <p>Anything else breaks the contract, so that a change of format can't
 * quietly go unaudited. So does a report that disagrees with the upstream
 * JAR: a member of an available capability, or an optional member said to be
 * present, that the JAR doesn't have; an optional member said to be absent
 * that it has; or enum constants other than the JAR's.
 */
final class CapabilityReport {

    static final String ENTRY = Transformer.REPORT_DIRECTORY + "capabilities.tsv";
    static final String ABSENT = "absent";
    static final String UNAVAILABLE = "unavailable";
    static final String PRESENT = "present";
    /** How the audit's key of a capability's way starts, followed by its ID */
    static final String CAPABILITY_KEY = "capability ";

    private static final Map<String, Integer> FIELDS = Map.of(
        "capability", 4, "member", 3, "optional", 4, "relies", 4, "enum", 4, "doc", 4, "rejected", 4);

    /** Capability IDs and strategies */
    private static final Pattern NAME = Pattern.compile("[a-z0-9][a-z0-9.-]*");
    private static final String IDENTIFIER = "[A-Za-z_$][A-Za-z0-9_$]*";
    /** An internal class name */
    private static final String CLASS = IDENTIFIER + "(?:/" + IDENTIFIER + ")*";
    private static final String FIELD_TYPE = "\\[*(?:[BCDFIJSZ]|L" + CLASS + ";)";
    private static final Pattern CLASS_NAME = Pattern.compile(CLASS);
    private static final Pattern METHOD = Pattern.compile(
        CLASS + "#(?:<init>|<clinit>|" + IDENTIFIER + ")\\((?:" + FIELD_TYPE + ")*\\)(?:" + FIELD_TYPE + "|V)");
    private static final Pattern FIELD = Pattern.compile(CLASS + "#" + IDENTIFIER + ":" + FIELD_TYPE);
    private static final Pattern CONSTANT = Pattern.compile(IDENTIFIER);
    private static final Pattern PATH_SEGMENT = Pattern.compile("[A-Za-z0-9_.-]+");
    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");

    /** The SHA-256 of the upstream JAR that the extensions' build probed */
    final String upstreamSha256;
    /** The capabilities, in the report's order */
    final List<TransformReport.Capability> capabilities;

    private CapabilityReport(String upstreamSha256, List<TransformReport.Capability> capabilities) {
        this.upstreamSha256 = upstreamSha256;
        this.capabilities = capabilities;
    }

    /**
     * @return the report's text
     * @throws ContractViolation if it isn't valid UTF-8
     */
    static String decode(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw new ContractViolation("The capability report isn't valid UTF-8");
        }
    }

    /**
     * @param upstream          the upstream JAR, which the report must agree with, and whose methods that the
     *                          extensions rely on are fingerprinted
     * @param upstreamDirectory upstream's source tree, whose documentation is hashed, or {@code null} if the
     *                          report names no documentation
     */
    static CapabilityReport read(String text, JarContents upstream, Path upstreamDirectory) throws IOException {
        List<String> lines = lines(text);
        String upstreamSha256 = probedSha256(text);

        Map<String, Builder> builders = new LinkedHashMap<>();
        List<String[]> details = new ArrayList<>();
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i);
            int number = i + 1;
            require(!line.isEmpty(), number, "it is empty");
            require(!line.equals("upstream") && !line.startsWith("upstream\t"), number,
                "only the first line may be the 'upstream' line");
            require(i == 1 || compareBytes(lines.get(i - 1), line) < 0, number,
                "the lines after the first must be sorted by their UTF-8 bytes, without duplicates");
            String[] fields = fields(line, number);
            Integer expected = FIELDS.get(fields[0]);
            require(expected != null, number, "unknown line type '" + fields[0] + "'. The transformer knows "
                + "upstream, " + String.join(", ", new TreeSet<>(FIELDS.keySet())) + "; teach it the new one");
            require(fields.length == expected, number, "a '" + fields[0] + "' line has " + expected
                + " fields, found " + fields.length);
            require(NAME.matcher(fields[1]).matches(), number, "capability ID '" + fields[1] + "' isn't made of "
                + "lowercase letters, digits, '.' and '-'");
            if (fields[0].equals("capability")) {
                require(NAME.matcher(fields[2]).matches(), number, "strategy '" + fields[2] + "' isn't made of "
                    + "lowercase letters, digits, '.' and '-'");
                require(builders.put(fields[1], new Builder(fields[1], fields[2], fields[3])) == null, number,
                    "capability " + fields[1] + " appears twice");
            } else {
                details.add(fields);
            }
        }

        UpstreamMembers members = new UpstreamMembers(upstream);
        for (String[] fields : details) {
            Builder builder = builders.get(fields[1]);
            ContractViolation.require(builder != null, "The capability report has a '" + fields[0] + "' line for "
                + fields[1] + ", but no 'capability' line for it");
            String where = "'" + fields[0] + "' line of " + fields[1];
            switch (fields[0]) {
                case "member" -> {
                    String member = member(fields[2], where);
                    agree(!builder.available() || members.find(member) != UpstreamMembers.Lookup.MISSING,
                        "says that " + fields[1] + " works with " + builder.value + ", which uses " + member
                            + ", but the upstream JAR doesn't have it");
                    builder.members.add(member);
                }
                case "optional" -> {
                    String member = member(fields[2], where);
                    ContractViolation.require(fields[3].equals(PRESENT) || fields[3].equals(ABSENT),
                        "The capability report's " + where + " says '" + fields[3] + "', expected " + PRESENT + " or "
                            + ABSENT);
                    UpstreamMembers.Lookup lookup = members.find(member);
                    agree(fields[3].equals(PRESENT) ? lookup != UpstreamMembers.Lookup.MISSING
                        : lookup != UpstreamMembers.Lookup.FOUND, "says that " + member + " is " + fields[3]
                        + ", but the upstream JAR " + (fields[3].equals(PRESENT) ? "doesn't have it" : "has it"));
                    builder.optionals.add(new TransformReport.OptionalMember(member, fields[3]));
                }
                case "relies" -> {
                    ContractViolation.require(METHOD.matcher(fields[2]).matches(), "The capability report's " + where
                        + " names '" + fields[2] + "', expected a method as owner#name(descriptor)");
                    builder.relies.add(new TransformReport.Reliance(fields[2], fields[3],
                        CodeFingerprint.of(upstream, fields[2])));
                }
                case "enum" -> {
                    ContractViolation.require(CLASS_NAME.matcher(fields[2]).matches(), "The capability report's "
                        + where + " names '" + fields[2] + "', expected a class's internal name");
                    List<String> constants = Arrays.asList(fields[3].split(",", -1));
                    ContractViolation.require(constants.stream().allMatch(constant ->
                        CONSTANT.matcher(constant).matches()), "The capability report's " + where
                        + " has constants '" + fields[3] + "', expected names separated by commas");
                    List<String> actual = members.enumConstants(fields[2]);
                    agree(constants.equals(actual), "lists the constants of " + fields[2] + " as " + fields[3]
                        + ", but the upstream JAR " + (actual == null ? "has no such enum"
                        : "has " + String.join(",", actual)));
                    builder.enums.add(new TransformReport.EnumConstants(fields[2], constants));
                }
                case "doc" -> {
                    String path = path(fields[2], where);
                    ContractViolation.require(upstreamDirectory != null, "The capability report names upstream's "
                        + path + ", but the transformer wasn't given upstream's source tree (--upstream-dir)");
                    builder.docs.add(new TransformReport.Doc(path, fields[3], docHash(upstreamDirectory, path)));
                }
                case "rejected" -> {
                    ContractViolation.require(NAME.matcher(fields[2]).matches(), "The capability report's " + where
                        + " names strategy '" + fields[2] + "', which isn't made of lowercase letters, digits, "
                        + "'.' and '-'");
                    builder.rejected.add(new TransformReport.Rejected(fields[2], fields[3]));
                }
                default -> throw new IllegalStateException(fields[0]);
            }
        }

        List<TransformReport.Capability> capabilities = builders.values().stream().map(Builder::build).toList();
        observations(capabilities); // Check that the keys the audit compares have one value each
        return new CapabilityReport(upstreamSha256, capabilities);
    }

    /**
     * @return the SHA-256 of the upstream JAR that the report's first line says was probed
     */
    static String probedSha256(String text) {
        String line = lines(text).get(0);
        require(!line.startsWith("﻿"), 1, "it starts with a byte order mark; write the report as UTF-8 "
            + "without one");
        String[] fields = fields(line, 1);
        require(fields.length == 3 && fields[0].equals("upstream") && fields[1].equals("sha256")
            && SHA256.matcher(fields[2]).matches(), 1, "expected 'upstream', 'sha256' and a lowercase hex SHA-256 "
            + "first, found " + line);
        return fields[2];
    }

    private static List<String> lines(String text) {
        List<String> lines = new ArrayList<>(Arrays.asList(text.split("\n", -1)));
        if (lines.get(lines.size() - 1).isEmpty()) {
            lines.remove(lines.size() - 1);
        }
        ContractViolation.require(!lines.isEmpty(), "The capability report is empty");
        return lines;
    }

    /**
     * @return how many distinct upstream classes, methods and fields the
     *         extensions find by name for the capabilities they use: the
     *         members of each available capability and its optional members
     *         that are present
     */
    static int memberCount(List<TransformReport.Capability> capabilities) {
        Set<String> members = new TreeSet<>();
        for (TransformReport.Capability capability : capabilities) {
            if (capability.available()) {
                members.addAll(capability.members());
                capability.optionals().stream().filter(optional -> optional.state().equals(PRESENT))
                    .forEach(optional -> members.add(optional.member()));
            }
        }
        return members.size();
    }

    /**
     * What the audit compares with the baseline for one key.
     *
     * @param value    the key's value
     * @param contexts which capabilities the key belongs to, and why they care, for a reviewer
     */
    record Observation(String value, List<String> contexts) {
    }

    /**
     * The audit's keys, in order: {@code capability <id>}, then what the
     * capability's way uses, under the way: {@code code <id>/<way> <method>},
     * {@code doc <id>/<way> <path>}, {@code enum <id>/<way> <owner>} and
     * {@code optional <id>/<way> <member>}, where {@code <way>} is the
     * capability's strategy, or {@code absent} or {@code unavailable}. What a
     * way relies on holds only with that way: CoreProtect 25's purge command
     * claims its purge, as the background-claims way needs, and CoreProtect
     * 24's sets purgeRunning, as the cooperative-flags way needs. So the
     * baseline accepts each fingerprint only with its way.
     *
     * @throws ContractViolation if the report gives a member, method, enum or
     *                           document two values, even under two ways
     */
    static Map<String, Observation> observations(List<TransformReport.Capability> capabilities) {
        Map<String, Observation> observations = new TreeMap<>();
        Map<String, String> values = new TreeMap<>();
        for (TransformReport.Capability capability : capabilities) {
            String id = capability.id();
            String way = id + "/" + capability.value();
            observe(observations, values, CAPABILITY_KEY + id, null, capability.value(), capability.text());
            for (TransformReport.OptionalMember optional : capability.optionals()) {
                observe(observations, values, "optional " + optional.member(), way, optional.state(), id
                    + " uses it if it exists: " + capability.text());
            }
            for (TransformReport.Reliance reliance : capability.relies()) {
                observe(observations, values, "code " + reliance.member(), way, reliance.fingerprint(), id
                    + " relies on it: " + reliance.why());
            }
            for (TransformReport.EnumConstants constants : capability.enums()) {
                observe(observations, values, "enum " + constants.owner(), way, String.join(",",
                    constants.constants()), id + " uses its constants: " + capability.text());
            }
            for (TransformReport.Doc doc : capability.docs()) {
                observe(observations, values, "doc " + doc.path(), way, doc.hash(), id + " follows it: "
                    + doc.what());
            }
        }
        return observations;
    }

    /**
     * @param subject what the value is of, such as {@code code <method>}
     * @param way     the capability and way whose key it is, or {@code null} for the capability's own key
     */
    private static void observe(Map<String, Observation> observations, Map<String, String> values, String subject,
                                String way, String value, String context) {
        String existingValue = values.putIfAbsent(subject, value);
        ContractViolation.require(existingValue == null || existingValue.equals(value), "The capability report "
            + "gives " + subject + " two values: " + existingValue + " and " + value);
        int space = subject.indexOf(' ');
        String key = way == null ? subject : subject.substring(0, space) + " " + way + subject.substring(space);
        Observation existing = observations.get(key);
        if (existing == null) {
            observations.put(key, new Observation(value, new ArrayList<>(List.of(context))));
        } else if (!existing.contexts().contains(context)) {
            existing.contexts().add(context);
        }
    }

    /**
     * @return the start of the file's SHA-256, or {@value #ABSENT} if it doesn't exist
     */
    private static String docHash(Path upstreamDirectory, String path) throws IOException {
        Path file = upstreamDirectory.resolve(path);
        if (!Files.isRegularFile(file)) {
            return ABSENT;
        }
        ContractViolation.require(file.toRealPath().startsWith(upstreamDirectory.toRealPath()),
            "Upstream's " + path + " leads outside its source tree");
        return sha256(Files.readAllBytes(file)).substring(0, CodeFingerprint.LENGTH);
    }

    static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String member(String member, String where) {
        ContractViolation.require(METHOD.matcher(member).matches() || FIELD.matcher(member).matches()
                || CLASS_NAME.matcher(member).matches(), "The capability report's " + where + " names '" + member
            + "', expected owner#name(descriptor), owner#name:descriptor or owner, with internal names");
        return member;
    }

    private static String path(String path, String where) {
        boolean relative = Arrays.stream(path.split("/", -1)).allMatch(segment ->
            PATH_SEGMENT.matcher(segment).matches() && !segment.equals(".") && !segment.equals(".."));
        ContractViolation.require(relative, "The capability report's " + where + " names '" + path
            + "', expected a relative path in upstream's source tree, such as docs/database-migration.md");
        return path;
    }

    private static String[] fields(String line, int number) {
        require(!line.contains("\r"), number, "it contains a carriage return; write the report with \\n line ends");
        require(line.chars().noneMatch(c -> c != '\t' && (c < 0x20 || c == 0x7F)), number,
            "it contains a control character");
        String[] fields = line.split("\t", -1);
        for (String field : fields) {
            require(!field.isEmpty(), number, "it has an empty field: " + line);
        }
        return fields;
    }

    private static int compareBytes(String first, String second) {
        return Arrays.compareUnsigned(first.getBytes(StandardCharsets.UTF_8), second.getBytes(StandardCharsets.UTF_8));
    }

    private static void require(boolean condition, int line, String problem) {
        ContractViolation.require(condition, "Line " + line + " of the capability report doesn't follow its "
            + "format: " + problem);
    }

    /**
     * Require the report to agree with the upstream JAR.
     */
    private static void agree(boolean condition, String disagreement) {
        ContractViolation.require(condition, "The capability report " + disagreement + ". The report, or the "
            + "probe in the extensions' build that wrote it, is wrong.");
    }

    private static final class Builder {
        final String id;
        final String value;
        final String text;
        final List<String> members = new ArrayList<>();
        final List<TransformReport.OptionalMember> optionals = new ArrayList<>();
        final List<TransformReport.Reliance> relies = new ArrayList<>();
        final List<TransformReport.EnumConstants> enums = new ArrayList<>();
        final List<TransformReport.Doc> docs = new ArrayList<>();
        final List<TransformReport.Rejected> rejected = new ArrayList<>();

        Builder(String id, String value, String text) {
            this.id = id;
            this.value = value;
            this.text = text;
        }

        boolean available() {
            return !value.equals(ABSENT) && !value.equals(UNAVAILABLE);
        }

        TransformReport.Capability build() {
            return new TransformReport.Capability(id, value, available() ? text : null, available() ? null : text,
                List.copyOf(members), List.copyOf(optionals), List.copyOf(relies), List.copyOf(enums),
                List.copyOf(docs), List.copyOf(rejected));
        }
    }
}
