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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Which components of a CycloneDX software bill of materials of upstream's
 * build are in upstream's JAR. The bill of materials comes from upstream's
 * dependencies, but upstream's build leaves some of them out of the JAR,
 * such as Log4j and SLF4J, which the server provides. This tells them apart
 * by what the JAR contains, rather than by reading upstream's build
 * configuration, which can include, exclude, filter and relocate in many
 * ways.
 *
 * <p>The files that the shaded JAR has beyond upstream's own, which the
 * original JAR has, came from the components. Each component's files are
 * matched to them by name, allowing for the package prefix that relocation
 * replaced: the prefixes that explain the most of the component's files
 * are taken as its relocation. A component with most of its files in the
 * JAR is in it. A component is not in the JAR when none of its files are,
 * or only files that the components in the JAR explain, as when a library
 * in the JAR has a copy of a few of its classes. Anything else counts as in
 * the JAR, since some of it is, such as a component that upstream's build
 * shrank. So does a component whose files can't be compared, such as one
 * that Maven didn't copy: it stays in the bill of materials, with a
 * warning.
 *
 * <p>Run by {@code scripts/lp sbom}, which leaves out the components that
 * the JAR doesn't contain.
 */
final class BundledComponents {

    /** Maven types whose files are JARs, which the repository layout names {@code .jar} */
    private static final Set<String> JAR_TYPES = Set.of("jar", "test-jar", "maven-plugin", "ejb", "ejb-client",
        "java-source", "javadoc", "bundle");

    private BundledComponents() {
    }

    /**
     * A component of the bill of materials.
     *
     * @param purl    its package URL
     * @param file    its artifact, or {@code null} if it has none to compare
     * @param missing why it has no artifact to compare, or {@code null}
     */
    record Component(String purl, Path file, String missing) {

        Component(String purl, Path file) {
            this(purl, file, null);
        }
    }

    /**
     * Whether the JAR contains a component, and why.
     *
     * @param inJar   whether the JAR contains at least some of it, or it
     *                can't be told
     * @param files   how many files it has that a JAR can bundle
     * @param matched how many of them are in the JAR, relocated as
     *                {@code from} and {@code to} say, or if it isn't in the
     *                JAR, how many are named like files of the JAR's
     *                libraries
     * @param from    the package prefix that relocation replaced, such as
     *                {@code org/bstats/}, or empty
     * @param to      what relocation replaced it with, such as
     *                {@code net/coreprotect/}, or empty
     * @param unknown why its files couldn't be compared with the JAR's, or
     *                {@code null} if they were
     */
    record Verdict(boolean inJar, int files, int matched, String from, String to, String unknown) {

        Verdict(boolean inJar, int files, int matched, String from, String to) {
            this(inJar, files, matched, from, to, null);
        }

        /**
         * @return a component whose files couldn't be compared, which counts as in the JAR
         */
        static Verdict unknown(String why) {
            return new Verdict(true, 0, 0, "", "", why);
        }

        /**
         * @return why, for the log
         */
        String describe() {
            if (unknown != null) {
                return "kept, since its files can't be compared with the JAR's: " + unknown;
            }
            if (!inJar) {
                return "not in the JAR" + (matched == 0 ? "" : " (" + matched + " of its " + files + " files are named"
                    + " like files of the libraries in the JAR)");
            }
            String where = from.equals(to) ? "" : ", " + (from.isEmpty() ? "under " + to : from + " as "
                + (to.isEmpty() ? "the top level" : to));
            return (mostly(matched, files) ? "in the JAR: " : "partly in the JAR: ") + matched + " of " + files
                + " files" + where;
        }
    }

    /**
     * @return whether most of a component's files are in the JAR
     */
    private static boolean mostly(int matched, int files) {
        return files > 0 && matched * 2 > files;
    }

    /**
     * How a component's files match the JAR's under one relocation.
     */
    private static final class Relocation {
        final String from;
        final String to;
        /** The component's files that the JAR has this way */
        final Set<String> sources = new HashSet<>();
        /** The JAR's files that they are */
        final Set<String> targets = new HashSet<>();

        Relocation(String from, String to) {
            this.from = from;
            this.to = to;
        }
    }

    /**
     * @param jar         upstream's shaded JAR
     * @param originalJar upstream's JAR before shading, with only upstream's own files
     * @return whether the shaded JAR contains each component, by package URL
     */
    static Map<String, Verdict> judge(Path jar, Path originalJar, List<Component> components) throws IOException {
        Set<String> bundled = new TreeSet<>(files(jar));
        bundled.removeAll(files(originalJar));
        Map<String, List<String>> byName = new HashMap<>();
        for (String file : bundled) {
            byName.computeIfAbsent(fileName(file), name -> new ArrayList<>()).add(file);
        }

        Map<String, Matches> matches = new LinkedHashMap<>();
        Map<String, Verdict> unknown = new LinkedHashMap<>();
        // The JAR's files that the components mostly in it account for
        Set<String> explained = new HashSet<>();
        for (Component component : components) {
            if (component.file() == null) {
                unknown.put(component.purl(), Verdict.unknown(component.missing()));
                continue;
            }
            Set<String> files;
            try {
                files = files(component.file());
            } catch (IOException e) {
                unknown.put(component.purl(), Verdict.unknown("can't read " + component.file() + ": " + e));
                continue;
            }
            Matches match = match(files, byName);
            matches.put(component.purl(), match);
            if (mostly(match.best.sources.size(), match.files)) {
                explained.addAll(match.best.targets);
            }
        }

        Map<String, Verdict> verdicts = new LinkedHashMap<>();
        for (Component component : components) {
            Matches match = matches.get(component.purl());
            if (match == null) {
                verdicts.put(component.purl(), unknown.get(component.purl()));
                continue;
            }
            // Files in the JAR that only it may account for mean that some of it is there
            boolean inJar = mostly(match.best.sources.size(), match.files) || !explained.containsAll(match.namesakes);
            verdicts.put(component.purl(), new Verdict(inJar, match.files, inJar ? match.best.sources.size()
                : match.named.size(), match.best.from, match.best.to));
        }
        return verdicts;
    }

    /**
     * How a component's files match the JAR's.
     *
     * @param files     how many files it has that a JAR can bundle
     * @param best      the relocation under which the JAR has the most of them
     * @param named     its files that are named like files in the JAR, under
     *                  any relocation
     * @param namesakes the JAR's files that are named like its files
     */
    private record Matches(int files, Relocation best, Set<String> named, Set<String> namesakes) {
    }

    /**
     * @param byName the files that the JAR bundles, by file name
     */
    private static Matches match(Set<String> files, Map<String, List<String>> byName) {
        Map<String, Relocation> relocations = new TreeMap<>();
        Set<String> named = new HashSet<>();
        Set<String> namesakes = new HashSet<>();
        for (String file : files) {
            String[] source = file.split("/");
            for (String candidate : byName.getOrDefault(fileName(file), List.of())) {
                String[] target = candidate.split("/");
                // Relocation replaces a prefix, and keeps the path segments after it
                int common = 0;
                while (common < source.length && common < target.length
                    && source[source.length - 1 - common].equals(target[target.length - 1 - common])) {
                    common++;
                }
                String from = prefix(source, source.length - common);
                String to = prefix(target, target.length - common);
                Relocation relocation = relocations.computeIfAbsent(from + "\n" + to, key -> new Relocation(from, to));
                relocation.sources.add(file);
                relocation.targets.add(candidate);
                named.add(file);
                namesakes.add(candidate);
            }
        }
        Relocation best = new Relocation("", "");
        for (Relocation relocation : relocations.values()) {
            if (relocation.sources.size() > best.sources.size()) {
                best = relocation;
            }
        }
        return new Matches(files.size(), best, named, namesakes);
    }

    /**
     * @return the first {@code count} segments of a path, with a slash after
     *         each, such as {@code org/bstats/}
     */
    private static String prefix(String[] segments, int count) {
        StringBuilder prefix = new StringBuilder();
        for (int i = 0; i < count; i++) {
            prefix.append(segments[i]).append('/');
        }
        return prefix.toString();
    }

    private static String fileName(String path) {
        return path.substring(path.lastIndexOf('/') + 1);
    }

    /**
     * @return the files of a JAR that a shaded JAR can bundle: everything but
     *         directories, {@code META-INF/} (which a shaded JAR merges or
     *         drops) and module descriptors, with multi-release copies under
     *         the path of the class they are a version of
     */
    static Set<String> files(Path jar) throws IOException {
        Set<String> files = new TreeSet<>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (entry.isDirectory()) {
                    continue;
                }
                if (name.startsWith(JarContents.VERSIONS_PREFIX)) {
                    int slash = name.indexOf('/', JarContents.VERSIONS_PREFIX.length());
                    name = slash < 0 ? "" : name.substring(slash + 1);
                }
                if (name.isEmpty() || name.startsWith("META-INF/") || name.equals("module-info.class")) {
                    continue;
                }
                files.add(name);
            }
        }
        return files;
    }

    /**
     * @param bom          a CycloneDX bill of materials from Maven
     * @param dependencies where Maven copied the components' artifacts, in
     *                     its repository layout
     * @return the bill of materials' components with their artifacts, or
     *         why one has none there, such as a dependency of system scope,
     *         which Maven doesn't copy with the others
     */
    static List<Component> components(String bom, Path dependencies) {
        JsonObject root = JsonParser.parseString(bom).getAsJsonObject();
        List<Component> components = new ArrayList<>();
        JsonElement list = root.get("components");
        if (list == null || list.isJsonNull()) {
            return components;
        }
        for (JsonElement element : list.getAsJsonArray()) {
            JsonObject component = element.getAsJsonObject();
            String purl = component.has("purl") ? component.get("purl").getAsString() : "";
            try {
                components.add(new Component(purl, artifact(purl, dependencies)));
            } catch (IllegalArgumentException e) {
                components.add(new Component(purl, null, e.getMessage()));
            }
        }
        return components;
    }

    /**
     * @return where Maven's repository layout under {@code dependencies} has
     *         the artifact of a package URL such as
     *         {@code pkg:maven/com.clickhouse/clickhouse-jdbc@0.10.0?classifier=all&type=jar}
     */
    static Path artifact(String purl, Path dependencies) {
        if (!purl.startsWith("pkg:maven/")) {
            throw new IllegalArgumentException("Not a Maven artifact: '" + purl + "'");
        }
        String rest = purl.substring("pkg:maven/".length());
        Map<String, String> qualifiers = new HashMap<>();
        int question = rest.indexOf('?');
        if (question >= 0) {
            for (String qualifier : rest.substring(question + 1).split("&")) {
                int equals = qualifier.indexOf('=');
                if (equals > 0) {
                    qualifiers.put(qualifier.substring(0, equals), decode(qualifier.substring(equals + 1)));
                }
            }
            rest = rest.substring(0, question);
        }
        int slash = rest.indexOf('/');
        int at = rest.lastIndexOf('@');
        if (slash <= 0 || at <= slash + 1 || at == rest.length() - 1) {
            throw new IllegalArgumentException("Not a Maven artifact: '" + purl + "'");
        }
        String group = decode(rest.substring(0, slash));
        String name = decode(rest.substring(slash + 1, at));
        String version = decode(rest.substring(at + 1));
        String type = qualifiers.getOrDefault("type", "jar");
        String classifier = qualifiers.get("classifier");
        String extension = JAR_TYPES.contains(type) ? "jar" : type;
        Path file = dependencies.resolve(String.join("/", group.split("\\."))).resolve(name).resolve(version)
            .resolve(name + "-" + version + (classifier == null ? "" : "-" + classifier) + "." + extension);
        if (!Files.isRegularFile(file)) {
            throw new IllegalArgumentException("No artifact of " + purl + " at " + file);
        }
        return file;
    }

    private static String decode(String text) {
        return URLDecoder.decode(text, StandardCharsets.UTF_8);
    }

    /**
     * Write the package URLs of the components that upstream's JAR doesn't
     * contain as a JSON array, and log each verdict, with a warning for a
     * component that it can't tell about, which it keeps.
     *
     * <p>Arguments: {@code --bom FILE --jar FILE --original-jar FILE
     * --dependencies DIRECTORY --output FILE}. Exit status 1 on any error.
     */
    public static void main(String[] args) {
        try {
            Map<String, String> arguments = new HashMap<>();
            for (int i = 0; i < args.length; i += 2) {
                if (!args[i].startsWith("--") || i + 1 >= args.length) {
                    throw new IllegalArgumentException("Expected --name value, got: " + args[i]);
                }
                arguments.put(args[i].substring(2), args[i + 1]);
            }
            List<String> names = List.of("bom", "jar", "original-jar", "dependencies", "output");
            for (String name : names) {
                if (!arguments.containsKey(name)) {
                    throw new IllegalArgumentException("Missing --" + name);
                }
            }
            for (String name : arguments.keySet()) {
                if (!names.contains(name)) {
                    throw new IllegalArgumentException("Unknown option --" + name);
                }
            }

            List<Component> components = components(
                Files.readString(Path.of(arguments.get("bom")), StandardCharsets.UTF_8),
                Path.of(arguments.get("dependencies")));
            Map<String, Verdict> verdicts = judge(Path.of(arguments.get("jar")), Path.of(arguments.get("original-jar")),
                components);
            JsonArray outside = new JsonArray();
            verdicts.forEach((purl, verdict) -> {
                System.out.println((verdict.unknown() == null ? "" : "warning: ") + purl + ": " + verdict.describe());
                if (!verdict.inJar()) {
                    outside.add(purl);
                }
            });
            Files.writeString(Path.of(arguments.get("output")), outside + "\n", StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException e) {
            System.err.println("error: " + e.getMessage());
            System.exit(1);
        }
    }
}
