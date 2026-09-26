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

import org.objectweb.asm.Type;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Renders {@code DIFFERENCES.md}, the human-readable account of how a
 * LibreProtect JAR differs from the upstream CoreProtect JAR it was built
 * from. The Artistic License 2.0 (section 4) asks distributors of modified
 * versions to document how they differ from the standard version.
 */
final class Differences {

    /** Database engines by the names that CoreProtect's configuration uses, in the order the table shows them */
    private static final Map<String, String> ENGINES = orderedMap(
        "sqlite", "SQLite", "mysql", "MySQL", "duckdb", "DuckDB", "clickhouse", "ClickHouse");

    /** Readable names of the capabilities for each database engine, by ID prefix; {@code {}} is the engine */
    private static final Map<String, String> ENGINE_FEATURES = orderedMap(
        "migrate-db.source.", "`/co migrate-db` from {}",
        "migrate-db.target.", "`/co migrate-db` to {}",
        "auto-purge.engine.", "`auto-purge` with {}");

    /**
     * Readable names of the capabilities that users know as features, by
     * ID, in the order the table shows them
     */
    static final Map<String, String> FEATURES = features();
    private static final List<String> FEATURE_ORDER = List.copyOf(FEATURES.keySet());

    /**
     * Readable names of the capabilities that several features share, by
     * ID. The table shows one only when it isn't available, since the
     * features that need it can't work then either.
     */
    static final Map<String, String> SHARED = orderedMap(
        "database.selector", "Which database CoreProtect uses",
        "lifecycle.flags", "CoreProtect's state flags",
        "consumer.gate", "Pausing CoreProtect's database writes",
        "consumer.start-result", "CoreProtect's answers when its maintenance starts",
        "config.lock", "CoreProtect's lock on its settings",
        "server.thread", "Running tasks on the server's thread",
        "migrate-db.schema", "Creating CoreProtect's tables",
        "clickhouse.reads", "Reading ClickHouse",
        "clickhouse.writes", "Writing ClickHouse",
        "hook.auto-purge-counter", "Counting purged rows for `/co status`",
        "hook.lock-heartbeat", "Refreshing CoreProtect's database lock",
        "hook.entity-spawn-verification", "Rechecking tracked entities",
        "hook.duckdb-recovery", "CoreProtect's recovery of its DuckDB database",
        "hook.purge-worker", "Noticing a manual purge at work");

    private static Map<String, String> features() {
        Map<String, String> features = new LinkedHashMap<>();
        features.put("migrate-db.protocol", "`/co migrate-db`");
        for (String prefix : List.of("migrate-db.source.", "migrate-db.target.")) {
            ENGINES.forEach((engine, name) -> features.put(prefix + engine, ENGINE_FEATURES.get(prefix)
                .replace("{}", name)));
        }
        features.put("migrate-db.transcoding", "`/co migrate-db` between SQLite or MySQL and DuckDB or ClickHouse");
        features.put("migrate-db.duckdb-writes", "`/co migrate-db`: writing to DuckDB");
        features.put("migrate-db.incomplete-mark", "`/co migrate-db`: keeping CoreProtect off an unfinished copy");
        features.put("auto-purge.retention", "`auto-purge`: how much to keep");
        features.put("auto-purge.settings", "`auto-purge`: when to purge, and the table prefix");
        features.put("auto-purge.coordination", "`auto-purge`: taking turns with CoreProtect's database work");
        features.put("auto-purge.tables", "`auto-purge`: the tables to purge");
        ENGINES.forEach((engine, name) -> features.put("auto-purge.engine." + engine, ENGINE_FEATURES
            .get("auto-purge.engine.").replace("{}", name)));
        return Collections.unmodifiableMap(features);
    }

    /**
     * @param keysAndValues a key, then its value, and so on
     */
    private static Map<String, String> orderedMap(String... keysAndValues) {
        Map<String, String> map = new LinkedHashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            map.put(keysAndValues[i], keysAndValues[i + 1]);
        }
        return Collections.unmodifiableMap(map);
    }

    private Differences() {
    }

    static String render(TransformReport report) {
        StringBuilder md = new StringBuilder();
        md.append("# How LibreProtect ").append(report.forkVersion).append(" Differs from CoreProtect\n\n");
        md.append("This JAR was built from CoreProtect ").append(code(report.upstreamRef)).append(" (commit ")
            .append(code(report.upstreamCommit)).append("). Upstream's own build output was post-processed by ")
            .append("LibreProtect's transformer (LibreProtect commit ").append(code(report.forkCommit))
            .append("); no upstream source file was modified. Everything that changed is listed below.\n\n")
            .append("Source: https://github.com/Deltik/LibreProtect\n\n");

        md.append("## License\n\n")
            .append("CoreProtect is by Intelli and its contributors, under the Artistic License 2.0. ")
            .append("As section 4(c)(ii) of that license permits, this modified version is distributed under the ")
            .append("GNU General Public License, version 3 or later. The license texts and notice are in ")
            .append("`META-INF/libreprotect/`.\n\n");

        md.append("## Network Requests\n\n")
            .append("Each call below used to open a network connection directly. It now goes through ")
            .append("`net.deltik.mc.libreprotect.Egress`, which applies the network policy in ")
            .append("`plugins/CoreProtect/libreprotect.yml`. By default, with the `allow-updates` preset, ")
            .append("LibreProtect answers CoreProtect's update checks itself: it asks GitHub for LibreProtect's ")
            .append("latest release, or Modrinth if GitHub fails or names no LibreProtect release, and nothing ")
            .append("is sent to update.coreprotect.net. ")
            .append("These requests name LibreProtect, but carry no version, server or key information; GitHub or ")
            .append("Modrinth still sees the server's IP address, as with any request. LibreProtect answers ")
            .append("translation requests itself too, from the translations it bundles, and blocks every other ")
            .append("request. The `privacy-first` preset blocks update checks as well, so LibreProtect makes no web ")
            .append("requests at all. The `passthrough` preset lets every request through unchanged. Connections to ")
            .append("the databases in `config.yml` are outside the network policy.\n\n")
            .append("| Class | Method | Call | Origin | Places |\n|---|---|---|---|---|\n");
        Map<String, Long> egress = report.egressSites.stream().collect(Collectors.groupingBy(site ->
                cellCode(site.className().replace('/', '.')) + " | " + cellCode(readable(site.method())) + " | "
                    + cellCode("URL." + readable(site.api())) + " (" + cellText(site.kind()) + ") | "
                    + (site.origin() == Origin.UPSTREAM ? "CoreProtect" : "bundled library")
                    + (JarContents.isVersioned(site.entry()) ? ", multi-release copy" : ""),
            LinkedHashMap::new, Collectors.counting()));
        egress.forEach((row, count) -> md.append("| ").append(row).append(" | ").append(count).append(" |\n"));

        md.append("\n## Donation-Key Checks\n\n")
            .append("These checks now return a constant, so features that upstream reserves for donors are ")
            .append("available. No donation key is needed, and by default none is sent. Under the `passthrough` ")
            .append("preset, CoreProtect's own license check runs as upstream's does: it sends a `donation-key` set ")
            .append("in `config.yml` to coreprotect.net.\n\n")
            .append("| Class | Method | Always returns |\n|---|---|---|\n");
        for (TransformReport.EditionGate gate : report.editionGates) {
            md.append("| ").append(cellCode(gate.className().replace('/', '.'))).append(" | ")
                .append(cellCode(readable(gate.method()))).append(" | ").append(cellCode(String.valueOf(gate.value())))
                .append(" |\n");
        }

        md.append("\n## CoreProtect's Own Version\n\n")
            .append("`plugin.yml` has LibreProtect's version, which the server and `/co status` show. CoreProtect ")
            .append("compares its own version with those of its database, its patches and its features. It now ")
            .append("compares the version that upstream's build gave it, ").append(code(report.upstreamVersion))
            .append(", which this method reads instead of `plugin.yml`'s version:\n\n")
            .append("| Class | Method | Reads |\n|---|---|---|\n");
        for (TransformReport.PluginVersionRead read : report.pluginVersionReads) {
            md.append("| ").append(cellCode(read.className().replace('/', '.'))).append(" | ")
                .append(cellCode(readable(read.method()))).append(" | ").append(cellCode(read.version()))
                .append(" |\n");
        }

        md.append("\n## Messages\n\n")
            .append("The plugin is still named CoreProtect, so that other plugins and the data folder keep working, ")
            .append("but its messages name LibreProtect:\n\n")
            .append("- Each call to the phrase renderer (").append(codeList(report.phraseRenderers)).append(", ")
            .append(report.countBranding(BrandingRewriter.KIND_PHRASE)).append(" calls) passes its result to ")
            .append("`net.deltik.mc.libreprotect.Branding`. It leaves out the donation-key line of `/co status` and ")
            .append("the Patreon link, points the Discord and download links to LibreProtect, names ")
            .append("LibreProtect where the plugin names itself, and shows LibreProtect's release in update notices ")
            .append("when LibreProtect answered the update check.\n")
            .append("- ").append(report.countBranding(BrandingRewriter.KIND_OUTPUT))
            .append(" calls that print messages (Bukkit `sendMessage(String)` and `java.util.logging.Logger`) go ")
            .append("through `Branding`, which skips the messages it leaves out.\n")
            .append("- These texts that show the plugin name now say LibreProtect. `{}` marks a value that is filled ")
            .append("in when the message is shown:\n\n")
            .append("| Before | After | Places |\n|---|---|---|\n");
        Map<String, Long> texts = report.brandingSites.stream()
            .filter(site -> site.kind().equals(BrandingRewriter.KIND_TEXT))
            .collect(Collectors.groupingBy(site -> text(site.before()) + " | " + text(site.after()),
                TreeMap::new, Collectors.counting()));
        texts.forEach((change, count) -> md.append("| ").append(change).append(" | ").append(count).append(" |\n"));

        md.append("\n## Translations\n\n")
            .append("CoreProtect's source code has translations that its JAR leaves out. LibreProtect bundles them ")
            .append("in `").append(Translations.DIRECTORY).append("` and answers CoreProtect's translation requests ")
            .append("with them, so `language` in `config.yml` works without a network request. Of CoreProtect's ")
            .append(report.phraseCount).append(" phrases, those that a translation lacks stay in English, and those ")
            .append("customized in `language.yml` stay as customized. A phrase counts as customized when its text ")
            .append("isn't CoreProtect's built-in English, as CoreProtect's own cache decides; the build takes that ")
            .append("English from CoreProtect's code into `").append(Translations.DEFAULTS).append("`.\n\n")
            .append("| Language | Phrases | Missing |\n|---|---|---|\n");
        for (TransformReport.Translation translation : report.translations) {
            md.append("| ").append(cellCode(translation.language())).append(" | ").append(translation.phrases())
                .append(" | ").append(translation.missing().size()).append(" |\n");
        }
        String unknown = report.translations.stream().filter(translation -> !translation.unknown().isEmpty())
            .map(translation -> code(translation.language()) + ": " + codes(translation.unknown()))
            .collect(Collectors.joining("; "));
        if (!unknown.isEmpty()) {
            md.append("\nThese keys aren't CoreProtect's phrases, so they are never used: ").append(unknown).append("\n");
        }
        if (!report.phrasesWithoutDefault.isEmpty()) {
            md.append("\nCoreProtect's code has no plain English text for ").append(codes(report.phrasesWithoutDefault))
                .append(", so these phrases stay in English.\n");
        }
        if (!report.englishDifferences.isEmpty()) {
            md.append("\n`").append(Translations.ENGLISH).append(".yml` differs from the built-in English for ")
                .append(codes(report.englishDifferences)).append(". The built-in English is what counts.\n");
        }

        md.append("\n## Plugin Entry Point\n\n")
            .append(code(report.upstreamMainClass)).append(" is no longer `final`. The new main class ")
            .append(code(report.generatedMainClass)).append(" extends it. It loads the network policy in its ")
            .append("constructor. After `onEnable`, it writes a default `plugins/CoreProtect/libreprotect.yml` if ")
            .append("there is none, and logs which policy is active. Everything else is inherited unchanged.\n\n");

        md.append("## plugin.yml\n\n| Key | CoreProtect | LibreProtect |\n|---|---|---|\n");
        for (Map.Entry<String, TransformReport.ValueChange> change : report.pluginYmlChanges.entrySet()) {
            md.append("| ").append(cellCode(change.getKey())).append(" | ").append(cell(change.getValue().before()))
                .append(" | ").append(cell(change.getValue().after())).append(" |\n");
        }

        md.append("\n## Extension Points\n\n")
            .append("Upstream loads these classes by name, but its public source doesn't include them. LibreProtect ")
            .append("provides them, with its own implementations of `/co migrate-db` and automatic purging ")
            .append("(`auto-purge`):\n\n");
        for (TransformReport.ExtensionPoint extensionPoint : report.extensionPoints) {
            md.append("- ").append(code(extensionPoint.className())).append(", requested by ")
                .append(codes(extensionPoint.requestedBy())).append("\n");
        }
        if (!report.capabilities.isEmpty()) {
            md.append("\n## How the Extensions Work with This CoreProtect\n\n")
                .append("The extensions don't link against CoreProtect's classes. When they run, they find the ")
                .append(report.upstreamMemberCount).append(" CoreProtect classes, methods and fields that they use ")
                .append("by name, through reflection. The build checked each of them against this CoreProtect JAR; ")
                .append("they are listed in `transform-report.json`, and what the build found is in `")
                .append(CapabilityReport.ENTRY).append("`.\n\n");
            capabilities(md, report.capabilities);
        }

        md.append("\n## Added Files\n\n");
        for (String entry : report.injectedEntries) {
            md.append("- ").append(code(entry)).append("\n");
        }
        return md.toString();
    }

    /**
     * The table of what each feature does with this CoreProtect: the
     * features users know first, in {@link #FEATURES}' order, then any the
     * transformer has no name for, by ID. A capability that several features
     * share is left out while it's available. Features that this CoreProtect
     * doesn't have at all, such as those of engines it lacks, follow the
     * table, by the reason.
     */
    static void capabilities(StringBuilder md, List<TransformReport.Capability> capabilities) {
        List<TransformReport.Capability> ordered = new ArrayList<>(capabilities);
        ordered.sort(Comparator.comparingInt(Differences::rank).thenComparing(TransformReport.Capability::id));
        Map<String, List<String>> absent = new LinkedHashMap<>();
        int shared = 0;
        int sharedUnavailable = 0;
        md.append("| Feature | With this CoreProtect |\n|---|---|\n");
        for (TransformReport.Capability capability : ordered) {
            boolean isShared = SHARED.containsKey(capability.id());
            if (capability.value().equals(CapabilityReport.ABSENT)) {
                if (!isShared) {
                    absent.computeIfAbsent(capability.reason(), reason -> new ArrayList<>()).add(feature(capability.id()));
                }
                continue;
            }
            if (isShared) {
                shared++;
                if (capability.available()) {
                    continue;
                }
                sharedUnavailable++;
            }
            String status = capability.available() ? sentenceCase(capability.description())
                : "Not available: " + capability.reason();
            md.append("| ").append(feature(capability.id())).append(" | ").append(cellText(status)).append(" |\n");
        }
        if (!absent.isEmpty()) {
            md.append("\nThis CoreProtect doesn't have these at all:\n\n");
            absent.forEach((reason, features) -> md.append("- ").append(String.join(", ", features)).append(": ")
                .append(cellText(reason)).append("\n"));
        }
        if (shared > 0) {
            md.append("\nThe features also rest on ").append(shared).append(shared == 1 ? " capability" : " capabilities")
                .append(" that several of them share, such as telling which database CoreProtect uses. ")
                .append(sharedStatus(shared, sharedUnavailable)).append("\n");
        }
    }

    /**
     * @return a sentence on whether the capabilities that the features share
     *         work; the table has a row for each one that doesn't
     */
    private static String sharedStatus(int shared, int unavailable) {
        if (unavailable == 0) {
            return shared == 1 ? "It works with this CoreProtect." : "All of those work with this CoreProtect.";
        }
        if (unavailable == shared) {
            return shared == 1 ? "It doesn't work with this CoreProtect, as the table shows."
                : "None of those work with this CoreProtect, as the table shows.";
        }
        return (unavailable == 1 ? "One of those doesn't" : unavailable + " of those don't")
            + " work with this CoreProtect, as the table shows; the others do.";
    }

    /**
     * @return the text with its first letter capitalized, as a table cell
     *         starts, such as a description "the migration's own SQLite
     *         connections"
     */
    private static String sentenceCase(String text) {
        return text.isEmpty() ? text : Character.toUpperCase(text.charAt(0)) + text.substring(1);
    }

    /**
     * @return where a capability goes in the table: its place among the
     *         features users know, then after them
     */
    private static int rank(TransformReport.Capability capability) {
        int index = FEATURE_ORDER.indexOf(capability.id());
        return index >= 0 ? index : SHARED.containsKey(capability.id()) ? FEATURE_ORDER.size() + 1
            : FEATURE_ORDER.size();
    }

    /**
     * @return the value as a code span, which shows it as it is, whatever
     *         backticks or HTML it contains
     */
    static String code(String value) {
        String flat = String.valueOf(value).replace('\n', ' ').replace('\r', ' ');
        int longest = 0;
        for (int i = 0, run = 0; i < flat.length(); i++) {
            run = flat.charAt(i) == '`' ? run + 1 : 0;
            longest = Math.max(longest, run);
        }
        String fence = "`".repeat(longest + 1);
        String padding = flat.startsWith("`") || flat.endsWith("`") ? " " : "";
        return fence + padding + flat + padding + fence;
    }

    /**
     * @return the value as a code span in a table cell
     */
    private static String cellCode(String value) {
        return code(value).replace("|", "\\|");
    }

    /**
     * @return text for a table cell, escaped so that it shows as it is: it
     *         can't end the cell, start a code span, or become HTML
     */
    static String cellText(String value) {
        StringBuilder escaped = new StringBuilder();
        for (char c : value.toCharArray()) {
            switch (c) {
                case '\\' -> escaped.append("\\\\");
                case '|' -> escaped.append("\\|");
                case '`' -> escaped.append("\\`");
                case '<' -> escaped.append("&lt;");
                case '>' -> escaped.append("&gt;");
                case '&' -> escaped.append("&amp;");
                case '\n', '\r' -> escaped.append(' ');
                default -> escaped.append(c);
            }
        }
        return escaped.toString();
    }

    /**
     * @return a readable name for a capability, or its ID as code if it has none
     */
    static String feature(String id) {
        String feature = FEATURES.getOrDefault(id, SHARED.get(id));
        if (feature != null) {
            return feature;
        }
        for (Map.Entry<String, String> prefix : ENGINE_FEATURES.entrySet()) {
            if (id.startsWith(prefix.getKey()) && id.length() > prefix.getKey().length()) {
                String engine = id.substring(prefix.getKey().length());
                return prefix.getValue().replace("{}", ENGINES.getOrDefault(engine, code(engine)));
            }
        }
        return code(id);
    }

    /**
     * @return a method's name and descriptor as its name and simple parameter
     *         types, such as {@code openConnection(Proxy)}
     */
    private static String readable(String method) {
        int parenthesis = method.indexOf('(');
        if (parenthesis < 0) {
            return method;
        }
        return method.substring(0, parenthesis) + Arrays.stream(Type.getArgumentTypes(method.substring(parenthesis)))
            .map(type -> type.getClassName().substring(type.getClassName().lastIndexOf('.') + 1))
            .collect(Collectors.joining(", ", "(", ")"));
    }

    /**
     * @return methods, given as {@code owner.name descriptor}, as a list of {@code owner.name}
     */
    private static String codeList(List<String> methods) {
        return codes(methods.stream().map(method -> method.substring(0, method.indexOf('(')).replace('/', '.'))
            .toList());
    }

    /**
     * @return the names as a list of code spans
     */
    private static String codes(List<String> names) {
        return names.stream().map(Differences::code).collect(Collectors.joining(", "));
    }

    /**
     * @return a string constant as a table cell, without the concatenation
     *         slots and Minecraft format codes that would make it unreadable
     */
    private static String text(String value) {
        String readable = value.replaceAll("[\u0001\u0002]", "{}").replaceAll("\u00A7[0-9a-fk-orxA-FK-ORX]", "")
            .replace("\n", " ").strip();
        return cellCode(readable);
    }

    private static String cell(String value) {
        return value == null ? "(unset)" : cellCode(value);
    }
}
