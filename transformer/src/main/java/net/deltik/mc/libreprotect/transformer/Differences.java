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

import java.util.Arrays;
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
            .append("`plugins/CoreProtect/libreprotect.yml`. By default, that policy sends no web requests: ")
            .append("LibreProtect answers translation requests itself and blocks every other request. Connections to ")
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
            .append("the Patreon link, points the Discord and download links to LibreProtect, and names ")
            .append("LibreProtect where the plugin names itself.\n")
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

        md.append("\n## Extension Point Placeholders\n\n")
            .append("Upstream loads these classes by name, but its public source doesn't include them. LibreProtect's ")
            .append("placeholders explain that the feature isn't available.\n\n");
        for (TransformReport.ExtensionPoint extensionPoint : report.extensionPoints) {
            md.append("- ").append(code(extensionPoint.className())).append(", requested by ")
                .append(codes(extensionPoint.requestedBy())).append("\n");
        }

        md.append("\n## Added Files\n\n");
        for (String entry : report.injectedEntries) {
            md.append("- ").append(code(entry)).append("\n");
        }
        return md.toString();
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
