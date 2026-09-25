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

package net.deltik.mc.libreprotect.extension.upstream;

import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.net.JarURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The capability report that the build writes for the transformer.
 */
class CapabilityReportTest {

    /** How many fields each kind of record has */
    private static final Map<String, Integer> FIELDS = Map.of("upstream", 3, "capability", 4, "member", 3,
        "optional", 4, "relies", 4, "enum", 4, "doc", 4, "rejected", 4);

    @TempDir
    Path folder;

    private static Path upstreamJar() throws Exception {
        URL found = CapabilityReport.class.getClassLoader().getResource(
            Names.CONFIG_HANDLER.replace('.', '/') + ".class");
        return new File(((JarURLConnection) found.openConnection()).getJarFileURL().toURI()).toPath();
    }

    @Test
    @DisplayName("should write the same report every time, in byte order after the upstream line")
    void deterministic() {
        String report = CapabilityReport.render(Capabilities.probe(Upstream.coreProtect()), "00ff");

        assertEquals(report, CapabilityReport.render(Capabilities.probe(Upstream.coreProtect()), "00ff"));
        List<String> lines = Arrays.asList(report.split("\n", -1));
        assertEquals("", lines.get(lines.size() - 1), "The report ends with a line break");
        assertEquals("upstream\tsha256\t00ff", lines.get(0));
        List<String> records = new ArrayList<>(lines.subList(1, lines.size() - 1));
        List<String> sorted = new ArrayList<>(records);
        sorted.sort((a, b) -> Arrays.compareUnsigned(a.getBytes(StandardCharsets.UTF_8),
            b.getBytes(StandardCharsets.UTF_8)));
        assertEquals(sorted, records);
        assertEquals(sorted, CapabilityReport.sort(records));
        assertEquals(CapabilityReport.render(Capabilities.probe(Upstream.coreProtect()), null),
            String.join("\n", records) + "\n");
    }

    @Test
    @DisplayName("should write one well-formed record per line, with a capability line for each capability")
    void wellFormed() {
        String report = CapabilityReport.render(Capabilities.current(), null);

        for (String line : report.split("\n")) {
            String[] fields = line.split("\t", -1);
            assertTrue(FIELDS.containsKey(fields[0]), line);
            assertEquals(FIELDS.get(fields[0]), fields.length, line);
            for (String field : fields) {
                assertFalse(field.isEmpty(), line);
            }
            if (fields[0].equals("optional")) {
                assertTrue(fields[3].equals("present") || fields[3].equals("absent"), line);
            }
        }
        for (Capability<?> capability : Capabilities.known()) {
            assertEquals(1, report.lines().filter(line -> line.startsWith("capability\t" + capability.id() + "\t"))
                .count(), capability.id());
        }
        assertEquals(CapabilityReport.current(), report);
    }

    @Test
    @DisplayName("should list only what upstream's own JAR has, not the libraries it brings along")
    void onlyUpstream() {
        for (String line : CapabilityReport.render(Capabilities.current(), null).split("\n")) {
            String[] fields = line.split("\t");
            if (List.of("member", "optional", "relies", "enum").contains(fields[0])) {
                assertTrue(fields[2].startsWith("net/coreprotect/"), line);
            }
        }
    }

    @Test
    @DisplayName("should sort by UTF-8 bytes, not Java's order of strings, and refuse text that isn't Unicode")
    void utf8() {
        String replacement = "doc\tfake\tdocs/a.md\t�";
        String emoji = "doc\tfake\tdocs/a.md\t😀";

        assertTrue(emoji.compareTo(replacement) < 0, "Java puts the surrogate pair first");
        assertEquals(List.of(replacement, emoji), CapabilityReport.sort(List.of(emoji, replacement)));
        assertArrayEquals(new byte[]{(byte) 0xF0, (byte) 0x9F, (byte) 0x98, (byte) 0x80},
            CapabilityReport.utf8("😀"));
        assertThrows(IllegalArgumentException.class, () -> CapabilityReport.utf8("half \uD83D of a pair"));
    }

    @Test
    @DisplayName("should report the upstream JAR's SHA-256 and what probing it found")
    void main() throws Exception {
        Path jar = upstreamJar();
        Path out = folder.resolve("reports/capabilities.tsv");

        CapabilityReport.main(new String[]{jar.toString(), out.toString()});

        String report = Files.readString(out);
        String sha256 = CapabilityReport.sha256(jar);
        assertTrue(sha256.matches("[0-9a-f]{64}"), sha256);
        assertEquals(CapabilityReport.render(Capabilities.probe(Upstream.coreProtect()), sha256), report);
    }

    @Test
    @DisplayName("should refuse a JAR other than the one on the class path")
    void otherJar() throws Exception {
        Path other = Files.write(folder.resolve("other.jar"), new byte[]{1, 2, 3});

        IllegalStateException refused = assertThrows(IllegalStateException.class,
            () -> CapabilityReport.main(new String[]{other.toString(), folder.resolve("out.tsv").toString()}));
        assertTrue(refused.getMessage().contains(other.toString()), refused.getMessage());
        assertFalse(Files.exists(folder.resolve("out.tsv")));
    }
}
