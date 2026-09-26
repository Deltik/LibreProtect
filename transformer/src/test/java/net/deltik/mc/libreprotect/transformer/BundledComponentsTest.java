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

import net.deltik.mc.libreprotect.transformer.BundledComponents.Component;
import net.deltik.mc.libreprotect.transformer.BundledComponents.Verdict;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Which components of upstream's bill of materials its shaded JAR contains,
 * as {@code scripts/lp sbom} marks them.
 */
class BundledComponentsTest {

    @TempDir
    Path folder;

    private Path jar(String name, String... entries) throws IOException {
        Map<String, byte[]> contents = new LinkedHashMap<>();
        for (String entry : entries) {
            contents.put(entry, entry.getBytes(StandardCharsets.UTF_8));
        }
        return TestClasses.writeJar(folder.resolve(name), contents);
    }

    /** Upstream's own classes, which both of its JARs have */
    private static final String[] UPSTREAM = {"net/up/Main.class", "net/up/util/Strings.class", "plugin.yml",
        "META-INF/MANIFEST.MF"};

    private Path original() throws IOException {
        return jar("original.jar", UPSTREAM);
    }

    private Path shaded(String... bundled) throws IOException {
        String[] entries = new String[UPSTREAM.length + bundled.length];
        System.arraycopy(UPSTREAM, 0, entries, 0, UPSTREAM.length);
        System.arraycopy(bundled, 0, entries, UPSTREAM.length, bundled.length);
        return jar("shaded.jar", entries);
    }

    @Test
    @DisplayName("should find a relocated library, one as it is, and not one that the JAR leaves out")
    void relocatedAndExcluded() throws IOException {
        Path metrics = jar("metrics.jar", "org/metrics/Metrics.class", "org/metrics/charts/Pie.class",
            "org/metrics/charts/Bar.class", "META-INF/MANIFEST.MF", "META-INF/maven/org.metrics/metrics/pom.xml");
        Path driver = jar("driver.jar", "com/driver/Driver.class", "com/driver/internal/Pool.class",
            "com/driver/version.properties");
        // Upstream's own util/Strings.class doesn't count: it isn't a library's
        Path logging = jar("logging.jar", "org/logging/Logger.class", "org/logging/LoggerFactory.class",
            "org/logging/util/Strings.class", "org/logging/Main.class", "module-info.class");
        Path shaded = shaded("net/up/Metrics.class", "net/up/charts/Pie.class", "net/up/charts/Bar.class",
            "com/driver/Driver.class", "com/driver/internal/Pool.class", "com/driver/version.properties",
            "META-INF/maven/org.metrics/metrics/pom.xml");

        Map<String, Verdict> verdicts = BundledComponents.judge(shaded, original(), List.of(
            new Component("metrics", metrics), new Component("driver", driver), new Component("logging", logging)));

        assertEquals(new Verdict(true, 3, 3, "org/metrics/", "net/up/"), verdicts.get("metrics"));
        assertEquals("in the JAR: 3 of 3 files, org/metrics/ as net/up/", verdicts.get("metrics").describe());
        assertEquals(new Verdict(true, 3, 3, "", ""), verdicts.get("driver"));
        assertEquals("in the JAR: 3 of 3 files", verdicts.get("driver").describe());
        assertFalse(verdicts.get("logging").inJar());
        assertEquals(new Verdict(false, 4, 0, "", ""), verdicts.get("logging"));
        assertEquals("not in the JAR", verdicts.get("logging").describe());
    }

    @Test
    @DisplayName("should leave out a library whose only namesakes in the JAR are another library's copies of its classes")
    void namesakes() throws IOException {
        // Like Log4j's date formatting, which the ClickHouse driver's copy of Commons Lang has too
        Path logging = jar("logging.jar", "org/logging/Logger.class", "org/logging/Level.class",
            "org/logging/time/FastDateFormat.class", "org/logging/time/FastDateParser.class");
        Path driver = jar("driver.jar", "com/driver/Driver.class", "com/driver/Logger.class",
            "com/driver/lang/time/FastDateFormat.class", "com/driver/lang/time/FastDateParser.class");
        Path shaded = shaded("com/driver/Driver.class", "com/driver/Logger.class",
            "com/driver/lang/time/FastDateFormat.class", "com/driver/lang/time/FastDateParser.class");

        Map<String, Verdict> verdicts = BundledComponents.judge(shaded, original(), List.of(
            new Component("logging", logging), new Component("driver", driver)));

        assertTrue(verdicts.get("driver").inJar());
        assertEquals(new Verdict(false, 4, 3, "org/logging/", "com/driver/lang/"), verdicts.get("logging"));
        assertEquals("not in the JAR (3 of its 4 files are named like files of the libraries in the JAR)",
            verdicts.get("logging").describe());
    }

    @Test
    @DisplayName("should count a library that the JAR has only some of as in it, and one that is in the JAR in part")
    void partly() throws IOException {
        Path shrunk = jar("shrunk.jar", "org/big/A.class", "org/big/B.class", "org/big/C.class", "org/big/D.class",
            "org/big/E.class");
        Path shaded = shaded("net/up/big/A.class");

        Verdict verdict = BundledComponents.judge(shaded, original(), List.of(new Component("shrunk", shrunk)))
            .get("shrunk");

        assertEquals(new Verdict(true, 5, 1, "org/", "net/up/"), verdict);
        assertEquals("partly in the JAR: 1 of 5 files, org/ as net/up/", verdict.describe());
    }

    @Test
    @DisplayName("should keep a component whose files it can't compare with the JAR's, and say why")
    void unknown() throws IOException {
        Path notZip = Files.writeString(folder.resolve("native.so"), "not a ZIP file");
        Path shaded = shaded("net/up/Metrics.class");

        Map<String, Verdict> verdicts = BundledComponents.judge(shaded, original(), List.of(
            new Component("missing", null, "No artifact of missing at somewhere"), new Component("native", notZip)));

        assertEquals(Verdict.unknown("No artifact of missing at somewhere"), verdicts.get("missing"));
        assertTrue(verdicts.get("missing").inJar());
        assertEquals("kept, since its files can't be compared with the JAR's: No artifact of missing at somewhere",
            verdicts.get("missing").describe());
        assertTrue(verdicts.get("native").inJar());
        assertTrue(verdicts.get("native").unknown().startsWith("can't read " + notZip + ": "),
            verdicts.get("native")::toString);
    }

    @Test
    @DisplayName("should read a multi-release copy as the class it is a version of, and skip META-INF")
    void files() throws IOException {
        Path library = jar("library.jar", "org/lib/A.class", "META-INF/versions/11/org/lib/A.class",
            "META-INF/versions/17/org/lib/B.class", "META-INF/versions/9/module-info.class", "module-info.class",
            "META-INF/services/java.sql.Driver", "META-INF/LICENSE", "lib.properties");

        assertEquals(Set.of("org/lib/A.class", "org/lib/B.class", "lib.properties"), BundledComponents.files(library));
    }

    @Test
    @DisplayName("should find each component's artifact where Maven copied it in its repository layout")
    void components() throws IOException {
        Path dependencies = folder.resolve("dependencies");
        Path driver = dependencies.resolve("com/clickhouse/clickhouse-jdbc/0.10.0/clickhouse-jdbc-0.10.0-all.jar");
        Path pool = dependencies.resolve("com/zaxxer/HikariCP/7.0.2/HikariCP-7.0.2.jar");
        Files.createDirectories(driver.getParent());
        Files.createDirectories(pool.getParent());
        Files.writeString(driver, "");
        Files.writeString(pool, "");
        String bom = """
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
              {"type": "library", "group": "com.zaxxer", "name": "HikariCP", "version": "7.0.2",
               "purl": "pkg:maven/com.zaxxer/HikariCP@7.0.2?type=jar"},
              {"type": "library", "group": "com.clickhouse", "name": "clickhouse-jdbc", "version": "0.10.0",
               "purl": "pkg:maven/com.clickhouse/clickhouse-jdbc@0.10.0?classifier=all&type=jar"},
              {"type": "library", "group": "com.example", "name": "vendored", "version": "1",
               "purl": "pkg:maven/com.example/vendored@1?type=jar"}
            ]}
            """;

        // Maven doesn't copy a dependency of system scope with the others
        assertEquals(List.of(new Component("pkg:maven/com.zaxxer/HikariCP@7.0.2?type=jar", pool),
            new Component("pkg:maven/com.clickhouse/clickhouse-jdbc@0.10.0?classifier=all&type=jar", driver),
            new Component("pkg:maven/com.example/vendored@1?type=jar", null, "No artifact of"
                + " pkg:maven/com.example/vendored@1?type=jar at " + dependencies.resolve(
                    "com/example/vendored/1/vendored-1.jar"))),
            BundledComponents.components(bom, dependencies));
        assertEquals(List.of(), BundledComponents.components("{\"specVersion\": \"1.6\"}", dependencies));
        assertEquals("No artifact of pkg:maven/org.slf4j/slf4j-api@2.0.17?type=jar at " + dependencies.resolve(
            "org/slf4j/slf4j-api/2.0.17/slf4j-api-2.0.17.jar"), assertThrows(IllegalArgumentException.class,
            () -> BundledComponents.artifact("pkg:maven/org.slf4j/slf4j-api@2.0.17?type=jar", dependencies))
            .getMessage());
        for (String purl : List.of("pkg:npm/left-pad@1.3.0", "pkg:maven/nameless@1", "pkg:maven/g/a@", "")) {
            assertThrows(IllegalArgumentException.class, () -> BundledComponents.artifact(purl, dependencies), purl);
        }
    }
}
