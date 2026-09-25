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

import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/**
 * The capability report, {@code capabilities.tsv}: how LibreProtect's
 * extensions use the upstream JAR. One tab-separated record per line; the
 * {@code upstream} line first, the others sorted by their bytes:
 * <pre>
 * upstream    sha256      &lt;SHA-256 of the upstream JAR&gt;
 * capability  &lt;id&gt;  &lt;strategy|absent|unavailable&gt;  &lt;description, or why not&gt;
 * member      &lt;id&gt;  &lt;class, owner#field:descriptor or owner#method(descriptor)&gt;
 * optional    &lt;id&gt;  &lt;member&gt;  present|absent
 * relies      &lt;id&gt;  &lt;owner#method(descriptor)&gt;  &lt;what probing can't prove&gt;
 * enum        &lt;id&gt;  &lt;owner&gt;  &lt;CONSTANT,...&gt; in declaration order
 * doc         &lt;id&gt;  &lt;path in upstream's source tree&gt;  &lt;what it documents&gt;
 * rejected    &lt;id&gt;  &lt;strategy&gt;  &lt;why&gt;
 * </pre>
 * Classes are in the JVM's internal form, such as
 * {@code net/coreprotect/consumer/Consumer}.
 */
public final class CapabilityReport {

    private CapabilityReport() {
    }

    /**
     * For the build: probe the upstream JAR on the class path and write its
     * report.
     *
     * @param args the upstream JAR, which must be the one on the class path,
     *             and the report to write
     */
    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            throw new IllegalArgumentException("Usage: CapabilityReport <upstream JAR> <report>");
        }
        Path jar = Paths.get(args[0]);
        Path out = Paths.get(args[1]);
        checkOnClassPath(jar);
        Capabilities capabilities = Capabilities.probe(Upstream.coreProtect());
        Path parent = out.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(out, utf8(render(capabilities, sha256(jar))));
        for (Choice<?> choice : capabilities.all()) {
            if (!choice.isAvailable() && !choice.isAbsent()) {
                System.err.println("[WARNING] " + choice.id() + " is unavailable: " + choice.reason());
            }
        }
    }

    /**
     * @return the report of the CoreProtect that runs, without the
     *         {@code upstream} line, for the integration test
     */
    public static String current() {
        return render(Capabilities.current(), null);
    }

    /**
     * @param upstreamSha256 the hex SHA-256 of the upstream JAR, or
     *                       {@code null} to leave out the {@code upstream} line
     * @return the report, with a line break after every line
     */
    public static String render(Capabilities capabilities, String upstreamSha256) {
        List<String> lines = new ArrayList<>();
        for (Choice<?> choice : capabilities.all()) {
            lines.addAll(choice.reportLines());
        }
        StringBuilder report = new StringBuilder();
        if (upstreamSha256 != null) {
            report.append("upstream\tsha256\t").append(upstreamSha256).append('\n');
        }
        for (String line : sort(lines)) {
            report.append(line).append('\n');
        }
        return report.toString();
    }

    /**
     * @return the lines in the order of their UTF-8 bytes, which differs
     *         from Java's order of strings outside the Basic Multilingual Plane
     */
    static List<String> sort(List<String> lines) {
        List<String> sorted = new ArrayList<>(lines);
        sorted.sort(Comparator.comparing(CapabilityReport::utf8, Arrays::compareUnsigned));
        return sorted;
    }

    /**
     * @return the text in UTF-8
     * @throws IllegalArgumentException if it isn't valid Unicode, such as
     *                                  with half of a surrogate pair
     */
    static byte[] utf8(String text) {
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(text));
            byte[] bytes = new byte[encoded.remaining()];
            encoded.get(bytes);
            return bytes;
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Not valid Unicode: " + text, e);
        }
    }

    /**
     * Make sure the classes probed are the upstream JAR's, not another
     * CoreProtect's on the class path.
     */
    private static void checkOnClassPath(Path jar) throws IOException {
        String resource = Names.CONFIG_HANDLER.replace('.', '/') + ".class";
        URL found = CapabilityReport.class.getClassLoader().getResource(resource);
        if (found == null) {
            throw new IllegalStateException("CoreProtect isn't on the class path; add " + jar);
        }
        File source;
        try {
            source = new File(((JarURLConnection) found.openConnection()).getJarFileURL().toURI());
        } catch (ClassCastException | java.net.URISyntaxException e) {
            throw new IllegalStateException("CoreProtect on the class path isn't a JAR: " + found, e);
        }
        if (!Files.isSameFile(source.toPath(), jar)) {
            throw new IllegalStateException("The CoreProtect on the class path is " + source + ", not " + jar);
        }
    }

    static String sha256(Path file) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) {
                digest.update(buffer, 0, read);
            }
        }
        StringBuilder hex = new StringBuilder();
        for (byte b : digest.digest()) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
}
