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

package net.deltik.mc.libreprotect.testutil;

import net.deltik.mc.libreprotect.extension.upstream.Capabilities;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.JarURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Skips tests that need the CoreProtect being built to use a capability in
 * one particular way, such as tests of CoreProtect 25's codecs.
 */
public final class AssumeCapability {

    /** The reviewed state of upstream; tests run in the module's directory */
    private static final Path BASELINE = Path.of("..", "audit", "baseline.json");
    /** The SHA-256 of the upstream JAR whose build a line of the baseline was accepted from */
    private static final Pattern JAR_SHA256 = Pattern.compile("\"jarSha256\"\\s*:\\s*\"([0-9a-f]{64})\"");

    private static String upstreamSha256;

    private AssumeCapability() {
    }

    /**
     * @param id the capability's ID, such as {@code migrate-db.transcoding}
     * @param strategy the way the test needs, such as {@code statement-codecs}
     * @return how the CoreProtect being built supports the capability
     */
    public static Choice<?> strategy(String id, String strategy) {
        Choice<?> choice = Capabilities.current().get(id);
        assumeTrue(choice.strategy().equals(strategy),
            () -> "This CoreProtect's " + id + " is " + choice.strategy() + ", not " + strategy);
        return choice;
    }

    /**
     * Skip a test whose exact expectations are those of the upstream JARs
     * whose builds the lines of {@code audit/baseline.json} were accepted
     * from, unless the CoreProtect being built is one of them. On one of
     * them, such a test fails whenever LibreProtect takes another way, as
     * when a change to the extensions breaks one. On another upstream, such
     * as a development build of a changed one, the features whose needs
     * changed turn off and its audit reports the change, and its unit tests
     * don't fail it for that.
     */
    public static void reviewedUpstream() {
        String sha256 = upstreamSha256();
        assumeTrue(reviewedUpstreams().contains(sha256), () -> "The upstream JAR being built, whose SHA-256 is "
            + sha256 + ", isn't the jarSha256 of a line of audit/baseline.json, whose ways these tests expect"
            + " exactly");
    }

    /**
     * @return the SHA-256 of the upstream JARs whose builds the lines of
     *         {@code audit/baseline.json} were accepted from
     */
    static Set<String> reviewedUpstreams() {
        String baseline;
        try {
            baseline = Files.readString(BASELINE, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Can't read the audit baseline at " + BASELINE.toAbsolutePath(), e);
        }
        Set<String> reviewed = new HashSet<>();
        Matcher sha256 = JAR_SHA256.matcher(baseline);
        while (sha256.find()) {
            reviewed.add(sha256.group(1));
        }
        return reviewed;
    }

    /**
     * @return the SHA-256 of the upstream JAR on the class path, which the
     *         capability report's {@code upstream sha256} line gives too
     */
    public static synchronized String upstreamSha256() {
        if (upstreamSha256 != null) {
            return upstreamSha256;
        }
        URL found = AssumeCapability.class.getClassLoader().getResource("net/coreprotect/CoreProtect.class");
        if (found == null) {
            throw new IllegalStateException("CoreProtect isn't on the class path");
        }
        try {
            Path jar = Path.of(((JarURLConnection) found.openConnection()).getJarFileURL().toURI());
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream in = Files.newInputStream(jar)) {
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = in.read(buffer)) > 0) {
                    digest.update(buffer, 0, read);
                }
            }
            upstreamSha256 = HexFormat.of().formatHex(digest.digest());
            return upstreamSha256;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (ClassCastException | URISyntaxException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Can't read the CoreProtect JAR at " + found, e);
        }
    }
}
