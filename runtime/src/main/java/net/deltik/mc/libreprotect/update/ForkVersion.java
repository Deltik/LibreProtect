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

package net.deltik.mc.libreprotect.update;

import java.util.Arrays;
import java.util.Comparator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A LibreProtect version: the CoreProtect release tag it is named after, and
 * either a release revision or a development build.
 *
 * <ul>
 *   <li>Release: {@code <upstream>-libre<N>}, such as {@code 24.1-libre2}, the
 *       second release of LibreProtect's changes to CoreProtect's release
 *       {@code v24.1}</li>
 *   <li>Development build: what {@code git describe --tags --long --dirty}
 *       says about the upstream commit, without the tag's {@code v}, then
 *       {@code -libre-dev}: {@code <upstream>-<commits>-g<commit>[-dirty]-libre-dev},
 *       such as {@code 24.0-121-gd5cad31-libre-dev} for upstream's commit
 *       {@code d5cad31}, 121 commits past CoreProtect's release tag
 *       {@code v24.0}</li>
 * </ul>
 *
 * <p>The upstream version is the tag's two or three numbers, as CoreProtect's
 * release tags have. Versions are ordered by upstream version, numerically
 * and with a missing third part counting as 0. For the same upstream
 * version, releases come first, by revision, and development builds after
 * them, by how many commits they are past the tag, and a clean one before a
 * dirty one. So a development build named after {@code v24.1} is newer than
 * every {@code 24.1-libre<N>}, and older than {@code 24.2-libre1}.
 */
public final class ForkVersion {

    /** Each part fits in an {@code int}, which is what CoreProtect parses it as */
    private static final String UPSTREAM = "(\\d{1,9}(?:\\.\\d{1,9}){1,2})";
    private static final Pattern UPSTREAM_ONLY = Pattern.compile(UPSTREAM);
    private static final Pattern RELEASE = Pattern.compile(UPSTREAM + "-libre(\\d{1,9})");
    private static final Pattern DEV = Pattern.compile(UPSTREAM + "-(\\d{1,9})-g[0-9a-f]{7,40}(-dirty)?-libre-dev");

    /** Orders versions from oldest to newest, as the class comment describes */
    static final Comparator<ForkVersion> ORDER = ((Comparator<ForkVersion>) ForkVersion::compareNumbers)
        .thenComparing(version -> !version.isRelease())
        .thenComparingInt(version -> version.revision)
        .thenComparingInt(version -> version.commits)
        .thenComparing(version -> version.dirty);

    private final String text;
    private final int[] upstream;
    /** The release revision, or -1 for a development build */
    private final int revision;
    /** How many commits a development build is past its tag, or -1 for a release */
    private final int commits;
    /** Whether a development build was made from a checkout with local changes */
    private final boolean dirty;

    private ForkVersion(String text, int[] upstream, int revision, int commits, boolean dirty) {
        this.text = text;
        this.upstream = upstream;
        this.revision = revision;
        this.commits = commits;
        this.dirty = dirty;
    }

    /**
     * @return the version, or {@code null} if the text isn't a LibreProtect
     *         release or development build version
     */
    public static ForkVersion parse(String text) {
        if (text == null) {
            return null;
        }
        Matcher release = RELEASE.matcher(text);
        if (release.matches()) {
            return new ForkVersion(text, parts(release.group(1)), Integer.parseInt(release.group(2)), -1, false);
        }
        Matcher dev = DEV.matcher(text);
        if (dev.matches()) {
            return new ForkVersion(text, parts(dev.group(1)), -1, Integer.parseInt(dev.group(2)),
                dev.group(3) != null);
        }
        return null;
    }

    /**
     * @return the release version, or {@code null} if the text isn't a
     *         LibreProtect release version
     */
    public static ForkVersion parseRelease(String text) {
        ForkVersion version = parse(text);
        return version != null && version.isRelease() ? version : null;
    }

    private static int[] parts(String upstream) {
        return Arrays.stream(upstream.split("\\.")).mapToInt(Integer::parseInt).toArray();
    }

    /**
     * @param version a version from a plugin.yml, such as {@code 24.1}
     * @return the numbers of the version as CoreProtect reads its own, from
     *         the part before the first dash, such as {@code [24, 1]}; or
     *         {@code null} if that part isn't what an upstream version in a
     *         LibreProtect version can be
     */
    static int[] coreProtectParts(String version) {
        if (version == null) {
            return null;
        }
        int dash = version.indexOf('-');
        String own = dash < 0 ? version : version.substring(0, dash);
        return UPSTREAM_ONLY.matcher(own).matches() ? parts(own) : null;
    }

    public boolean isRelease() {
        return revision >= 0;
    }

    /**
     * @return the numeric parts of the upstream version, two or three
     */
    int[] upstreamParts() {
        return upstream.clone();
    }

    /**
     * @return the numbers of the upstream version as CoreProtect compares
     *         them, such as {@code 24.1}, without leading zeros
     */
    public String upstream() {
        return join(upstream);
    }

    static String join(int[] parts) {
        StringBuilder text = new StringBuilder();
        for (int part : parts) {
            if (text.length() > 0) {
                text.append('.');
            }
            text.append(part);
        }
        return text.toString();
    }

    /**
     * Compare the numbers of upstream versions only, as CoreProtect does.
     *
     * @return negative, zero or positive as this upstream version's numbers
     *         are lower than, the same as or higher than the other's
     */
    int compareNumbers(ForkVersion other) {
        return compareNumbers(other.upstream);
    }

    /**
     * Compare the numbers of this upstream version with others, as
     * CoreProtect does.
     *
     * @param other two or three numbers, such as {@code [24, 1]}
     * @return negative, zero or positive as this upstream version's numbers
     *         are lower than, the same as or higher than the others
     */
    int compareNumbers(int[] other) {
        for (int i = 0; i < 3; i++) {
            int compared = Integer.compare(part(upstream, i), part(other, i));
            if (compared != 0) {
                return compared;
            }
        }
        return 0;
    }

    private static int part(int[] parts, int index) {
        return index < parts.length ? parts[index] : 0;
    }

    /**
     * Whether a server running {@code running} should be told about this
     * release, for a CoreProtect that declares the upstream version of
     * {@code running}'s name. See {@link #isUpdateFor(ForkVersion, int[])}.
     */
    public boolean isUpdateFor(ForkVersion running) {
        return isUpdateFor(running, running.upstream);
    }

    /**
     * Whether a server running {@code running} should be told about this
     * release. A release is offered releases that are newer by
     * {@link #ORDER}: of a newer upstream version, or of the same one with a
     * higher revision. A development build is only offered releases of an
     * upstream version newer than its tag's, since it may already contain
     * what a revision of that version fixed. They must also be newer than the
     * version that its CoreProtect declares, which can be newer than the tag:
     * upstream sometimes tags a release on a branch of its own, and its main
     * branch then declares that version but describes itself from the tag
     * before, such as {@code 24.0-121-gd5cad31-libre-dev} declaring 24.1.
     *
     * @param running     the version the server runs
     * @param coreProtect the numbers of the version that the server's
     *                    CoreProtect declares, such as {@code [24, 1]}
     */
    public boolean isUpdateFor(ForkVersion running, int[] coreProtect) {
        if (!isRelease() || ORDER.compare(this, running) <= 0) {
            return false;
        }
        return running.isRelease() || compareNumbers(coreProtect) > 0;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ForkVersion && text.equals(((ForkVersion) other).text);
    }

    @Override
    public int hashCode() {
        return text.hashCode();
    }

    /**
     * @return the version as it was written, such as {@code 24.1-libre2}
     */
    @Override
    public String toString() {
        return text;
    }
}
