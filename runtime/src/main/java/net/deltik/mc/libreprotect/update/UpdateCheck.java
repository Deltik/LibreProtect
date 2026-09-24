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

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.PrivacyConstants;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Answers CoreProtect's update check by asking the update sources for
 * LibreProtect's newest release.
 *
 * <p>CoreProtect reads the reply as a version of its own and announces an
 * update if that is newer than its version: the version that upstream's
 * build gave it, such as {@code 24.1}, which the transformer has it compare
 * instead of LibreProtect's. So when there is a newer release, this reports a
 * synthetic version that CoreProtect sees as newer, and records the release
 * in {@link UpdateStatus} so that {@link UpdatePhrases} can show the release
 * instead.
 */
public final class UpdateCheck {

    /** CoreProtect ignores replies of this many characters or more */
    static final int MAX_VERSION_LENGTH = 10;

    private final List<UpdateSource> sources;
    private final String runningText;
    private final ForkVersion running;
    /** The numbers of the version that CoreProtect compares the reply with, or {@code null} if {@link #running} is */
    private final int[] coreProtect;
    private final CheckUpdatesSetting checkUpdates;
    private final UpdateHttp http;
    private final AtomicBoolean warnedUnknownVersion = new AtomicBoolean();

    /**
     * Check without looking at CoreProtect's settings, for a CoreProtect
     * whose version is the upstream part of the running version.
     *
     * @param sources        the sources to ask, in order; none turns update
     *                       checks off
     * @param runningVersion the LibreProtect version the server runs
     */
    public UpdateCheck(List<UpdateSource> sources, String runningVersion) {
        this(sources, runningVersion, null, null, new UpdateHttp());
    }

    /**
     * @param sources            the sources to ask, in order; none turns
     *                           update checks off
     * @param runningVersion     the LibreProtect version the server runs
     * @param coreProtectVersion the version that CoreProtect compares as its
     *                           own, from upstream's plugin.yml; if it's
     *                           {@code null} or not a version like
     *                           {@code 24.1}, the upstream part of the running
     *                           version
     * @param coreProtectConfig  CoreProtect's {@code config.yml}, whose
     *                           {@code check-updates} is read before each check
     */
    public UpdateCheck(List<UpdateSource> sources, String runningVersion, String coreProtectVersion,
                       File coreProtectConfig) {
        this(sources, runningVersion, coreProtectVersion, coreProtectConfig, new UpdateHttp());
    }

    UpdateCheck(List<UpdateSource> sources, String runningVersion, File coreProtectConfig, UpdateHttp http) {
        this(sources, runningVersion, null, coreProtectConfig, http);
    }

    UpdateCheck(List<UpdateSource> sources, String runningVersion, String coreProtectVersion, File coreProtectConfig,
                UpdateHttp http) {
        this.sources = Collections.unmodifiableList(new ArrayList<>(sources));
        this.runningText = runningVersion;
        this.running = ForkVersion.parse(runningVersion);
        int[] declared = ForkVersion.coreProtectParts(coreProtectVersion);
        this.coreProtect = declared != null ? declared : running == null ? null : running.upstreamParts();
        this.checkUpdates = coreProtectConfig == null ? null : new CheckUpdatesSetting(coreProtectConfig);
        this.http = http;
    }

    /**
     * @return CoreProtect's own version, as it compares it, or {@code null} if
     *         the running version isn't a LibreProtect version
     */
    public String runningUpstreamVersion() {
        return running == null ? null : ForkVersion.join(coreProtect);
    }

    /**
     * Ask the sources in order until one answers.
     *
     * @return the version to report so that CoreProtect announces a newer
     *         release, or empty if there is nothing to announce, which clears
     *         {@link UpdateStatus}
     * @throws IOException if CoreProtect's {@code check-updates} is off now,
     *         or every source failed, without changing {@link UpdateStatus}
     */
    public Optional<String> check() throws IOException {
        if (sources.isEmpty()) {
            UpdateStatus.clear();
            return Optional.empty();
        }
        requireCheckUpdates();
        if (running == null) {
            if (warnedUnknownVersion.compareAndSet(false, true)) {
                LibreProtectLogger.warning("Update checks can't compare versions: the running version '" + runningText
                    + "' isn't a " + PrivacyConstants.FORK_NAME + " version like 24.1-libre1, so no update is announced");
            }
            UpdateStatus.clear();
            return Optional.empty();
        }

        Release release = newestRelease();
        if (!release.version().isUpdateFor(running, coreProtect)) {
            UpdateStatus.clear();
            return Optional.empty();
        }
        String synthetic = syntheticVersion(coreProtect, release.version());
        if (synthetic == null) {
            LibreProtectLogger.debug("Update check: CoreProtect can't be told about " + release.version()
                + " with a version of fewer than " + MAX_VERSION_LENGTH + " characters");
            UpdateStatus.clear();
            return Optional.empty();
        }
        UpdateStatus.set(release, synthetic);
        return Optional.of(synthetic);
    }

    /**
     * CoreProtect's hourly update check doesn't notice when {@code /co reload}
     * turns {@code check-updates} off, so check the setting here.
     *
     * @throws IOException if update checks are off, or the setting can't be
     *         read, so that CoreProtect carries on as if offline
     */
    private void requireCheckUpdates() throws IOException {
        if (checkUpdates == null) {
            return;
        }
        String problem;
        try {
            if (checkUpdates.isOn()) {
                return;
            }
            problem = CheckUpdatesSetting.KEY + " is off in " + checkUpdates.file();
        } catch (IOException e) {
            problem = "couldn't read " + CheckUpdatesSetting.KEY + " from " + checkUpdates.file() + ": " + e.getMessage();
        }
        LibreProtectLogger.debug("Update check skipped: " + problem);
        throw new IOException("Update check skipped: " + problem);
    }

    /**
     * An answer without a LibreProtect release, such as a GitHub release
     * whose tag isn't a LibreProtect version, counts as the source failing,
     * since the next source may know better.
     *
     * @return the newest release of the first source that names one
     * @throws IOException if every source failed
     */
    Release newestRelease() throws IOException {
        IOException failure = new IOException("No update source answered");
        for (UpdateSource source : sources) {
            String request = source.describe();
            try {
                request += ": GET " + source.requestUrl();
                Release release = source.newestRelease(http)
                    .orElseThrow(() -> new IOException("the answer names no " + PrivacyConstants.FORK_NAME + " release"));
                LibreProtectLogger.debug("Update source " + request + " -> newest release " + release.version());
                return release;
            } catch (IOException | RuntimeException e) {
                LibreProtectLogger.debug("Update source " + request + " -> failed: " + e.getMessage());
                failure.addSuppressed(e);
            }
        }
        throw failure;
    }

    /**
     * The version to report so that CoreProtect, running {@code running}'s
     * upstream version, announces {@code release}.
     */
    static String syntheticVersion(ForkVersion running, ForkVersion release) {
        return syntheticVersion(running.upstreamParts(), release);
    }

    /**
     * The version to report so that CoreProtect, whose own version has the
     * numbers {@code running}, announces {@code release}.
     *
     * <p>CoreProtect reads a reply of fewer than {@value #MAX_VERSION_LENGTH}
     * characters, keeps its digits and dots, ignores it without a dot, and
     * compares it with its own version by major, minor and third part
     * ({@code VersionUtils.newVersion}). If the numbers of the release's
     * upstream version are higher, they are reported. Otherwise the release
     * has the same numbers as CoreProtect's own version: it's a new revision.
     * Then CoreProtect's own version is reported with its third part raised:
     * {@code 24.1} becomes {@code 24.1.1}, and {@code 24.1.1} becomes
     * {@code 24.1.2}. Either is newer by CoreProtect's rules.
     *
     * @param running the numbers of CoreProtect's own version, two or three
     * @param release a release that {@link ForkVersion#isUpdateFor is an update}
     *                for the running version
     * @return the version, or {@code null} if it would be too long
     */
    static String syntheticVersion(int[] running, ForkVersion release) {
        if (release.compareNumbers(running) > 0) {
            String newer = release.upstream();
            if (newer.length() < MAX_VERSION_LENGTH) {
                return newer;
            }
        }
        int[] raised = running.length == 3
            ? new int[] {running[0], running[1], running[2] + 1}
            : new int[] {running[0], running[1], 1};
        String version = ForkVersion.join(raised);
        return version.length() < MAX_VERSION_LENGTH ? version : null;
    }
}
