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

/*
 * Portions of this file are copied or adapted from CoreProtect
 * <https://github.com/PlayPro/CoreProtect>:
 *
 * Copyright (c) Intelli and the CoreProtect contributors
 *
 * CoreProtect is licensed under the Artistic License 2.0 (see
 * LICENSES/Artistic-2.0.txt). As section 4(c)(ii) of that license
 * permits, LibreProtect distributes these portions under the
 * GNU General Public License, version 3 or later. See NOTICE.
 */

package net.deltik.mc.libreprotect.update;

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.testutil.LocalHttpServer;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;

import static org.junit.jupiter.api.Assertions.*;

class UpdateCheckTest {

    private TestLogger testLogger;

    @BeforeEach
    void setUp() {
        LibreProtectLogger.reset();
        testLogger = new TestLogger();
        LibreProtectLogger.initialize(testLogger);
        UpdateStatus.reset();
    }

    @AfterEach
    void tearDown() {
        LibreProtectLogger.reset();
        UpdateStatus.reset();
    }

    /**
     * What CoreProtect does with the reply to its update check, copied from
     * upstream's {@code NetworkHandler} (v24.1 and master, lines 324-345) and
     * {@code VersionUtils.newVersion} with {@code StringUtils.convertArray}:
     * read one line of fewer than 10 characters, keep digits and dots, require
     * a dot, and compare with its own version.
     *
     * @return whether CoreProtect announces the reply as a newer version
     */
    static boolean coreProtectAnnounces(String pluginVersion, String response) {
        if (response == null || !(response.length() > 0 && response.length() < 10)) {
            return false;
        }
        String remoteVersion = response.replaceAll("[^0-9.]", "");
        if (!remoteVersion.contains(".")) {
            return false;
        }
        return newVersion(pluginVersion, remoteVersion);
    }

    /** Upstream's {@code VersionUtils.newVersion(String, String)} */
    static boolean newVersion(String oldVersion, String currentVersion) {
        if (!oldVersion.contains(".") || !currentVersion.contains(".")) {
            return false;
        }
        return newVersion(convertArray(oldVersion.split("\\.")), convertArray(currentVersion.split("\\.")));
    }

    /** Upstream's {@code StringUtils.convertArray} */
    private static Integer[] convertArray(String[] array) {
        List<Integer> list = new ArrayList<>();
        for (String item : array) {
            list.add(Integer.parseInt(item));
        }
        return list.toArray(new Integer[list.size()]);
    }

    /** Upstream's {@code VersionUtils.newVersion(Integer[], Integer[])} */
    private static boolean newVersion(Integer[] oldVersion, Integer[] currentVersion) {
        if (oldVersion[0] < currentVersion[0]) {
            return true;
        }
        else if (oldVersion[0].equals(currentVersion[0]) && oldVersion[1] < currentVersion[1]) {
            return true;
        }
        else if (oldVersion.length < 3 && currentVersion.length >= 3 && oldVersion[0].equals(currentVersion[0])
            && oldVersion[1].equals(currentVersion[1]) && 0 < currentVersion[2]) {
            return true;
        }
        else if (oldVersion.length >= 3 && currentVersion.length >= 3 && oldVersion[0].equals(currentVersion[0])
            && oldVersion[1].equals(currentVersion[1]) && oldVersion[2] < currentVersion[2]) {
            return true;
        }
        return false;
    }

    /** Upstream's {@code VersionUtils.getPluginVersion()}: the plugin version up to its first dash */
    private static String pluginVersion(String forkVersion) {
        return forkVersion.contains("-") ? forkVersion.split("-")[0] : forkVersion;
    }

    private static ForkVersion version(String text) {
        return ForkVersion.parse(text);
    }

    @Nested
    @DisplayName("syntheticVersion")
    class SyntheticVersion {

        @ParameterizedTest
        @DisplayName("should report a version that CoreProtect announces")
        @CsvSource({
            // A new revision of the running upstream version raises its last part
            "24.1-libre1, 24.1-libre2, 24.1.1",
            "24.1-libre1, 24.1-libre99, 24.1.1",
            "24.1.1-libre1, 24.1.1-libre2, 24.1.2",
            "24.1.9-libre1, 24.1.9-libre2, 24.1.10",
            "24.1.0-libre1, 24.1-libre2, 24.1.1",
            "24.1-libre1, 24.1.0-libre2, 24.1.1",
            // A newer upstream version is reported as it is
            "24.1-libre1, 24.2-libre1, 24.2",
            "24.1-libre5, 24.1.1-libre1, 24.1.1",
            "24.1.1-libre1, 24.2-libre1, 24.2",
            "24.1.5-libre1, 24.1.6-libre1, 24.1.6",
            "24.1-libre1, 25.0-libre1, 25.0",
            "9.9-libre1, 10.0-libre1, 10.0",
            // Development builds only get newer upstream versions
            "24.1-5-gabc1234-libre-dev, 24.2-libre1, 24.2",
            "24.1-5-gabc1234-libre-dev, 24.1.1-libre1, 24.1.1",
            "24.1.3-5-gabc1234-dirty-libre-dev, 25.0-libre1, 25.0",
            // Too long to report as it is, so the running version is raised
            "24.1-libre1, 24.1.1000000-libre1, 24.1.1",
            "24.1-libre1, 100000.0.0-libre1, 24.1.1"
        })
        void announced(String running, String release, String expected) {
            assertTrue(version(release).isUpdateFor(version(running)), "not an update: " + release);

            String synthetic = UpdateCheck.syntheticVersion(version(running), version(release));

            assertEquals(expected, synthetic);
            assertTrue(coreProtectAnnounces(pluginVersion(running), synthetic),
                "CoreProtect " + pluginVersion(running) + " wouldn't announce " + synthetic);
        }

        @ParameterizedTest
        @DisplayName("should report a version that CoreProtect announces, relative to the version it declares")
        @CsvSource({
            // Upstream's master declares 24.1, but describes itself from v24.0
            "24.0-121-gd5cad31-libre-dev, 24.1, 24.1.1-libre1, 24.1.1",
            "24.0-121-gd5cad31-libre-dev, 24.1, 24.2-libre1, 24.2",
            "24.0-121-gd5cad31-libre-dev, 24.1, 25.0-libre1, 25.0",
            "24.1-libre1, 24.1, 24.1-libre2, 24.1.1"
        })
        void announcedToDeclared(String running, String coreProtect, String release, String expected) {
            int[] declared = ForkVersion.coreProtectParts(coreProtect);
            assertTrue(version(release).isUpdateFor(version(running), declared), "not an update: " + release);

            String synthetic = UpdateCheck.syntheticVersion(declared, version(release));

            assertEquals(expected, synthetic);
            assertTrue(coreProtectAnnounces(coreProtect, synthetic),
                "CoreProtect " + coreProtect + " wouldn't announce " + synthetic);
        }

        @Test
        @DisplayName("should give up when no version short enough exists")
        void tooLong() {
            assertNull(UpdateCheck.syntheticVersion(version("1234.5678.9-libre1"), version("1234.5678.9-libre2")));
            assertNull(UpdateCheck.syntheticVersion(version("1234.5678.9-libre1"), version("1234.56789.0-libre1")));
            // A running version too long to raise can still be told about a short, newer upstream version
            assertEquals("123.457", UpdateCheck.syntheticVersion(version("123.456.999-libre1"), version("123.457-libre1")));
            assertTrue(coreProtectAnnounces("123.456.999", "123.457"));
        }

        @Test
        @DisplayName("should report nothing, and remember nothing, when CoreProtect can't be told")
        void tooLongCheck() throws IOException {
            try (LocalHttpServer server = new LocalHttpServer(exchange -> LocalHttpServer.respond(exchange, 200,
                "[{\"version_number\":\"1234.5678.9-libre2\",\"version_type\":\"release\"}]"))) {
                UpdateCheck check = new UpdateCheck(List.of(new ModrinthSource("libreprotect", server.getBaseUrl())),
                    "1234.5678.9-libre1");

                assertEquals(Optional.empty(), check.check());
                assertNull(UpdateStatus.current());
            }
        }

        @Test
        @DisplayName("should agree with CoreProtect for every update among many versions")
        void exhaustive() {
            List<String> versions = new ArrayList<>();
            for (int major = 23; major <= 25; major++) {
                for (int minor = 0; minor <= 2; minor++) {
                    for (int revision = 1; revision <= 2; revision++) {
                        versions.add(major + "." + minor + "-libre" + revision);
                        versions.add(major + "." + minor + ".0-libre" + revision);
                        versions.add(major + "." + minor + ".1-libre" + revision);
                        versions.add(major + "." + minor + ".10-libre" + revision);
                    }
                    versions.add(major + "." + minor + "-3-gabc1234-libre-dev");
                    versions.add(major + "." + minor + ".2-3-gabc1234-libre-dev");
                    versions.add(major + "." + minor + "-40-gabc1234-dirty-libre-dev");
                }
            }
            int updates = 0;
            for (String running : versions) {
                String own = pluginVersion(running);
                // A development build's CoreProtect may declare a newer version than the tag it's named after
                String[] parts = own.split("\\.");
                List<String> declared = version(running).isRelease() ? List.of(own)
                    : List.of(own, parts[0] + "." + (Integer.parseInt(parts[1]) + 1));
                for (String coreProtect : declared) {
                    int[] coreProtectParts = ForkVersion.coreProtectParts(coreProtect);
                    for (String release : versions) {
                        ForkVersion releaseVersion = ForkVersion.parseRelease(release);
                        if (releaseVersion == null || !releaseVersion.isUpdateFor(version(running), coreProtectParts)) {
                            // CoreProtect must never be told about something that isn't an update
                            continue;
                        }
                        updates++;
                        String synthetic = UpdateCheck.syntheticVersion(coreProtectParts, releaseVersion);
                        assertNotNull(synthetic, release + " for " + running);
                        assertTrue(coreProtectAnnounces(coreProtect, synthetic),
                            release + " for " + running + " declaring " + coreProtect + " as " + synthetic);
                    }
                }
            }
            assertTrue(updates > 1000, "only " + updates + " updates checked");
        }

        @Test
        @DisplayName("CoreProtect should not announce its own version, which is the no-update answer")
        void noUpdateAnswer() {
            for (String running : List.of("24.1-libre1", "24.1.3-libre2", "24.0-121-gd5cad31-libre-dev")) {
                assertFalse(coreProtectAnnounces(pluginVersion(running), version(running).upstream()), running);
            }
            assertFalse(coreProtectAnnounces("24.1",
                new UpdateCheck(List.of(), "24.0-121-gd5cad31-libre-dev", "24.1", null).runningUpstreamVersion()));
            assertFalse(coreProtectAnnounces("24.1", "0.0"));
        }
    }

    @Nested
    @DisplayName("check")
    class Check {

        private final List<LocalHttpServer> servers = new ArrayList<>();

        @AfterEach
        void closeServers() {
            servers.forEach(LocalHttpServer::close);
        }

        private LocalHttpServer server(int status, String body) throws IOException {
            LocalHttpServer server = new LocalHttpServer(exchange -> LocalHttpServer.respond(exchange, status, body));
            servers.add(server);
            return server;
        }

        private ModrinthSource modrinth(LocalHttpServer server) {
            return new ModrinthSource("libreprotect", server.getBaseUrl() + "/v2");
        }

        private GitHubSource github(LocalHttpServer server) {
            return new GitHubSource("Deltik/LibreProtect", server.getBaseUrl());
        }

        private static String modrinthVersions(String... versions) {
            StringBuilder body = new StringBuilder("[");
            for (String version : versions) {
                body.append(body.length() > 1 ? "," : "")
                    .append("{\"version_number\":\"").append(version).append("\",\"version_type\":\"release\"}");
            }
            return body.append("]").toString();
        }

        private UpdateCheck check(String running, UpdateSource... sources) {
            return new UpdateCheck(List.of(sources), running, null, new UpdateHttp(2_000, 2_000, 5_000));
        }

        @Test
        @DisplayName("should report and record a newer release")
        void newerRelease() throws IOException {
            LocalHttpServer server = server(200, modrinthVersions("24.1-libre3", "24.1-libre2"));

            assertEquals(Optional.of("24.1.1"), check("24.1-libre1", modrinth(server)).check());

            UpdateStatus.Known known = UpdateStatus.current();
            assertEquals("24.1-libre3", known.version());
            assertEquals("24.1.1", known.syntheticVersion());
            assertEquals("https://modrinth.com/plugin/libreprotect/version/24.1-libre3", known.pageUrl());
        }

        @Test
        @DisplayName("should answer relative to the version that CoreProtect compares as its own")
        void coreProtectVersion() throws IOException {
            LocalHttpServer server = server(200, modrinthVersions("24.1-libre2"));
            UpdateCheck check = new UpdateCheck(List.of(modrinth(server)), "24.1-libre1", "24.1.3", null,
                new UpdateHttp(2_000, 2_000, 5_000));

            assertEquals("24.1.3", check.runningUpstreamVersion());
            assertEquals(Optional.of("24.1.4"), check.check());
            assertTrue(coreProtectAnnounces("24.1.3", "24.1.4"));
            assertEquals("24.1-libre2", UpdateStatus.current().version());
        }

        @ParameterizedTest
        @DisplayName("should take the running version's upstream part for a CoreProtect version it can't read")
        @ValueSource(strings = {"unknown", "", "24.x", "v24.1", "25", "1.2.3.4"})
        void unreadableCoreProtectVersion(String coreProtect) {
            assertEquals("24.1", new UpdateCheck(List.of(), "24.1-libre1", coreProtect, null).runningUpstreamVersion());
            assertNull(new UpdateCheck(List.of(), "unknown", coreProtect, null).runningUpstreamVersion());
        }

        @Test
        @DisplayName("should read CoreProtect's version as CoreProtect does, up to the first dash")
        void coreProtectVersionToDash() {
            assertEquals("24.2", new UpdateCheck(List.of(), "24.1-libre1", "24.2-local", null).runningUpstreamVersion());
            assertEquals("24.1", new UpdateCheck(List.of(), "24.1-libre1", (String) null, null).runningUpstreamVersion());
        }

        @Test
        @DisplayName("should not offer a development build a release of the version that its CoreProtect declares")
        void devBuildPastTag() throws IOException {
            // Upstream tagged v24.1 on a branch of its own; its master declares 24.1, but describes itself from v24.0
            String running = "24.0-121-gd5cad31-libre-dev";
            LocalHttpServer server = server(200, modrinthVersions("24.1-libre2", "24.0-libre1"));
            UpdateCheck check = new UpdateCheck(List.of(modrinth(server)), running, "24.1", null,
                new UpdateHttp(2_000, 2_000, 5_000));

            assertEquals(Optional.empty(), check.check());
            assertNull(UpdateStatus.current());
            assertEquals("24.1", check.runningUpstreamVersion());

            LocalHttpServer newer = server(200, modrinthVersions("24.2-libre1", "24.1-libre2"));
            assertEquals(Optional.of("24.2"), new UpdateCheck(List.of(modrinth(newer)), running, "24.1", null,
                new UpdateHttp(2_000, 2_000, 5_000)).check());
            assertEquals("24.2-libre1", UpdateStatus.current().version());
            assertTrue(coreProtectAnnounces("24.1", "24.2"));
        }

        @Test
        @DisplayName("should ask the next source when one fails, in order, and stop at the first that answers")
        void fallbackOrder() throws IOException {
            LocalHttpServer missing = server(404, "{\"error\":\"not_found\"}");
            LocalHttpServer limited = server(429, "");
            LocalHttpServer answering = server(200, "{\"tag_name\":\"v24.1-libre2\","
                + "\"html_url\":\"https://github.com/Deltik/LibreProtect/releases/tag/v24.1-libre2\"}");
            LocalHttpServer unasked = server(200, modrinthVersions("99.0-libre1"));

            Optional<String> result = check("24.1-libre1",
                modrinth(missing), github(limited), github(answering), modrinth(unasked)).check();

            assertEquals(Optional.of("24.1.1"), result);
            assertEquals(1, missing.getRequests().size());
            assertEquals(1, limited.getRequests().size());
            assertEquals(1, answering.getRequests().size());
            assertEquals(List.of(), unasked.getRequests());
            assertEquals("github.com/Deltik/LibreProtect/releases/tag/v24.1-libre2", UpdateStatus.current().displayUrl());
        }

        @ParameterizedTest
        @DisplayName("should ask the next source when one answers without a LibreProtect release")
        @ValueSource(strings = {
            "{\"tag_name\":\"v25.0\",\"html_url\":\"https://github.com/Deltik/LibreProtect/releases/tag/v25.0\"}",
            "{\"tag_name\":\"v24.1-libre2\",\"prerelease\":true}",
            "{\"html_url\":\"https://github.com/Deltik/LibreProtect/releases/tag/v24.1-libre2\"}"
        })
        void answerWithoutRelease(String githubAnswer) throws IOException {
            LibreProtectLogger.setVerbose(true);
            LocalHttpServer unusable = server(200, githubAnswer);
            LocalHttpServer next = server(200, modrinthVersions("24.1-libre2"));

            assertEquals(Optional.of("24.1.1"), check("24.1-libre1", github(unusable), modrinth(next)).check());

            assertEquals(1, next.getRequests().size());
            assertEquals("24.1-libre2", UpdateStatus.current().version());
            assertTrue(testLogger.hasMessageContaining("-> failed: the answer names no LibreProtect release"),
                testLogger.getMessages().toString());
        }

        @Test
        @DisplayName("should fail, and keep the release it knew, when no source names a LibreProtect release")
        void noSourceNamesRelease() throws IOException {
            check("24.1-libre1", modrinth(server(200, modrinthVersions("24.1-libre2")))).check();
            LocalHttpServer empty = server(200, "[]");
            LocalHttpServer betaOnly = server(200, "[{\"version_number\":\"24.1-libre3\",\"version_type\":\"beta\"}]");

            IOException e = assertThrows(IOException.class,
                () -> check("24.1-libre1", modrinth(empty), modrinth(betaOnly)).check());

            assertEquals(2, e.getSuppressed().length);
            assertEquals(1, betaOnly.getRequests().size());
            assertEquals("24.1-libre2", UpdateStatus.current().version());
        }

        @Test
        @DisplayName("should fail when every source fails, and keep the release it knew")
        void everySourceFails() throws IOException {
            LocalHttpServer first = server(200, modrinthVersions("24.1-libre2"));
            check("24.1-libre1", modrinth(first)).check();
            LocalHttpServer broken = server(200, "not json");
            LocalHttpServer forbidden = server(403, "{\"message\":\"API rate limit exceeded\"}");

            IOException e = assertThrows(IOException.class,
                () -> check("24.1-libre1", modrinth(broken), github(forbidden)).check());

            assertEquals(2, e.getSuppressed().length);
            assertEquals("24.1-libre2", UpdateStatus.current().version());
        }

        @Test
        @DisplayName("should forget a release it knew when the sources report nothing newer")
        void forgetsRelease() throws IOException {
            check("24.1-libre1", modrinth(server(200, modrinthVersions("24.1-libre2")))).check();
            assertNotNull(UpdateStatus.current());

            assertEquals(Optional.empty(), check("24.1-libre2", modrinth(server(200, modrinthVersions("24.1-libre2")))).check());

            assertNull(UpdateStatus.current());
        }

        @Test
        @DisplayName("should not offer a development build a new revision of its own upstream version")
        void devBuild() throws IOException {
            LocalHttpServer server = server(200, modrinthVersions("24.1-libre99"));

            assertEquals(Optional.empty(), check("24.1-5-gabc1234-libre-dev", modrinth(server)).check());
            assertEquals(1, server.getRequests().size());
            assertNull(UpdateStatus.current());
        }

        @Test
        @DisplayName("should ask nobody and report nothing without sources")
        void noSources() throws IOException {
            UpdateStatus.set(new Release(version("24.1-libre2"), "https://example.invalid/"), "24.1.1");

            assertEquals(Optional.empty(), check("24.1-libre1").check());

            assertNull(UpdateStatus.current());
        }

        @Test
        @DisplayName("should ask nobody when the running version is unknown")
        void unknownRunningVersion() throws IOException {
            LocalHttpServer server = server(200, modrinthVersions("24.1-libre2"));

            assertEquals(Optional.empty(), check("unknown", modrinth(server)).check());
            assertEquals(List.of(), server.getRequests());
            assertNull(new UpdateCheck(List.of(), "unknown").runningUpstreamVersion());
            assertEquals("24.1", new UpdateCheck(List.of(), "24.1-libre1").runningUpstreamVersion());
        }

        @ParameterizedTest
        @DisplayName("should warn once, and ask nobody, when it can't compare the running version")
        @ValueSource(strings = {"unknown", "24.1", "24.1-libre-dev.20260920.abc1234", "v24.0-121-gd5cad31",
            "24.1-libre1-extra"})
        void warnsForUnknownRunningVersion(String running) throws IOException {
            LocalHttpServer server = server(200, modrinthVersions("99.0-libre1"));
            UpdateCheck check = check(running, modrinth(server));

            assertEquals(Optional.empty(), check.check());
            assertEquals(Optional.empty(), check.check());

            assertEquals(List.of(), server.getRequests());
            assertEquals(1, testLogger.countAtLevel(Level.WARNING));
            assertTrue(testLogger.hasMessageContaining(Level.WARNING, "Update checks can't compare versions: the running"
                + " version '" + running + "' isn't a LibreProtect version like 24.1-libre1"), testLogger.getMessages().toString());
        }

        @Test
        @DisplayName("should not warn about the running version when update checks are off")
        void noWarningWhenOff() throws IOException {
            check("unknown").check();
            assertFalse(testLogger.hasLevel(Level.WARNING));
        }

        @Test
        @DisplayName("should log one debug line per request with its outcome when verbose")
        void verboseLogging() throws IOException {
            LibreProtectLogger.setVerbose(true);
            LocalHttpServer missing = server(404, "{}");
            LocalHttpServer answering = server(200, modrinthVersions("24.1-libre2"));

            check("24.1-libre1", modrinth(missing), modrinth(answering)).check();

            List<String> lines = testLogger.getMessages();
            assertEquals(2, lines.size(), lines.toString());
            assertTrue(lines.get(0).contains("Update source Modrinth project libreprotect: GET "
                + missing.getBaseUrl() + "/v2/project/libreprotect/version?include_changelog=false -> failed: HTTP 404"),
                lines.get(0));
            assertTrue(lines.get(1).endsWith("-> newest release 24.1-libre2"), lines.get(1));
            assertTrue(lines.stream().allMatch(line -> line.contains("[DEBUG]")));
        }

        @Test
        @DisplayName("should log nothing when not verbose")
        void quiet() throws IOException {
            check("24.1-libre1", modrinth(server(404, "{}")), modrinth(server(200, modrinthVersions("24.1-libre2")))).check();

            assertEquals(List.of(), testLogger.getMessages());
            assertFalse(testLogger.hasLevel(Level.WARNING));
        }

        @Test
        @DisplayName("should ask nobody, fail and keep the release it knew once check-updates is off in config.yml")
        void checkUpdatesTurnedOff(@TempDir Path dataFolder) throws IOException {
            Path config = dataFolder.resolve("config.yml");
            Files.writeString(config, "use-mysql: false\ncheck-updates: true\n");
            LocalHttpServer server = server(200, modrinthVersions("24.1-libre2"));
            UpdateCheck check = new UpdateCheck(List.of(modrinth(server)), "24.1-libre1", config.toFile(),
                new UpdateHttp(2_000, 2_000, 5_000));
            assertEquals(Optional.of("24.1.1"), check.check());

            // As after /co reload, while CoreProtect's hourly check carries on
            Files.writeString(config, "use-mysql: false\ncheck-updates: false\n");
            IOException e = assertThrows(IOException.class, check::check);

            assertEquals("Update check skipped: check-updates is off in " + config, e.getMessage());
            assertEquals(1, server.getRequests().size());
            assertEquals("24.1-libre2", UpdateStatus.current().version());

            Files.writeString(config, "check-updates: true\n");
            assertEquals(Optional.of("24.1.1"), check.check());
            assertEquals(2, server.getRequests().size());
        }

        @Test
        @DisplayName("should ask nobody and fail when config.yml can't be read")
        void unreadableConfig(@TempDir Path dataFolder) throws IOException {
            Path config = Files.createDirectory(dataFolder.resolve("config.yml"));
            LocalHttpServer server = server(200, modrinthVersions("24.1-libre2"));

            IOException e = assertThrows(IOException.class, () -> new UpdateCheck(List.of(modrinth(server)), "24.1-libre1",
                config.toFile(), new UpdateHttp(2_000, 2_000, 5_000)).check());

            assertTrue(e.getMessage().startsWith("Update check skipped: couldn't read check-updates from "), e.getMessage());
            assertEquals(List.of(), server.getRequests());
        }

        @Test
        @DisplayName("should ask the sources when config.yml doesn't exist, as CoreProtect defaults to checking")
        void missingConfig(@TempDir Path dataFolder) throws IOException {
            LocalHttpServer server = server(200, modrinthVersions("24.1-libre2"));

            assertEquals(Optional.of("24.1.1"), new UpdateCheck(List.of(modrinth(server)), "24.1-libre1",
                dataFolder.resolve("config.yml").toFile(), new UpdateHttp(2_000, 2_000, 5_000)).check());
        }

        @Test
        @DisplayName("should treat an unexpected exception from a source as that source failing")
        void runtimeException() throws IOException {
            UpdateSource broken = new UpdateSource() {
                @Override
                public String type() {
                    return "broken";
                }

                @Override
                public String api() {
                    return "http://127.0.0.1:1";
                }

                @Override
                public String describe() {
                    return "Broken source";
                }

                @Override
                URL requestUrl() throws IOException {
                    return new URL(api() + "/");
                }

                @Override
                Optional<Release> newestRelease(UpdateHttp http) {
                    throw new IllegalStateException("a bug");
                }
            };
            LocalHttpServer answering = server(200, modrinthVersions("24.1-libre2"));

            assertEquals(Optional.of("24.1.1"), check("24.1-libre1", broken, modrinth(answering)).check());
        }
    }
}
