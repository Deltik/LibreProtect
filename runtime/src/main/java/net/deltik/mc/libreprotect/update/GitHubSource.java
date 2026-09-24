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

import java.io.IOException;
import java.net.URL;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A GitHub repository. Its newest release is GitHub's latest release, which
 * is never a draft or prerelease, if its tag is a LibreProtect release
 * version with or without a leading {@code v}.
 *
 * <p>GitHub answers 404 for a repository without releases, so the next
 * source is asked then.
 */
public final class GitHubSource extends UpdateSource {

    static final String TYPE = "github";
    static final String DEFAULT_API = "https://api.github.com";
    static final String API_VERSION = "2022-11-28";

    private static final Set<String> FIELDS = Set.of("tag_name", "html_url", "draft", "prerelease");
    /** A release page to link to as it is; anything else is replaced with a page built from the tag */
    private static final Pattern RELEASE_PAGE = Pattern.compile("https://github\\.com/[A-Za-z0-9._~/-]{1,200}");

    private final String repository;
    private final String api;

    /**
     * @param repository {@code owner/name}, checked by {@link UpdateSourceParser}
     * @param api        the API's base URL, without a final slash
     */
    GitHubSource(String repository, String api) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.api = Objects.requireNonNull(api, "api");
    }

    /**
     * @return the repository, as {@code owner/name}
     */
    public String repository() {
        return repository;
    }

    @Override
    public String type() {
        return TYPE;
    }

    @Override
    public String api() {
        return api;
    }

    @Override
    public String describe() {
        return "GitHub repository " + repository;
    }

    @Override
    URL requestUrl() throws IOException {
        return new URL(api + "/repos/" + repository + "/releases/latest");
    }

    @Override
    Optional<Release> newestRelease(UpdateHttp http) throws IOException {
        String body = http.get(requestUrl(),
            Map.of("Accept", "application/vnd.github+json", "X-GitHub-Api-Version", API_VERSION));
        Map<String, String> release = Json.parse(body, reader -> Json.scalars(reader, FIELDS));
        if ("true".equals(release.get("draft")) || "true".equals(release.get("prerelease"))) {
            return Optional.empty();
        }

        String tag = release.get("tag_name");
        ForkVersion version = ForkVersion.parseRelease(tag != null && tag.startsWith("v") ? tag.substring(1) : tag);
        if (version == null) {
            return Optional.empty();
        }
        String page = release.get("html_url");
        if (page == null || !RELEASE_PAGE.matcher(page).matches()) {
            page = "https://github.com/" + repository + "/releases/tag/" + tag;
        }
        return Optional.of(new Release(version, page));
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof GitHubSource)) {
            return false;
        }
        GitHubSource source = (GitHubSource) other;
        return repository.equals(source.repository) && api.equals(source.api);
    }

    @Override
    public int hashCode() {
        return Objects.hash(TYPE, repository, api);
    }
}
