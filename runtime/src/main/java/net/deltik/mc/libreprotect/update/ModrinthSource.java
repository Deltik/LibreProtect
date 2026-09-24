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

import com.google.gson.stream.JsonToken;

import java.io.IOException;
import java.net.URL;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * A Modrinth project. Its newest release is the highest listed version of
 * type {@code release} whose version number is a LibreProtect release
 * version.
 *
 * <p>Modrinth answers 404 for a project that isn't approved yet, so the next
 * source is asked then.
 */
public final class ModrinthSource extends UpdateSource {

    static final String TYPE = "modrinth";
    static final String DEFAULT_API = "https://api.modrinth.com/v2";

    private static final String PAGE = "https://modrinth.com/plugin/";
    private static final Set<String> FIELDS = Set.of("version_number", "version_type", "status");

    private final String project;
    private final String api;

    /**
     * @param project a project ID or slug, checked by {@link UpdateSourceParser}
     * @param api     the API's base URL, without a final slash
     */
    ModrinthSource(String project, String api) {
        this.project = Objects.requireNonNull(project, "project");
        this.api = Objects.requireNonNull(api, "api");
    }

    /**
     * @return the project ID or slug
     */
    public String project() {
        return project;
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
        return "Modrinth project " + project;
    }

    @Override
    URL requestUrl() throws IOException {
        return new URL(api + "/project/" + project + "/version?include_changelog=false");
    }

    @Override
    Optional<Release> newestRelease(UpdateHttp http) throws IOException {
        String body = http.get(requestUrl(), Map.of("Accept", "application/json"));
        ForkVersion newest = Json.parse(body, reader -> {
            ForkVersion best = null;
            reader.beginArray();
            while (reader.hasNext()) {
                if (reader.peek() != JsonToken.BEGIN_OBJECT) {
                    reader.skipValue();
                    continue;
                }
                ForkVersion version = release(Json.scalars(reader, FIELDS));
                if (version != null && (best == null || ForkVersion.ORDER.compare(version, best) > 0)) {
                    best = version;
                }
            }
            reader.endArray();
            return best;
        });
        return newest == null
            ? Optional.empty()
            : Optional.of(new Release(newest, PAGE + project + "/version/" + newest));
    }

    /**
     * @return the version if it is a listed release, otherwise {@code null}
     */
    private static ForkVersion release(Map<String, String> version) {
        String status = version.get("status");
        if (!"release".equals(version.get("version_type")) || (status != null && !status.equals("listed"))) {
            return null;
        }
        return ForkVersion.parseRelease(version.get("version_number"));
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof ModrinthSource)) {
            return false;
        }
        ModrinthSource source = (ModrinthSource) other;
        return project.equals(source.project) && api.equals(source.api);
    }

    @Override
    public int hashCode() {
        return Objects.hash(TYPE, project, api);
    }
}
