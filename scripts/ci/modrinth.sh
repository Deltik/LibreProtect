#!/usr/bin/env bash
# Copyright (C) 2026 Deltik <https://www.deltik.net/>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This file is part of LibreProtect.
#
# LibreProtect is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# LibreProtect is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with LibreProtect.  If not, see <https://www.gnu.org/licenses/>.

# Publish a GitHub release to Modrinth, and sync the Modrinth project's
# details. Safe to rerun: an existing version is only linked.
#
#   modrinth.sh <tag>
#
# Needs MODRINTH_TOKEN (scopes: PROJECT_READ, PROJECT_WRITE, VERSION_READ,
# VERSION_CREATE), MODRINTH_PROJECT_ID and GH_TOKEN.
#
# Upstream decides which Minecraft versions and server software a release
# supports: they are copied from the version that upstream published on
# Modrinth for the same CoreProtect release. So are the project's categories
# and environment. The description comes from README.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/lib/stores.sh
source "$ROOT/scripts/lib/stores.sh"

tag="${1:?release tag, such as v24.1-libre1}"
version="${tag#v}"
project="${MODRINTH_PROJECT_ID:?}"
: "${MODRINTH_TOKEN:?}"
# Upstream publishes to Modrinth separately. Give it this long before failing.
UPSTREAM_GRACE_HOURS=72

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
gh release download "$tag" --dir "$work" --pattern "LibreProtect-$version.jar" --pattern transform-report.json
jar="$work/LibreProtect-$version.jar"
upstream_ref="$(jq -r .upstreamRef "$work/transform-report.json")"

echo "==> Syncing the project's details"
upstream_project="$(modrinth GET "/project/$UPSTREAM_MODRINTH_PROJECT")"
store_description > "$work/body.md"
jq -n --argjson upstream "$upstream_project" --rawfile body "$work/body.md" \
    --arg summary "$STORE_SUMMARY" --arg repository "$REPOSITORY_URL" '{
        description: $summary,
        body: $body,
        categories: $upstream.categories,
        additional_categories: $upstream.additional_categories,
        client_side: $upstream.client_side,
        server_side: $upstream.server_side,
        license_id: "GPL-3.0-or-later",
        source_url: $repository,
        issues_url: ($repository + "/issues")
    }' > "$work/project.json"
modrinth PATCH "/project/$project" -H "Content-Type: application/json" --data-binary "@$work/project.json"
slug="$(modrinth GET "/project/$project" | jq -r .slug)"
url="https://modrinth.com/plugin/$slug/version/$version"

# A version that is already there, even one uploaded by hand, only needs linking
if modrinth GET "/project/$project/version" | jq -e --arg version "$version" 'any(.[]; .version_number == $version)' >/dev/null; then
    echo "==> Modrinth already has $version"
else
    upstream="$(upstream_modrinth_version "${upstream_ref#v}")"
    if [[ -z "$upstream" ]]; then
        published="$(gh release view "$tag" --json publishedAt --jq .publishedAt)"
        age_hours=$(( ($(date +%s) - $(date -d "$published" +%s)) / 3600 ))
        if (( age_hours < UPSTREAM_GRACE_HOURS )); then
            echo "::notice::CoreProtect $upstream_ref isn't on Modrinth yet, so its supported versions aren't known. upstream-watch tries again later."
            exit 0
        fi
        echo "::error::CoreProtect $upstream_ref still isn't on Modrinth after $age_hours hours. Upload $tag to Modrinth by hand, with the Minecraft versions from CoreProtect's release notes, and the next run links it."
        exit 1
    fi

    echo "==> Uploading $version"
    download="$REPOSITORY_URL/releases/download/$tag"
    cat > "$work/changelog.md" <<CHANGELOG
LibreProtect built from [CoreProtect $upstream_ref](https://github.com/PlayPro/CoreProtect/releases/tag/$upstream_ref). It replaces CoreProtect in place and unlocks every feature. By default, it sends no telemetry, license checks or error reports, and it only checks GitHub, then Modrinth if GitHub fails or names no LibreProtect release, for LibreProtect updates, without sending a version number, the server's port or a license key.

- [Release notes, checksums and build provenance]($REPOSITORY_URL/releases/tag/$tag)
- [How this build differs from CoreProtect]($download/DIFFERENCES.md)
- [Complete source code of this build]($download/LibreProtect-$version-sources.tar.gz)

LibreProtect is licensed under GPL-3.0-or-later. CoreProtect is by Intelli and its contributors, under the Artistic License 2.0.
CHANGELOG
    jq -n --arg project "$project" --arg version "$version" --rawfile changelog "$work/changelog.md" \
        --argjson upstream "$upstream" '{
            project_id: $project,
            name: ("LibreProtect " + $version),
            version_number: $version,
            changelog: $changelog,
            dependencies: [],
            game_versions: $upstream.game_versions,
            loaders: $upstream.loaders,
            version_type: "release",
            featured: true,
            status: "listed",
            file_parts: ["jar"],
            primary_file: "jar"
        }' > "$work/version.json"
    # Modrinth requires the data part before the files
    modrinth POST /version \
        -F "data=<$work/version.json;type=application/json" \
        -F "jar=@$jar;type=application/java-archive" > /dev/null
fi

echo "==> Linking the GitHub release to $url"
gh release view "$tag" --json body --jq .body > "$work/notes.md"
if ! grep -qF "$url" "$work/notes.md"; then
    printf '\nAlso on [Modrinth](%s).\n' "$url" >> "$work/notes.md"
    gh release edit "$tag" --notes-file "$work/notes.md"
fi
echo "Published $tag to $url"
