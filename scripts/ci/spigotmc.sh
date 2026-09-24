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

# Track a release's SpigotMC update in an issue that stays open until
# SpigotMC shows the release.
#
#   spigotmc.sh <tag>
#
# The issue lists the update's details: its version string, title, file URL
# and message, and the tested Minecraft versions and languages, which follow
# upstream's, each compared with what the resource has now. It closes once
# SpigotMC's public API reports the new version, or once a newer release
# supersedes it.
#
# Needs SPIGOTMC_RESOURCE_ID and GH_TOKEN. DRY_RUN=1 prints the issue instead
# of opening it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/lib/stores.sh
source "$ROOT/scripts/lib/stores.sh"

tag="${1:?release tag, such as v24.1-libre1}"
version="${tag#v}"
resource="${SPIGOTMC_RESOURCE_ID:?}"
DRY_RUN="${DRY_RUN:-0}"
label="spigotmc"
title="LibreProtect $version on SpigotMC"
resource_url="https://www.spigotmc.org/resources/$resource/"

spigot_resource() {
    # The query parameter that changes every time bypasses SpigotMC's day-long API cache
    curl -sS --fail --retry 3 -A "$USER_AGENT" \
        "https://api.spigotmc.org/simple/0.2/index.php?action=getResource&id=$1&t=$(date +%s)"
}

current="$(spigot_resource "$resource" | jq -r .current_version)"
open_issues="$(gh issue list --state open --label "$label" --limit 100 --json number,title)"

# Issues for older versions are superseded, and this one is done once SpigotMC has it
jq -r --arg title "$title" --arg current "$current" --arg version "$version" \
    '.[] | select(.title != $title or $current == $version) | "\(.number)\t\(.title == $title)"' <<<"$open_issues" \
    | while IFS=$'\t' read -r number is_current; do
        if [[ "$is_current" == "true" ]]; then
            comment="SpigotMC shows LibreProtect $current."
        else
            comment="Superseded by LibreProtect $version."
        fi
        if [[ "$DRY_RUN" == "1" ]]; then
            echo "DRY RUN: close issue #$number: $comment"
        else
            gh issue close "$number" --comment "$comment"
        fi
    done

if [[ "$current" == "$version" ]]; then
    echo "SpigotMC has LibreProtect $version"
    exit 0
fi

upstream_ref="$(release_upstream_ref "$tag")"
upstream="$(upstream_modrinth_version "${upstream_ref#v}")"
download="$REPOSITORY_URL/releases/download/$tag"
ours="$(spiget_resource "$resource")"
theirs="$(spiget_resource "$UPSTREAM_SPIGOTMC_RESOURCE")"

current_tested="$(jq -r '.testedVersions | join(", ")' <<<"$ours")"
upstream_tested="$(jq -r '.testedVersions | join(", ")' <<<"$theirs")"
languages="$(jq -r '.supportedLanguages' <<<"$theirs")"
current_languages="$(jq -r '.supportedLanguages' <<<"$ours")"

# A detail's value $1, compared with the resource's value $2
compared() {
    if [[ "$1" == "$2" ]]; then printf '%s (as the resource has now)' "$1"; else printf '%s (the resource has %s now)' "$1" "$2"; fi
}

# SpigotMC's tested Minecraft versions, from the versions upstream declares on Modrinth:
# 1.x.y counts as 1.x (except 1.20.5 and 1.20.6, which SpigotMC lists as 1.20.6) and 26.x.y as 26.x
if [[ -n "$upstream" ]]; then
    tested="$(jq -r '[.game_versions[]
        | if test("^1\\.20\\.[56]$") then "1.20.6" else capture("^(?<major>[0-9]+\\.[0-9]+)").major end]
        | unique_by(split(".") | map(tonumber)) | join(", ")' <<<"$upstream")"
    tested="$(compared "$tested" "$current_tested"). These are the versions that CoreProtect $upstream_ref declares on Modrinth. CoreProtect's SpigotMC page lists $upstream_tested."
else
    tested="not known yet, since CoreProtect $upstream_ref isn't on Modrinth yet; its release notes name them. The resource has $current_tested now, and CoreProtect's SpigotMC page lists $upstream_tested."
fi

body="$(cat <<EOF
[LibreProtect $version]($REPOSITORY_URL/releases/tag/$tag) is out, and [SpigotMC]($resource_url) shows $current. This issue closes once SpigotMC shows $version.

The update's details:

- **Version string:** \`$version\`
- **Update title:** \`LibreProtect $version\`
- **File URL:** $download/LibreProtect-$version.jar
- **Update message:**
  \`\`\`
  Built from [URL=https://github.com/PlayPro/CoreProtect/releases/tag/$upstream_ref]CoreProtect ${upstream_ref}[/URL].

  [LIST]
  [*][URL=$REPOSITORY_URL/releases/tag/$tag]Release notes, checksums and build provenance[/URL]
  [*][URL=$download/DIFFERENCES.md]How this build differs from CoreProtect[/URL]
  [*][URL=$download/LibreProtect-$version-sources.tar.gz]Complete source code of this build[/URL]
  [/LIST]
  \`\`\`
- **Tested Minecraft versions:** $tested
- **Languages:** $(compared "$languages" "$current_languages"), from CoreProtect's SpigotMC page.
EOF
)"

existing="$(jq -r --arg title "$title" '.[] | select(.title == $title) | .number' <<<"$open_issues" | head -n 1)"
if [[ "$DRY_RUN" == "1" ]]; then
    printf 'DRY RUN: %s issue "%s":\n%s\n' "$([[ -n "$existing" ]] && echo "update #$existing" || echo open)" "$title" "$body"
elif [[ -z "$existing" ]]; then
    gh label create "$label" --color E8A33D --description "Releases that SpigotMC doesn't show yet" 2>/dev/null || true
    gh issue create --title "$title" --label "$label" --body "$body"
elif [[ "$(gh issue view "$existing" --json body --jq .body)" != "$body" ]]; then
    gh issue edit "$existing" --body "$body"
fi
