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

# Publish dist/ as a GitHub release. Safe to rerun: an existing release is
# left alone.
#
#   publish.sh                                  Release for upstream.lock
#   publish.sh --prerelease --upstream-ref REF  Development build, keeps the newest $KEEP_DEV
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST="$ROOT/dist"
KEEP_DEV=10

prerelease=false
upstream_ref=""
while (( $# )); do
    case "$1" in
        --prerelease) prerelease=true; shift ;;
        --upstream-ref) upstream_ref="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

version="$(cat "$DIST/version.txt")"
tag="v$version"
jar="$DIST/LibreProtect-$version.jar"
sources="$DIST/LibreProtect-$version-sources.tar.gz"
[[ -f "$jar" ]] || { echo "Missing $jar" >&2; exit 1; }
# The GPL requires the complete source alongside every JAR
[[ -f "$sources" ]] || { echo "Missing $sources; run scripts/lp sources" >&2; exit 1; }

if gh release view "$tag" >/dev/null 2>&1; then
    echo "Release $tag already exists"
    exit 0
fi

upstream_commit="$(jq -r .upstreamCommit "$DIST/transform-report.json")"
upstream_tag="$(jq -r .upstreamRef "$DIST/transform-report.json")"
notes="$(mktemp)"
{
    if $prerelease; then
        echo "Development build of [CoreProtect \`${upstream_commit:0:7}\`](https://github.com/PlayPro/CoreProtect/commit/$upstream_commit) (\`$upstream_ref\`). **Not for production servers:** it may include unreleased CoreProtect database changes."
    else
        echo "LibreProtect build of [CoreProtect $upstream_tag](https://github.com/PlayPro/CoreProtect/releases/tag/$upstream_tag)."
    fi
    echo
    echo "It's a drop-in replacement for CoreProtect: remove CoreProtect's JAR from \`plugins/\`, add this one, and restart. Your data and settings in \`plugins/CoreProtect/\` stay where they are. The network policy is in \`plugins/CoreProtect/libreprotect.yml\`; by default it blocks CoreProtect's telemetry, license checks and error reports, and only lets LibreProtect check GitHub, then Modrinth if GitHub fails or names no LibreProtect release, for its own updates, without sending a version number, the server's port or a license key."
    echo
    echo "Verify the download: \`sha256sum -c LibreProtect-$version.jar.sha256\` or \`gh attestation verify LibreProtect-$version.jar --repo $GITHUB_REPOSITORY\`."
    echo
    echo "License: GPL-3.0-or-later. CoreProtect, by Intelli and its contributors, is Artistic-2.0; this modified version is distributed under the GPL as section 4(c)(ii) of that license permits. \`$(basename "$sources")\` has the complete source of this build: LibreProtect and CoreProtect at the exact commits it was built from."
    echo
    if jq -e '.reviewRequired' "$DIST/audit-report.json" >/dev/null; then
        echo "### Audit Findings Not Yet Reviewed"
        echo
        jq -r '[.findings[] | select(.severity == "REVIEW")][:50][] | "- \(.rule) at `\(.site)`: \(.detail)"' "$DIST/audit-report.json"
        echo
    fi
    sed 's/^# /### /; s/^## /#### /' "$DIST/DIFFERENCES.md"
} > "$notes"

assets=("$jar" "$jar.sha256" "$sources" "$DIST/DIFFERENCES.md" "$DIST/audit-report.json" "$DIST/transform-report.json")
for sbom in "$DIST"/*.cdx.json; do
    [[ -f "$sbom" ]] && assets+=("$sbom")
done

args=(--title "LibreProtect $version" --notes-file "$notes" --target "$GITHUB_SHA")
if $prerelease; then
    args+=(--prerelease --latest=false)
else
    args+=(--latest)
fi
gh release create "$tag" "${args[@]}" "${assets[@]}"
echo "Published $tag"

if $prerelease; then
    # Development builds end in -libre-dev
    gh release list --limit 200 --json tagName,isPrerelease,createdAt \
        --jq '[.[] | select(.isPrerelease and (.tagName | test("-libre-dev$")))] | sort_by(.createdAt) | reverse | .['"$KEEP_DEV"':][] | .tagName' \
        | while read -r old; do
            echo "Pruning $old"
            gh release delete "$old" --yes --cleanup-tag
        done
fi
