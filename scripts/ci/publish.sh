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

# Publish dist/ on GitHub. Safe to rerun.
#
#   publish.sh               Release for upstream.lock; an existing release is left alone
#   publish.sh --prerelease  Development build, added to the one prerelease that
#                            development builds share, which keeps the newest $KEEP_DEV
#
# The prerelease of development builds is made once, on the commit of the
# first build to be published in it, and keeps its tag there. Its notes are
# written anew at each development build, from the builds that it has.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST="$ROOT/dist"
DEV_TAG=dev
DEV_TITLE="LibreProtect development builds"
KEEP_DEV=10

prerelease=false
while (( $# )); do
    case "$1" in
        --prerelease) prerelease=true; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

version="$(cat "$DIST/version.txt")"
jar="$DIST/LibreProtect-$version.jar"
sources="$DIST/LibreProtect-$version-sources.tar.gz"
[[ -f "$jar" ]] || { echo "Missing $jar" >&2; exit 1; }
# The GPL requires the complete source alongside every JAR
[[ -f "$sources" ]] || { echo "Missing $sources; run scripts/lp sources" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# How to install a build, and what it does on the network by default, beginning with $1
install_notes() {
    echo "$1 a drop-in replacement for CoreProtect: remove CoreProtect's JAR from \`plugins/\`, add this one, and restart. Your data and settings in \`plugins/CoreProtect/\` stay where they are. The network policy is in \`plugins/CoreProtect/libreprotect.yml\`; by default it blocks CoreProtect's telemetry, license checks and error reports, and only lets LibreProtect check GitHub, then Modrinth if GitHub fails or names no LibreProtect release, for its own updates, without sending a version number, the server's port or a license key."
}

license_notes() {
    echo "License: GPL-3.0-or-later. CoreProtect, by Intelli and its contributors, is Artistic-2.0; this modified version is distributed under the GPL as section 4(c)(ii) of that license permits."
}

publish_release() {
    local tag="v$version"
    if gh release view "$tag" >/dev/null 2>&1; then
        echo "Release $tag already exists"
        return
    fi

    local upstream_tag notes="$work/notes.md"
    upstream_tag="$(jq -r .upstreamRef "$DIST/transform-report.json")"
    {
        echo "LibreProtect build of [CoreProtect $upstream_tag](https://github.com/PlayPro/CoreProtect/releases/tag/$upstream_tag)."
        echo
        install_notes "It's"
        echo
        echo "Verify the download: \`sha256sum -c LibreProtect-$version.jar.sha256\` or \`gh attestation verify LibreProtect-$version.jar --repo $GITHUB_REPOSITORY\`."
        echo
        echo "$(license_notes) \`$(basename "$sources")\` has the complete source of this build: LibreProtect and CoreProtect at the exact commits it was built from."
        echo
        if jq -e '.reviewRequired' "$DIST/audit-report.json" >/dev/null; then
            echo "### Audit Findings Not Yet Reviewed"
            echo
            jq -r '[.findings[] | select(.severity == "REVIEW")] | sort_by(.rule == "capability-change") | .[:50][] | "- \(.rule) at `\(.site)`: \(.detail)"' "$DIST/audit-report.json"
            echo
        fi
        sed 's/^# /### /; s/^## /#### /' "$DIST/DIFFERENCES.md"
    } > "$notes"

    local assets=("$jar" "$jar.sha256" "$sources" "$DIST/DIFFERENCES.md" "$DIST/audit-report.json" "$DIST/transform-report.json")
    for sbom in "$DIST"/*.cdx.json; do
        [[ -f "$sbom" ]] && assets+=("$sbom")
    done
    gh release create "$tag" --title "LibreProtect $version" --notes-file "$notes" --target "$GITHUB_SHA" --latest \
        "${assets[@]}"
    echo "Published $tag"
}

publish_development() {
    local name
    name="$(basename "$jar")"

    if ! gh release view "$DEV_TAG" --json tagName >/dev/null 2>&1; then
        # Without assets, so that it's published at once; they follow as for any other build
        gh release create "$DEV_TAG" --prerelease --latest=false --title "$DEV_TITLE" --target "$GITHUB_SHA" \
            --notes "Development builds are on their way."
        echo "Made the $DEV_TAG prerelease"
    fi

    # An asset counts once its upload finished
    local present
    present="$(gh release view "$DEV_TAG" --json assets --jq '.assets[] | select(.state == "uploaded") | .name')"
    if grep -qxF "$name" <<<"$present"; then
        echo "$version is already in the $DEV_TAG prerelease"
    else
        # Each of a build's assets begins with its name, so that builds can share the release
        local stage="$work/stage" prefix="LibreProtect-$version" report
        mkdir "$stage"
        for report in DIFFERENCES.md audit-report.json transform-report.json; do
            cp "$DIST/$report" "$stage/$prefix-$report"
        done
        local assets=("$jar.sha256" "$sources" "$stage"/*)
        for sbom in "$DIST"/*.cdx.json; do
            [[ -f "$sbom" ]] && assets+=("$sbom")
        done
        # The JAR goes last, so that only a build that has all of its assets has a JAR
        gh release upload "$DEV_TAG" --clobber "${assets[@]}"
        gh release upload "$DEV_TAG" --clobber "$jar"
        echo "Published $version in the $DEV_TAG prerelease"
    fi

    local listing="$work/assets.json"
    gh release view "$DEV_TAG" --json assets > "$listing"
    # The builds to keep, newest first: those whose JARs were uploaded last
    # shellcheck disable=SC2016 # A jq program, whose variables are jq's
    local kept='(.assets | map(select(.state == "uploaded" and (.name | test("^LibreProtect-.+\\.jar$"))))
        | sort_by(.createdAt) | reverse
        | .[:$keep] | map({version: (.name | ltrimstr("LibreProtect-") | rtrimstr(".jar")), published: .createdAt}))'

    # The notes name only the builds to keep, so that none of their links lead to an asset that's gone
    write_development_notes "$listing" "$kept"

    # Every other asset goes: those of older builds, and of uploads that never finished
    jq -r --argjson keep "$KEEP_DEV" "$kept"' as $kept | .assets[].name
        | select(. as $name | $kept | any(("LibreProtect-" + .version) as $prefix
            | $name | startswith($prefix + ".") or startswith($prefix + "-")) | not)' "$listing" \
        | while read -r old; do
            echo "Removing $old"
            gh release delete-asset "$DEV_TAG" "$old" --yes
        done

    # Development builds had a prerelease each before they shared one
    gh release list --limit 200 --json tagName,isPrerelease \
        --jq '.[] | select(.isPrerelease and (.tagName | test("^v[0-9].*-libre-dev$"))) | .tagName' \
        | while read -r old; do
            echo "Removing the prerelease $old, since development builds share the $DEV_TAG prerelease"
            gh release delete "$old" --yes --cleanup-tag
        done
}

# Write the notes of the prerelease of development builds, from its listing
# of assets, and the jq expression that picks the builds that it keeps
write_development_notes() {
    local listing="$1" kept="$2" reports="$work/reports" notes="$work/notes.md"
    mkdir "$reports"
    gh release download "$DEV_TAG" --dir "$reports" --pattern '*-transform-report.json' --pattern '*-audit-report.json'

    local download="https://github.com/$GITHUB_REPOSITORY/releases/download/$DEV_TAG"
    {
        echo "<!-- scripts/ci/publish.sh writes these notes anew at each development build -->"
        echo "Development builds of CoreProtect's unreleased code, from its default branch, newest first. **Not for production servers:** they may include unreleased CoreProtect database changes that released versions of CoreProtect can't read yet."
        echo
        install_notes "Each is"
        echo
        echo "| Build | CoreProtect | LibreProtect | Published | Download | Reports | Audit findings not yet reviewed |"
        echo "|---|---|---|---|---|---|---|"
        local build build_version published transform audit upstream fork findings sbom
        jq -c --argjson keep "$KEEP_DEV" "$kept"' | .[]' "$listing" | while read -r build; do
            build_version="$(jq -r .version <<<"$build")"
            published="$(jq -r '.published | sub("T"; " ") | sub(":[0-9]{2}Z$"; " UTC")' <<<"$build")"
            transform="$reports/LibreProtect-$build_version-transform-report.json"
            audit="$reports/LibreProtect-$build_version-audit-report.json"
            upstream="$(jq -r .upstreamCommit "$transform")"
            fork="$(jq -r .forkCommit "$transform")"
            findings="$(jq '[.findings[] | select(.severity == "REVIEW")] | length' "$audit")"
            sbom=""
            if jq -e --arg name "LibreProtect-$build_version.cdx.json" 'any(.assets[]; .name == $name)' "$listing" >/dev/null; then
                sbom=" · [SBOM]($download/LibreProtect-$build_version.cdx.json)"
            fi
            # shellcheck disable=SC2016 # Backquotes in single quotes are Markdown's
            printf '| `%s` | [`%s`](https://github.com/PlayPro/CoreProtect/commit/%s) | [`%s`](https://github.com/%s/commit/%s) | %s | [JAR](%s) ([SHA-256](%s)) · [source](%s) | [differences](%s) · [audit](%s) · [transform](%s)%s | %s |\n' \
                "$build_version" "${upstream:0:7}" "$upstream" "${fork:0:7}" "$GITHUB_REPOSITORY" "${fork%-dirty}" "$published" \
                "$download/LibreProtect-$build_version.jar" "$download/LibreProtect-$build_version.jar.sha256" \
                "$download/LibreProtect-$build_version-sources.tar.gz" \
                "$download/LibreProtect-$build_version-DIFFERENCES.md" "$download/LibreProtect-$build_version-audit-report.json" \
                "$download/LibreProtect-$build_version-transform-report.json" "$sbom" "$findings"
        done
        echo
        echo "Only the newest $KEEP_DEV builds stay here. Builds are reproducible: to get an older one, check out its LibreProtect commit and run \`scripts/lp build --ref <ref>\` with the \`upstreamRef\` of its transform report, as the build was run."
        echo
        echo "Unlike releases, development builds are published before LibreProtect's maintainer has reviewed what their audits find in CoreProtect's changes. A build's audit report lists those findings, and its differences say how it differs from CoreProtect."
        echo
        echo "Verify a download: \`sha256sum -c LibreProtect-<build>.jar.sha256\` or \`gh attestation verify LibreProtect-<build>.jar --repo $GITHUB_REPOSITORY\`."
        echo
        echo "$(license_notes) Each build's \`LibreProtect-<build>-sources.tar.gz\` has its complete source: LibreProtect and CoreProtect at the exact commits it was built from. GitHub's own source code archives are of LibreProtect alone, at the commit that the \`$DEV_TAG\` tag was made on."
    } > "$notes"
    gh release edit "$DEV_TAG" --prerelease --title "$DEV_TITLE" --notes-file "$notes"
}

if $prerelease; then
    publish_development
else
    publish_release
fi
