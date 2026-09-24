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

# Reconcile LibreProtect with upstream CoreProtect and the stores it is
# published to. Run by .github/workflows/upstream-watch.yml; every step is
# idempotent. It fails, after reconciling everything else, while upstream has
# a newer release under a kind of tag that LibreProtect can't build, or if it
# couldn't open an issue.
#
#   upstream-watch.sh
#
# DRY_RUN=1 prints each action instead of taking it. LOCK_FILE overrides
# upstream.lock, e.g. to see what would happen after an older release.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=scripts/lib/lock.sh
source "$ROOT/scripts/lib/lock.sh"
LOCK_FILE="${LOCK_FILE:-$ROOT/upstream.lock}"
DRY_RUN="${DRY_RUN:-0}"
read_lock "$LOCK_FILE"

upstream_slug="$(sed -E 's#^https://github\.com/##; s#\.git$##' <<<"$UPSTREAM_REPO")"
remote_refs="$(git ls-remote --tags --heads "$UPSTREAM_REPO")"
default_branch="$(git ls-remote --symref "$UPSTREAM_REPO" HEAD | awk '/^ref:/ {sub("refs/heads/", "", $2); print $2}')"

# Take an action, or only describe it in a dry run
act() {
    if [[ "$DRY_RUN" == "1" ]]; then
        printf 'DRY RUN:'
        printf ' %q' "$@"
        printf '\n'
    else
        "$@"
    fi
}

# Commit a ref points to, peeling annotated tags
ref_sha() {
    local peeled
    peeled="$(awk -v ref="$1^{}" '$2 == ref {print $1}' <<<"$remote_refs")"
    if [[ -n "$peeled" ]]; then
        printf '%s' "$peeled"
    else
        awk -v ref="$1" '$2 == ref {print $1}' <<<"$remote_refs"
    fi
}

# Open an issue with this title unless one is already open. If that fails, the
# rest still runs, and the run fails at the end.
unopened_issues=()
open_issue() {
    local title="$1" body="$2" label="upstream"
    if gh issue list --state open --label "$label" --limit 100 --json title --jq '.[].title' 2>/dev/null \
        | grep -qxF "$title"; then
        return
    fi
    act gh label create "$label" --color 1D76DB --description "Changes in upstream CoreProtect" 2>/dev/null || true
    if ! act gh issue create --title "$title" --label "$label" --body "$body"; then
        echo "::warning::Could not open the issue \"$title\""
        unopened_issues+=("$title")
    fi
}

# Whether a workflow has a queued or running run
workflow_busy() {
    local busy
    busy="$(gh run list --workflow "$1" --limit 20 --json status \
        --jq '[.[] | select(.status != "completed")] | length' 2>/dev/null || echo 0)"
    [[ "$busy" != "0" ]]
}

echo "::group::Pinned release tag"
current_sha="$(ref_sha "refs/tags/$UPSTREAM_TAG")"
if [[ -z "$current_sha" ]]; then
    open_issue "Upstream release tag $UPSTREAM_TAG disappeared" \
        "\`$UPSTREAM_TAG\`, pinned in \`upstream.lock\` at \`$UPSTREAM_SHA\`, no longer exists in $UPSTREAM_REPO. Builds keep using the pinned commit only if it is still reachable; find out why the tag was removed."
elif [[ "$current_sha" != "$UPSTREAM_SHA" ]]; then
    open_issue "Upstream release tag $UPSTREAM_TAG moved" \
        "\`$UPSTREAM_TAG\` in $UPSTREAM_REPO now points to \`$current_sha\`, but \`upstream.lock\` pins \`$UPSTREAM_SHA\`. A published release was changed after the fact. Compare the two commits before trusting it: https://github.com/$upstream_slug/compare/$UPSTREAM_SHA...$current_sha"
else
    echo "$UPSTREAM_TAG still points to $UPSTREAM_SHA"
fi
echo "::endgroup::"

echo "::group::Release for upstream.lock"
tag="$(release_tag)"
last_failed="$(gh run list --workflow release.yml --branch main --limit 1 --json headSha,conclusion \
    --jq ".[] | select(.headSha == \"${GITHUB_SHA:-}\" and .conclusion == \"failure\") | .headSha" 2>/dev/null || true)"
if gh release view "$tag" >/dev/null 2>&1; then
    echo "$tag is published"
elif workflow_busy release.yml; then
    echo "$tag is being released"
elif [[ -n "$last_failed" ]]; then
    echo "The last release attempt for this commit failed; its issue tracks it"
else
    echo "Releasing $tag"
    act gh workflow run release.yml --ref main
fi
echo "::endgroup::"

echo "::group::New upstream release"
# Release tags that LibreProtect can build and name: v and two or three numbers, as its update check reads them
supported='^v[0-9]+\.[0-9]+(\.[0-9]+)?$'
tags="$(grep -oE 'refs/tags/v[0-9][^^]*$' <<<"$remote_refs" | sed 's#refs/tags/##' | sort -uV || true)"
latest_tag="$(grep -E "$supported" <<<"$tags" | tail -n 1 || true)"
# A release under another kind of tag, newer than those, can't be built; say so rather than ignore it
unsupported=""
while IFS= read -r tag; do
    [[ -n "$tag" && "$(printf '%s\n%s\n' "${latest_tag:-$UPSTREAM_TAG}" "$tag" | sort -V | tail -n 1)" == "$tag" ]] || continue
    if [[ "$(gh api "repos/$upstream_slug/releases/tags/$tag" --jq '(.draft or .prerelease) | not' 2>/dev/null || echo false)" == "true" ]]; then
        unsupported="$tag"
        echo "::error::CoreProtect released $tag, but LibreProtect only builds release tags of v and two or three numbers, such as v24.1"
        open_issue "Upstream release $tag has a tag that LibreProtect can't build" \
            "CoreProtect [$tag](https://github.com/$upstream_slug/releases/tag/$tag) was released, but LibreProtect only builds and names releases whose tags are \`v\` and two or three numbers, such as \`v24.1\`: its versions, its update check (\`ForkVersion\`) and \`scripts/lp\` read no other kind. Decide how LibreProtect should name this release, then support that kind of tag in \`scripts/lp\`, \`ForkVersion\` and \`scripts/ci/upstream-watch.sh\`. Until then, upstream-watch fails."
    else
        echo "$tag is tagged, but isn't a release"
    fi
done < <(grep -vE "$supported" <<<"$tags" || true)
newest="$(printf '%s\n%s\n' "$UPSTREAM_TAG" "$latest_tag" | sort -V | tail -n 1)"
if [[ -z "$latest_tag" || "$newest" == "$UPSTREAM_TAG" ]]; then
    echo "No upstream release newer than $UPSTREAM_TAG"
elif [[ "$(gh api "repos/$upstream_slug/releases/tags/$latest_tag" --jq '(.draft or .prerelease) | not' 2>/dev/null || echo false)" != "true" ]]; then
    echo "$latest_tag is tagged but not published as a release yet"
else
    branch="upstream/$latest_tag"
    if [[ -n "$(gh pr list --head "$branch" --state open --json number --jq '.[].number' 2>/dev/null || true)" ]]; then
        echo "Pull request for $latest_tag is already open"
    else
        latest_sha="$(ref_sha "refs/tags/$latest_tag")"
        echo "Opening a pull request for $latest_tag ($latest_sha)"
        act git config user.name "github-actions[bot]"
        act git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
        act git checkout -B "$branch"
        act sed -i -E "s/^UPSTREAM_TAG=.*/UPSTREAM_TAG=$latest_tag/; s/^UPSTREAM_SHA=.*/UPSTREAM_SHA=$latest_sha/; s/^FORK_REVISION=.*/FORK_REVISION=1/" "$LOCK_FILE"
        act git commit -q -am "Build LibreProtect from CoreProtect $latest_tag"
        act git push -q --force origin "$branch"
        act gh label create upstream --color 1D76DB --description "Changes in upstream CoreProtect" 2>/dev/null || true
        act gh pr create --base main --head "$branch" --label upstream \
            --title "Build LibreProtect from CoreProtect $latest_tag" \
            --body "CoreProtect [$latest_tag](https://github.com/$upstream_slug/releases/tag/$latest_tag) was released ([changes](https://github.com/$upstream_slug/compare/$UPSTREAM_TAG...$latest_tag)).

This pull request merges by itself once CI passes. CI passes only if the transformer finds everything it needs, LibreProtect makes no network requests on a real server, and the audit finds nothing unreviewed. If the audit needs review, the job summary lists what changed; accept it by updating \`audit/baseline.json\` in this branch.

Merging releases LibreProtect v$(version_name "$latest_tag")-libre1."
        act gh pr merge "$branch" --auto --squash || echo "::warning::Could not enable auto-merge; merge by hand once CI passes"
        act gh workflow run ci.yml --ref "$branch"
        act git checkout -q -
    fi
fi
echo "::endgroup::"

echo "::group::Development build"
if [[ -z "$default_branch" ]]; then
    echo "::warning::Could not find upstream's default branch"
else
    head_sha="$(ref_sha "refs/heads/$default_branch")"
    dev_runs="$(gh run list --workflow dev.yml --limit 50 --json displayTitle \
        --jq "[.[] | select(.displayTitle | endswith(\"$head_sha\"))] | length" 2>/dev/null || echo 0)"
    # Development builds are named after git describe, such as v24.0-121-gd5cad31-libre-dev,
    # whose commit has at least 7 characters
    if gh release list --limit 100 --json tagName --jq '.[].tagName' 2>/dev/null \
        | grep -qE -- "-g${head_sha:0:7}[0-9a-f]*-libre-dev\$"; then
        echo "Development build of $default_branch ($head_sha) is published"
    elif [[ "$dev_runs" != "0" ]]; then
        echo "Development build of $head_sha already ran or is running"
    else
        echo "Building $default_branch at $head_sha"
        act gh workflow run dev.yml --ref main -f ref="$head_sha"
    fi
fi
echo "::endgroup::"

echo "::group::Distribution"
newest_release="$(gh release list --exclude-pre-releases --limit 1 --json tagName --jq '.[0].tagName // empty' 2>/dev/null || true)"
if [[ -z "$newest_release" ]]; then
    echo "Nothing released yet"
else
    if [[ -z "${MODRINTH_PROJECT_ID:-}" ]]; then
        echo "Modrinth isn't set up"
    elif gh release view "$newest_release" --json body --jq .body | grep -qF "modrinth.com/plugin/"; then
        echo "$newest_release is on Modrinth"
    else
        # Upstream's own Modrinth upload can lag behind, so keep retrying, but not on every run
        recent="$(gh run list --workflow distribute.yml --limit 20 --json displayTitle,createdAt \
            --jq "[.[] | select(.displayTitle == \"Distribute $newest_release\" and (.createdAt | fromdateiso8601) > now - 7200)] | length" \
            2>/dev/null || echo 0)"
        if [[ "$recent" != "0" ]]; then
            echo "Distribution of $newest_release ran in the last two hours"
        else
            echo "Distributing $newest_release"
            act gh workflow run distribute.yml --ref main -f tag="$newest_release"
        fi
    fi
    if [[ -n "${SPIGOTMC_RESOURCE_ID:-}" ]]; then
        DRY_RUN="$DRY_RUN" scripts/ci/spigotmc.sh "$newest_release"
    else
        echo "SpigotMC isn't set up"
    fi
fi
echo "::endgroup::"

# GitHub disables scheduled workflows after 60 days without repository
# activity. Cycling the workflow once a month resets that clock.
if [[ "$(date -u +%d%H)" == "0100" ]] && (( 10#$(date -u +%M) < 30 )); then
    echo "Monthly keepalive"
    act gh workflow disable upstream-watch.yml
    act gh workflow enable upstream-watch.yml
fi

# Only after everything else is reconciled
for title in "${unopened_issues[@]}"; do
    echo "::error::Could not open the issue \"$title\""
done
if [[ -n "$unsupported" ]]; then
    echo "::error::CoreProtect released $unsupported under a tag that LibreProtect can't build; see the issue about it"
fi
if [[ -n "$unsupported" ]] || (( ${#unopened_issues[@]} > 0 )); then
    exit 1
fi
