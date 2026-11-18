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

# Let a Dependabot pull request merge by itself once CI passes, if all it
# changes is versions of Maven dependencies: in pom.xml files, and the Maven
# wrapper's distribution and checksum. Otherwise, make sure that it doesn't
# merge by itself, so that the maintainer reviews it: by failing, if it
# changes more than versions, and with a notice, if it updates the actions
# that workflows pin, whose changes to workflows GitHub lets no workflow's
# own token merge.
#
#   dependabot-merge.sh PULL_REQUEST_NUMBER
#
# DRY_RUN=1 prints what it would do instead, for a pull request in any state.
# Run by .github/workflows/dependabot.yml.
set -euo pipefail

number="${1:?usage: dependabot-merge.sh PULL_REQUEST_NUMBER}"
DRY_RUN="${DRY_RUN:-0}"

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

# Turn auto-merge off if an earlier push to the pull request turned it on.
# If that fails, so does this, loudly: the pull request must not merge.
disable_auto_merge() {
    trap - ERR
    if [[ "$(gh pr view "$number" --json autoMergeRequest --jq '.autoMergeRequest != null')" == "true" ]]; then
        act gh pr merge "$number" --disable-auto
    fi
}
trap 'disable_auto_merge; exit 1' ERR

pull="$(gh api "repos/{owner}/{repo}/pulls/$number")"
url="$(jq -r .html_url <<<"$pull")"
head_sha="$(jq -r .head.sha <<<"$pull")"
if [[ "$(jq -r .state <<<"$pull")" != "open" && "$DRY_RUN" != "1" ]]; then
    echo "$url isn't open"
    exit 0
fi

files="$(gh api --paginate "repos/{owner}/{repo}/pulls/$number/files" | jq -s 'add // []')"

# Why the pull request can't merge by itself, one reason a line
problems="$(jq -r \
    --arg author "$(jq -r .user.login <<<"$pull")" \
    --arg head "$(jq -r .head.repo.full_name <<<"$pull")" \
    --arg base "$(jq -r .base.repo.full_name <<<"$pull")" '
    # A line that the pull request may change in a kind of file
    def version_line($kind):
        if $kind == "workflow" then
            test("^[+-]\\s*(-\\s+)?uses:\\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}(\\s+#\\s*[0-9A-Za-z.+_-]+)?\\s*$")
        elif $kind == "pom" then
            test("^[+-]\\s*<(version|[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*\\.version)>[0-9A-Za-z.+_-]+</\\1>\\s*$")
        else
            test("^[+-](distributionUrl=https://repo\\.maven\\.apache\\.org/maven2/org/apache/maven/apache-maven/([0-9A-Za-z.+_-]+)/apache-maven-\\2-bin\\.zip|distributionSha256Sum=[0-9a-f]{64})$")
        end;
    # A changed line without its version, which an added line shares with the line it replaces
    def unversioned($kind):
        sub("^[+-]"; "")
        | if $kind == "workflow" then sub("@.*$"; "")
          elif $kind == "pom" then sub(">[^<]*<"; "><")
          else sub("=.*$"; "")
          end;
    # The patch as runs of removed lines and the added lines right after them,
    # each ended by any other line, such as an unchanged one, but not by a
    # note that a file ends without a newline
    def runs:
        reduce ((split("\n") | .[] | select(startswith("\\") | not)), "") as $line
            ({runs: [], run: {removed: [], added: []}};
            if ($line | startswith("-")) and (.run.added | length) == 0 then .run.removed += [$line]
            elif $line | startswith("+") then .run.added += [$line]
            else
                (if (.run.removed + .run.added | length) > 0 then .runs += [.run] else . end)
                | .run = {removed: [], added: []}
                | if $line | startswith("-") then .run.removed = [$line] else . end
            end)
        | .runs;
    if $author != "dependabot[bot]" then "It was opened by \($author), not Dependabot"
    elif $head != $base then "Its branch is in \($head), not \($base)"
    elif length == 0 then "It changes no files"
    else .[] | .filename as $file
        | (if $file | test("(^|/)pom\\.xml$") then "pom"
           elif $file == ".mvn/wrapper/maven-wrapper.properties" then "wrapper"
           elif $file | test("^\\.github/workflows/[^/]+\\.ya?ml$") then "workflow"
           else null end) as $kind
        | if $kind == null then "\($file): not a file whose versions Dependabot may change by itself"
          elif .status != "modified" then "\($file): \(.status), not only modified"
          elif .patch == null then "\($file): GitHub shows no diff of it"
          else
            (.patch | split("\n") | .[] | select(test("^[+-]")) | select(version_line($kind) | not)
                | "\($file): changes more than a version: \(.)"),
            # Each changed line replaces the line of the same dependency where it was
            (.patch | runs | .[]
                | select((.removed | length) != (.added | length)
                    or ([.removed[] | unversioned($kind)] != [.added[] | unversioned($kind)]))
                | "\($file): changes lines other than in place, or more than their versions: \(.removed + .added | join(" "))")
          end
    end' <<<"$files")"

if [[ -n "$problems" ]]; then
    while IFS= read -r problem; do
        echo "::error::$problem"
    done <<<"$problems"
    disable_auto_merge
    echo "::error::$url changes more than versions, so it doesn't merge by itself; the maintainer has to review it"
    exit 1
fi

# GitHub refuses a workflow's own token to merge changes to workflows
if jq -e 'any(.[]; .filename | test("^\\.github/workflows/"))' <<<"$files" >/dev/null; then
    disable_auto_merge
    echo "::notice::$url only changes versions, but of the actions that workflows pin, and GitHub lets no workflow's own token merge changes to workflows; the maintainer merges it once CI passes"
    exit 0
fi

echo "$url only changes versions; it merges by itself once CI passes"
act gh pr merge "$number" --auto --squash --match-head-commit "$head_sha"
