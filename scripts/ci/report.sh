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

# Keep one open issue per failing pipeline: open it on the first failure,
# comment on it for repeat failures, close it on the next success. The issue
# names the jobs and steps of the run that failed, with the errors that their
# logs show, which needs the token to read actions.
#
#   report.sh <pipeline name> <true|false succeeded> <what was built>
#
# DRY_RUN=1 prints what it would do to the issue instead.
set -euo pipefail

pipeline="${1:?pipeline name}"
succeeded="${2:?true or false}"
subject="${3:-}"
label="pipeline-failure"
title="$pipeline failing"
run_url="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
# How many lines of errors to quote from each failed job's log
ERROR_LINES=20

existing="$(gh issue list --state open --label "$label" --limit 100 --json number,title \
    --jq ".[] | select(.title == \"$title\") | .number" 2>/dev/null | head -n 1 || true)"

if [[ "$succeeded" == "true" ]]; then
    if [[ "${DRY_RUN:-}" == 1 ]]; then
        printf 'DRY RUN: close issue #%s: Fixed: [%s succeeded](%s) for %s.\n' "${existing:-(none open)}" "$pipeline" \
            "$run_url" "$subject"
    elif [[ -n "$existing" ]]; then
        gh issue close "$existing" --comment "Fixed: [$pipeline succeeded]($run_url) for $subject."
    fi
    exit 0
fi

# Print stdin in a Markdown code block, fenced by more backquotes than any run of them in it
code_block() {
    local text fence
    text="$(cat)"
    fence="$(awk '{ while (match($0, /`+/)) { if (RLENGTH > longest) longest = RLENGTH; $0 = substr($0, RSTART + RLENGTH) } }
        END { for (i = 0; i < (longest < 3 ? 3 : longest + 1); i++) printf "`" }' <<<"$text")"
    printf '%s%s\n%s\n%s\n' "$fence" "$1" "$text" "$fence"
}

# The lines of a job's log that say what failed: GitHub's error annotations, other than a step's exit status;
# scripts/lp's errors; git's; the transformer's contract violations, failed audits and uncaught exceptions;
# Maven's failed goals, other than failed unit tests, which it lists, and compiler errors; and failed checks of the
# integration test
errors() {
    # Logs have colors, which newer versions of gh print only when told to, and older versions don't know the option
    { gh api --allow-escape-sequences "repos/$GITHUB_REPOSITORY/actions/jobs/$1/logs" 2>/dev/null \
        || gh api "repos/$GITHUB_REPOSITORY/actions/jobs/$1/logs" 2>/dev/null; } \
        | sed -E 's/^\xEF\xBB\xBF//; s/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z //; s/\x1B\[[0-9;]*[A-Za-z]//g' \
        | tr -d '\000-\010\013-\037' \
        | grep -aE '^(##\[error\]|error: |fatal: |CONTRACT VIOLATION|AUDIT FAILED|FAIL |\[ERROR\]   [^ ]|\[ERROR\] /|\[ERROR\] Failed to execute goal |Exception in thread |([a-z][A-Za-z0-9_]*\.)+[A-Z][A-Za-z0-9_$]*(Exception|Error)(: |$))' \
        | grep -avE '^(##\[error\]Process completed with exit code [0-9]+\.?|\[ERROR\]   mvn .*|\[ERROR\] Failed to execute goal .*: There are test failures\..*|org\.opentest4j\..*)$' \
        | awk '!seen[$0]++' | head -n "$ERROR_LINES" | LC_ALL=C.UTF-8 sed -E 's/^(.{300}).+$/\1.../' || true
}

# What failed, by job: its name, a link to it, the steps that failed, and their errors
failed=""
while IFS=$'\t' read -r id name url steps; do
    [[ -n "$id" ]] || continue
    failed+="Failed: [$name]($url)${steps:+ at $steps}"$'\n'
    lines="$(errors "$id")"
    if [[ -n "$lines" ]]; then
        failed+=$'\n'"$(code_block text <<<"$lines")"$'\n'
    fi
    failed+=$'\n'
done < <(gh run view "$GITHUB_RUN_ID" --repo "$GITHUB_REPOSITORY" --json jobs --jq '.jobs[]
    | select(.conclusion == "failure")
    | [.databaseId, (.name | gsub("[\t\n\\[\\]]"; " ")), .url,
        ([.steps[] | select(.conclusion == "failure") | "**\(.name | gsub("[\t\n*]"; " "))**"] | join(", "))]
    | join("\t")' 2>/dev/null || true)

if [[ "$pipeline" == "Distribution" ]]; then
    hints="- **Publish to Modrinth**: the log shows the request that failed and Modrinth's explanation, such as an expired \`MODRINTH_TOKEN\`.
- **Track the SpigotMC update**: SpigotMC's or Spiget's public API may have been unavailable. The next run of upstream-watch tries again."
else
    hints="- **CONTRACT VIOLATION** in the build step: upstream changed something that LibreProtect depends on. The message says what and where.
- **AUDIT FAILED** or **Require a reviewed audit baseline**: upstream added code that needs review, or changed its license; see the job summary.
- **Failed unit tests** in the build step: the job summary lists them, with their messages.
- **Integration test**: see the \`integration-logs\` artifact.
- **Source archive**: the build was made from a checkout with changes, so its source couldn't be archived. CI's License notices job names the files that a checkout changes."
fi

body="[$pipeline failed]($run_url) for $subject.

${failed:-Open the run for the step that failed.
}Where to look:
$hints"

if [[ "${DRY_RUN:-}" == 1 ]]; then
    printf 'DRY RUN: %s:\n\n%s\n' "$([[ -n "$existing" ]] && echo "comment on issue #$existing" \
        || echo "open the issue \"$title\"")" "$body"
elif [[ -n "$existing" ]]; then
    gh issue comment "$existing" --body "$body"
else
    gh label create "$label" --color B60205 --description "A LibreProtect pipeline is failing" 2>/dev/null || true
    gh issue create --title "$title" --label "$label" --body "$body"
fi
