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

# Print a Markdown summary of the last build for $GITHUB_STEP_SUMMARY.
# No -e: this runs after failed steps too, and reports what it can.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST="$ROOT/dist"
AUDIT="$DIST/audit-report.json"
# How many bytes of scripts/lp review to show, well within the 1 MiB that a step summary may have
REVIEW_BYTES=600000

if [[ ! -f "$AUDIT" ]]; then
    echo "## No Build Output"
    echo
    echo "The build stopped before the transformer finished. See the job log."
    exit 0
fi

echo "## LibreProtect $(cat "$DIST/version.txt" 2>/dev/null || echo '(not written)')"
echo
jq -r '"Audit: \([.findings[] | select(.severity == "FAIL")] | length) fail, \([.findings[] | select(.severity == "REVIEW")] | length) review, \([.findings[] | select(.severity == "INFO")] | length) info"' "$AUDIT"
echo

if jq -e '[.findings[] | select(.severity != "INFO")] | length > 0' "$AUDIT" >/dev/null; then
    echo "| Severity | Rule | Where | Detail | Resolved by |"
    echo "|---|---|---|---|---|"
    jq -r '[.findings[] | select(.severity != "INFO")] | sort_by(.rule == "capability-change") | .[:100][] | "| \(.severity) | \(.rule) | `\(.site)` | \(.detail | gsub("\\|"; "\\\\|")) | \(if .resolution == "ACCEPT" then "accepting" else "an allowance" end) |"' "$AUDIT"
    echo
    jq -r '[.findings[] | select(.severity != "INFO")] | length | select(. > 100)
        | "\(. - 100) more findings are in `audit-report.json`, and `scripts/lp review` shows them all.\n"' "$AUDIT"
    echo "Accepting reviewed changes: put this build's output (in the \`dist\` artifact) in \`dist/\`, run \`scripts/lp accept\`, and commit \`audit/baseline.json\`. A finding resolved by an allowance needs an \`allow\` entry with a reason instead."
    echo

    # What changed upstream, as scripts/lp review shows it, without the findings again
    review="$("$ROOT/scripts/lp" review 2>/dev/null \
        | awk '/^Upstream `/ || /^## What Changed Upstream/ { show = 1 } /^## Findings/ { show = 0 } show')"
    if [[ -n "$review" ]]; then
        echo "<details><summary>What changed upstream that the findings name</summary>"
        echo
        # Whole sections, one per heading, so that a code block is never cut off
        LC_ALL=C awk -v max="$REVIEW_BYTES" '
            function flush() { if (used + length(section) <= max) { printf "%s", section; used += length(section) }
                else if (section ~ /^##### /) left++; section = "" }
            /^##+ / { flush() }
            { sub(/^## /, "#### "); sub(/^### /, "##### "); section = section $0 "\n" }
            END { flush(); if (left) print "\n" left " more " (left == 1 ? "file isn'\''t" : "files aren'\''t") \
                " shown here: run scripts/lp review." }' <<<"$review"
        echo
        echo "</details>"
        echo
    fi
fi

if [[ -f "$DIST/DIFFERENCES.md" ]]; then
    echo "<details><summary>How this build differs from CoreProtect</summary>"
    echo
    sed 's/^# /### /; s/^## /#### /' "$DIST/DIFFERENCES.md"
    echo
    echo "</details>"
fi
