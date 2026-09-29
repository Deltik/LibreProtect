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

DIST="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/dist"
AUDIT="$DIST/audit-report.json"

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
    echo "Accepting reviewed changes: put this build's output (in the \`dist\` artifact) in \`dist/\`, run \`scripts/lp accept\`, and commit \`audit/baseline.json\`. A finding resolved by an allowance needs an \`allow\` entry with a reason instead."
    echo
fi

if [[ -f "$DIST/DIFFERENCES.md" ]]; then
    echo "<details><summary>How this build differs from CoreProtect</summary>"
    echo
    sed 's/^# /### /; s/^## /#### /' "$DIST/DIFFERENCES.md"
    echo
    echo "</details>"
fi
