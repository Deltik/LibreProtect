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

# Fail unless the audit found nothing that needs review. Findings that need
# review don't stop development builds, but they must be accepted into
# audit/baseline.json before anything merges or is released.
set -euo pipefail

report="${1:?usage: require-reviewed.sh <audit-report.json>}"
[[ -f "$report" ]] || { echo "No audit report at $report" >&2; exit 1; }

if jq -e '.failed == false and .reviewRequired == false' "$report" >/dev/null; then
    echo "Audit is clean against audit/baseline.json"
    exit 0
fi

echo "The audit found upstream changes that need a maintainer's review:" >&2
jq -r '.findings[] | select(.severity != "INFO")
    | "  \(.severity) \(.rule) at \(.site): \(.detail)\(if .resolution == "ALLOW" then " [needs an allowance]" else "" end)"' \
    "$report" >&2
cat >&2 <<'EOF'

The job's summary, like scripts/lp review, shows what changed upstream that they name.
To accept them after review, update audit/baseline.json in this branch:
  - put this build's dist artifact in dist/ and run scripts/lp accept, which makes its upstream line
    what the build observed (with --licenses for a change to upstream's licensing), and
  - add an "allow" entry with a reason for each finding that needs an allowance.
EOF
exit 1
