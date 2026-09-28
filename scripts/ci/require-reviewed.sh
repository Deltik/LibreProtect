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
jq -r '.findings[] | select(.severity != "INFO") | "  \(.severity) \(.rule) at \(.site): \(.detail)"' "$report" >&2
cat >&2 <<'EOF'

To accept them after review, update audit/baseline.json in this branch:
  - copy the reviewed values from dist/audit-observed.json (in the build artifact); for
    "capabilities" and "licenses", add the reviewed key=value lines, keeping the other upstream line's, or
  - add an "allow" entry with a reason for a specific rule and site.
EOF
exit 1
