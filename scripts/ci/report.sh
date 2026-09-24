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
# comment on it for repeat failures, close it on the next success.
#
#   report.sh <pipeline name> <true|false succeeded> <what was built>
set -euo pipefail

pipeline="${1:?pipeline name}"
succeeded="${2:?true or false}"
subject="${3:-}"
label="pipeline-failure"
title="$pipeline failing"
run_url="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"

existing="$(gh issue list --state open --label "$label" --limit 100 --json number,title \
    --jq ".[] | select(.title == \"$title\") | .number" 2>/dev/null | head -n 1 || true)"

if [[ "$succeeded" == "true" ]]; then
    if [[ -n "$existing" ]]; then
        gh issue close "$existing" --comment "Fixed: [$pipeline succeeded]($run_url) for $subject."
    fi
    exit 0
fi

if [[ "$pipeline" == "Distribution" ]]; then
    hints="- **Publish to Modrinth**: the log shows the request that failed and Modrinth's explanation, such as an expired \`MODRINTH_TOKEN\`.
- **Track the SpigotMC update**: SpigotMC's or Spiget's public API may have been unavailable. The next run of upstream-watch tries again."
else
    hints="- **CONTRACT VIOLATION** in the build step: upstream changed something that LibreProtect depends on. The message says what and where.
- **AUDIT FAILED** or **Require a reviewed audit baseline**: upstream added code that needs review; see the job summary.
- **Integration test**: see the \`integration-logs\` artifact."
fi

body="[$pipeline failed]($run_url) for $subject.

Open the run for the step that failed. Where to look:
$hints"

if [[ -n "$existing" ]]; then
    gh issue comment "$existing" --body "$body"
else
    gh label create "$label" --color B60205 --description "A LibreProtect pipeline is failing" 2>/dev/null || true
    gh issue create --title "$title" --label "$label" --body "$body"
fi
