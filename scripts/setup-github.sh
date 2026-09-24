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

# One-time setup of the GitHub repository that runs LibreProtect's pipelines.
# Needs repository admin rights (gh auth login). Safe to rerun.
#
#   scripts/setup-github.sh OWNER/REPO
#
# Run it after the first push, since branch protection needs main to exist.
#
# To publish releases to the stores too, set these when running it:
#   MODRINTH_PROJECT_ID   Modrinth project ID. You are asked for a Modrinth
#                         personal access token with the scopes PROJECT_READ,
#                         PROJECT_WRITE, VERSION_READ and VERSION_CREATE.
#   SPIGOTMC_RESOURCE_ID  SpigotMC resource ID, for the issues that track its updates
set -euo pipefail

repo="${1:?usage: setup-github.sh OWNER/REPO}"

echo "==> Repository settings"
gh repo edit "$repo" \
    --enable-auto-merge \
    --delete-branch-on-merge \
    --enable-squash-merge \
    --enable-merge-commit=false \
    --enable-rebase-merge=false

echo "==> Private vulnerability reporting (see .github/SECURITY.md)"
gh api -X PUT "repos/$repo/private-vulnerability-reporting" >/dev/null

echo "==> Let workflows open pull requests (upstream-watch's bump pull requests)"
# GitHub has one setting for "create and approve". Approvals from workflows
# still can't satisfy the code owner review that /audit/ changes require.
gh api -X PUT "repos/$repo/actions/permissions/workflow" \
    -f default_workflow_permissions=read -F can_approve_pull_request_reviews=true

echo "==> Labels"
gh label create pipeline-failure --repo "$repo" --force --color B60205 --description "A LibreProtect pipeline is failing"
gh label create upstream --repo "$repo" --force --color 1D76DB --description "Changes in upstream CoreProtect"
gh label create spigotmc --repo "$repo" --force --color E8A33D --description "Releases that SpigotMC doesn't show yet"

echo "==> Release environment (add required reviewers in Settings > Environments to approve each release)"
gh api -X PUT "repos/$repo/environments/release" >/dev/null

if [[ -n "${MODRINTH_PROJECT_ID:-}" ]]; then
    echo "==> Modrinth"
    gh variable set MODRINTH_PROJECT_ID --repo "$repo" --body "$MODRINTH_PROJECT_ID"
    # Only workflows on protected branches (main) can use the token
    gh api -X PUT "repos/$repo/environments/modrinth" --input - >/dev/null <<'JSON'
{"deployment_branch_policy": {"protected_branches": true, "custom_branch_policies": false}}
JSON
    gh secret set MODRINTH_TOKEN --repo "$repo" --env modrinth
fi

if [[ -n "${SPIGOTMC_RESOURCE_ID:-}" ]]; then
    echo "==> SpigotMC"
    gh variable set SPIGOTMC_RESOURCE_ID --repo "$repo" --body "$SPIGOTMC_RESOURCE_ID"
fi

echo "==> Branch protection for main"
gh api -X PUT "repos/$repo/branches/main/protection" --input - >/dev/null <<'JSON'
{
  "required_status_checks": {"strict": true, "checks": [{"context": "Build, test and audit"}, {"context": "License notices"}]},
  "enforce_admins": false,
  "required_pull_request_reviews": {"required_approving_review_count": 0, "require_code_owner_reviews": true},
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON

echo "Done. upstream-watch runs every 30 minutes; run it now with: gh workflow run upstream-watch.yml --repo $repo"
