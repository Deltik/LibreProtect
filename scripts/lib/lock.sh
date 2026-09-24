# shellcheck shell=bash
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

# Shared by scripts/lp and scripts/ci/*. Source it; don't run it.

# Read upstream.lock into UPSTREAM_REPO, UPSTREAM_TAG, UPSTREAM_SHA and
# FORK_REVISION. Only these keys are read, and the file is never executed.
read_lock() {
    local file="${1:?lock file}" key value
    while IFS='=' read -r key value; do
        [[ "$key" =~ ^[A-Z_]+$ ]] || continue
        case "$key" in
            UPSTREAM_REPO | UPSTREAM_TAG | UPSTREAM_SHA | FORK_REVISION) printf -v "$key" '%s' "$value" ;;
        esac
    done < "$file"
    [[ -n "${UPSTREAM_REPO:-}" && -n "${UPSTREAM_TAG:-}" && -n "${UPSTREAM_SHA:-}" && -n "${FORK_REVISION:-}" ]] \
        || { echo "error: $file must set UPSTREAM_REPO, UPSTREAM_TAG, UPSTREAM_SHA and FORK_REVISION" >&2; return 1; }
    [[ "$FORK_REVISION" =~ ^[1-9][0-9]*$ ]] || { echo "error: FORK_REVISION must be a positive integer" >&2; return 1; }
    [[ "$UPSTREAM_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "error: UPSTREAM_SHA must be a full commit SHA" >&2; return 1; }
}

# An upstream tag, or what git describe says about an upstream commit, as
# LibreProtect's versions begin: v24.1 is 24.1, and v24.0-121-gd5cad31 is
# 24.0-121-gd5cad31. A leading v before a digit goes, and each run of
# characters other than letters, digits, '.', '_' and '-' becomes one '-', so
# that Bukkit's plugin.yml version, Git tags and Modrinth's version numbers
# all take the name, whatever the tag. The tags that LibreProtect builds from,
# v and two or three numbers, need only the first step. Its update check
# (ForkVersion) reads only names from those, which scripts/lp checks.
version_name() {
    local name="$1"
    [[ "$name" =~ ^v[0-9] ]] && name="${name#v}"
    LC_ALL=C sed -E 's/[^A-Za-z0-9._-]+/-/g' <<<"$name"
}

# The GitHub release tag for the release that upstream.lock describes
release_tag() {
    printf 'v%s-libre%s' "$(version_name "$UPSTREAM_TAG")" "$FORK_REVISION"
}
