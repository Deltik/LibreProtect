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

# Shared by scripts/ci/modrinth.sh and scripts/ci/spigotmc.sh. Source it;
# don't run it.

REPOSITORY_URL="https://github.com/Deltik/LibreProtect"
USER_AGENT="Deltik/LibreProtect (+$REPOSITORY_URL)"
UPSTREAM_MODRINTH_PROJECT="coreprotect"
# shellcheck disable=SC2034 # Used by spigotmc.sh
UPSTREAM_SPIGOTMC_RESOURCE="8631"

# Shown on Modrinth under the title. Modrinth asks that it not repeat the title.
# shellcheck disable=SC2034 # Used by modrinth.sh
STORE_SUMMARY="A privacy-hardened build of CoreProtect, the block logging and rollback plugin, with no phoning home and every feature unlocked"

# Call Modrinth's API. Sends MODRINTH_TOKEN if it is set.
#   modrinth <method> <path under /v2> [curl arguments...]
modrinth() {
    local method="$1" path="$2"
    shift 2
    local auth=()
    [[ -n "${MODRINTH_TOKEN:-}" ]] && auth=(-H "Authorization: $MODRINTH_TOKEN")
    curl -sS --fail-with-body --retry 3 -X "$method" -A "$USER_AGENT" "${auth[@]}" \
        "https://api.modrinth.com/v2$path" "$@"
}

# The version that upstream published on Modrinth for a CoreProtect version
# number such as 24.1, as JSON, or nothing if there isn't one yet
upstream_modrinth_version() {
    modrinth GET "/project/$UPSTREAM_MODRINTH_PROJECT/version" \
        | jq --arg version "$1" 'first(.[] | select(.version_number == $version)) // empty'
}

# A SpigotMC resource as Spiget reports it, including its tested versions and languages
spiget_resource() {
    curl -sS --fail --retry 3 -A "$USER_AGENT" "https://api.spiget.org/v2/resources/$1"
}

# The upstream release that a LibreProtect release was built from, such as v24.1
release_upstream_ref() {
    gh release download "$1" --pattern transform-report.json --output - | jq -r .upstreamRef
}

# The user-facing parts of the README, marked with "begin store description"
# and "end store description" comments, with links that work outside GitHub
store_description() {
    awk '/<!-- end store description -->/ {keep = 0} keep {print} /<!-- begin store description -->/ {keep = 1; if (blocks++) print ""}' \
        "$ROOT/README.md" \
        | perl -pe 's{\]\(#}{]($ENV{REPOSITORY_URL}#}g; s{\]\((?![a-z]+:|#)([^)]+)\)}{]($ENV{REPOSITORY_URL}/blob/main/$1)}g'
    printf '\nSource code, documentation and issues: %s\n' "$REPOSITORY_URL"
}
export REPOSITORY_URL
