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

# Check that LibreProtect's source files begin with its license notice, the
# text of scripts/license-header.txt, or add the notice where it's missing.
#
#   license-headers.sh           Check the files in the working tree that Git
#                                tracks, or would track since they aren't ignored
#   license-headers.sh --fix     Add the notice to those of them that have none.
#                                A file with another notice is reported instead.
#   license-headers.sh --staged  Check the staged content of the files that the
#                                next commit adds or changes (.githooks/pre-commit)
#
# It fails with status 2 if Git can't list or read the files, and, without
# --staged, if it finds no file to check.
#
# Java files, shell scripts and Python scripts are covered: *.java, *.sh,
# *.py, *.pyi, scripts/lp, and any other file with an sh, bash, python or
# uv run shebang, except the paths in excluded(). A Java file begins with the
# notice as a /* */ comment. A shell or Python script has it as # comments
# after its shebang and any shellcheck directives that follow the shebang, or
# after a "# shellcheck shell=" directive that stands in for one. A blank
# line follows the notice.
#
# {YEAR} in the text may be one year or a range, such as 2026 or 2026-2027.
# --fix writes the current year.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEMPLATE="scripts/license-header.txt"
YEAR_FIELD="{YEAR}"
# Lines read from the top of each file: the notice after a shebang, and
# room for another notice before the code starts
WINDOW=80
SHEBANG='^#![[:space:]]*(/usr/bin/env[[:space:]]+(-S[[:space:]]+)?)?(/[^[:space:]]*/)?((ba)?sh|python[0-9.]*|uv[[:space:]]+run)([[:space:]]|$)'
# What another license notice says, in lowercase
OTHER_NOTICE='copyright|spdx-license-identifier|public license|licensed under'

die() { printf 'error: %s\n' "$*" >&2; exit 2; }

usage() {
    printf 'Usage: %s [--fix | --staged]\n' "${0##*/}"
    printf 'Checks that Java files, shell scripts and Python scripts begin with the license notice in %s.\n' "$TEMPLATE"
    printf '  --fix     Add the notice to files that have none\n'
    printf '  --staged  Check the staged files that the next commit adds or changes\n'
}

# Whether a path is left out: code that LibreProtect didn't write, files
# whose exact bytes matter, and build output
excluded() {
    case "$1" in
        # The Maven wrapper, Apache-2.0 from the Maven project
        mvnw | mvnw.cmd | .mvn/*) return 0 ;;
        # Resources, which the JARs contain byte for byte
        resources/* | */resources/*) return 0 ;;
        # Build output, which Git ignores anyway
        build/* | dist/* | target/* | */target/*) return 0 ;;
    esac
    return 1
}

# Set KIND to how path $1 takes comments: java, shell (# comments, which
# Python scripts take too), or empty if the path isn't covered. Without the
# path's first line as $2, KIND is unknown if only that can tell.
classify() {
    KIND=""
    if excluded "$1"; then
        return 0
    fi
    case "$1" in
        *.java) KIND=java ;;
        *.sh | *.py | *.pyi | scripts/lp) KIND=shell ;;
        *)
            if (( $# < 2 )); then
                KIND=unknown
            elif [[ "$2" =~ $SHEBANG ]]; then
                KIND=shell
            fi
            ;;
    esac
}

# Whether line $1 of a file matches line $2 of the notice, where $YEAR_FIELD
# stands for a year or a range of years
matches() {
    local actual="$1" expected="$2"
    if [[ "$expected" != *"$YEAR_FIELD"* ]]; then
        [[ "$actual" == "$expected" ]]
        return
    fi
    local before="${expected%%"$YEAR_FIELD"*}" after="${expected#*"$YEAR_FIELD"}"
    [[ "$actual" =~ ^"$before"([0-9]{4})(-([0-9]{4}))?"$after"$ ]] || return 1
    [[ -z "${BASH_REMATCH[3]}" ]] || (( 10#${BASH_REMATCH[3]} > 10#${BASH_REMATCH[1]} ))
}

# Whether the comments at the top of LINES, from line index $1 until the
# code starts, or any line that names an SPDX license, look like a license
# notice
has_other_notice() {
    local i line in_block=false
    for (( i = $1; i < ${#LINES[@]}; i++ )); do
        line="${LINES[i],,}"
        if [[ "$KIND" == java ]]; then
            if $in_block; then
                [[ "$line" != *'*/'* ]] || in_block=false
            elif [[ "$line" =~ ^[[:space:]]*/\* ]]; then
                [[ "$line" == *'*/'* ]] || in_block=true
            elif [[ ! "$line" =~ ^[[:space:]]*(//|$) ]]; then
                break
            fi
        elif [[ ! "$line" =~ ^[[:space:]]*(#|$) ]]; then
            break
        fi
        [[ ! "$line" =~ $OTHER_NOTICE ]] || return 0
    done
    for line in "${LINES[@]}"; do
        [[ "${line,,}" != *spdx-license-identifier* ]] || return 0
    done
    return 1
}

# Examine the top of a file, in LINES, as KIND. Sets NOTICE to the notice
# in KIND's comments, PREAMBLE to the number of lines that come before it,
# and PROBLEM to what's wrong, or empty if the notice is in place. MISSING is
# true if the file has no license notice at all, so --fix may add one.
examine() {
    local i
    PREAMBLE=0 PROBLEM="" MISSING=false
    if [[ "$KIND" == java ]]; then
        NOTICE=("${JAVA_NOTICE[@]}")
    else
        NOTICE=("${SHELL_NOTICE[@]}")
        if [[ "${LINES[0]-}" == '#!'* || "${LINES[0]-}" =~ ^#[[:space:]]*shellcheck[[:space:]]+shell= ]]; then
            # Directives right after the shebang apply to the whole file, so they stay there
            PREAMBLE=1
            while (( PREAMBLE < ${#LINES[@]} )) && [[ "${LINES[PREAMBLE]}" =~ ^#[[:space:]]*shellcheck[[:space:]] ]]; do
                PREAMBLE=$((PREAMBLE + 1))
            done
        fi
    fi

    for i in "${!NOTICE[@]}"; do
        if (( PREAMBLE + i >= ${#LINES[@]} )) || ! matches "${LINES[PREAMBLE + i]}" "${NOTICE[i]}"; then
            if has_other_notice "$PREAMBLE"; then
                PROBLEM="line $((PREAMBLE + i + 1)) differs from the license notice"
            else
                PROBLEM="no license notice"
                MISSING=true
            fi
            return 0
        fi
    done
    i=$((PREAMBLE + ${#NOTICE[@]}))
    if (( i < ${#LINES[@]} )) && [[ -n "${LINES[i]}" ]]; then
        PROBLEM="line $((i + 1)) should be blank, after the license notice"
    fi
}

# Add NOTICE with the current year to file $1, whose top is in LINES, after
# its PREAMBLE, leaving every other byte as it was
add_notice() {
    local path="$1" line
    {
        if (( PREAMBLE > 0 )); then
            printf '%s\n' "${LINES[@]:0:PREAMBLE}"
        fi
        for line in "${NOTICE[@]}"; do
            printf '%s\n' "${line//"$YEAR_FIELD"/$YEAR}"
        done
        if (( PREAMBLE < ${#LINES[@]} )) && [[ -n "${LINES[PREAMBLE]}" ]]; then
            printf '\n'
        fi
        tail -n "+$((PREAMBLE + 1))" -- "$path"
    } > "$WORK/scratch"
    # Rewriting in place keeps the file's permissions
    cat -- "$WORK/scratch" > "$path"
}

main() {
    local mode=check
    case "${1-}" in
        "") ;;
        --fix) mode=fix ;;
        --staged) mode=staged ;;
        -h | --help) usage; return 0 ;;
        *) usage >&2; exit 2 ;;
    esac
    (( $# <= 1 )) || { usage >&2; exit 2; }

    cd "$ROOT"
    git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "$ROOT is not a Git working tree"
    [[ -s "$TEMPLATE" ]] || die "$TEMPLATE is missing"
    local line
    mapfile -t TEXT < "$TEMPLATE"
    JAVA_NOTICE=("/*")
    SHELL_NOTICE=()
    for line in "${TEXT[@]}"; do
        JAVA_NOTICE+=(" *${line:+ $line}")
        SHELL_NOTICE+=("#${line:+ $line}")
    done
    JAVA_NOTICE+=(" */")
    YEAR="$(date +%Y)"
    # Git's output goes through files rather than process substitutions, so
    # that a failing git stops the check instead of leaving nothing to check
    WORK="$(mktemp -d)"
    trap 'rm -rf -- "$WORK"' EXIT

    local -a problems=() added=()
    local -A seen=()
    local count=0 path first meta mode_bits sha
    if [[ "$mode" == staged ]]; then
        git diff --cached --raw -z --no-abbrev --no-renames --diff-filter=ACMT > "$WORK/list" \
            || die "git diff can't list the staged files"
        # :old_mode new_mode old_blob new_blob status, then the path
        while IFS= read -r -d '' meta && IFS= read -r -d '' path; do
            read -r _ mode_bits _ sha _ <<<"$meta"
            [[ "$mode_bits" == 100644 || "$mode_bits" == 100755 ]] || continue
            classify "$path"
            [[ -n "$KIND" ]] || continue
            git cat-file blob "$sha" > "$WORK/blob" || die "git cat-file can't read the staged $path"
            if [[ "$KIND" == unknown ]]; then
                first=""
                IFS= read -r first < "$WORK/blob" || true
                classify "$path" "$first"
                [[ -n "$KIND" ]] || continue
            fi
            mapfile -t -n "$WINDOW" LINES < "$WORK/blob"
            examine
            count=$((count + 1))
            [[ -z "$PROBLEM" ]] || problems+=("$path: $PROBLEM")
        done < "$WORK/list"
    else
        # Without --deduplicate, which needs Git 2.31, an unmerged path is
        # listed once for each of its stages
        git ls-files -z --cached --others --exclude-standard > "$WORK/list" \
            || die "git ls-files can't list the files"
        while IFS= read -r -d '' path; do
            [[ -z "${seen[$path]+set}" ]] || continue
            seen[$path]=1
            [[ -f "$path" && ! -L "$path" ]] || continue
            classify "$path"
            if [[ "$KIND" == unknown ]]; then
                first=""
                IFS= read -r first < "$path" || true
                classify "$path" "$first"
            fi
            [[ -n "$KIND" ]] || continue
            mapfile -t -n "$WINDOW" LINES < "$path"
            examine
            count=$((count + 1))
            if [[ "$mode" == fix ]] && $MISSING; then
                add_notice "$path"
                added+=("$path")
            elif [[ -n "$PROBLEM" ]]; then
                problems+=("$path: $PROBLEM")
            fi
        done < "$WORK/list"
        # Every checkout has Java files and shell scripts, so finding none means the listing went wrong
        (( count > 0 )) || die "found no Java files, shell scripts or Python scripts in $ROOT"
    fi

    if (( ${#added[@]} )); then
        printf 'Added the license notice to:\n'
        printf '  %s\n' "${added[@]}"
    fi
    if (( ${#problems[@]} == 0 )); then
        if [[ "$mode" != staged ]]; then
            printf 'All %d Java files, shell scripts and Python scripts begin with the license notice.\n' "$count"
        fi
        return 0
    fi
    {
        case "$mode" in
            check) printf 'These files need to begin with the license notice in %s:\n' "$TEMPLATE" ;;
            fix) printf 'These files need to be corrected by hand to begin with the license notice in %s:\n' "$TEMPLATE" ;;
            staged) printf 'Commit refused: these staged files need to begin with the license notice in %s:\n' "$TEMPLATE" ;;
        esac
        printf '  %s\n' "${problems[@]}"
        case "$mode" in
            check) printf 'scripts/lp headers --fix adds the notice to files that have none. Correct the others by hand.\n' ;;
            staged) printf 'Run scripts/lp headers --fix to add the notice to files that have none, correct the others by hand, and stage the result.\n' ;;
        esac
    } >&2
    return 1
}

main "$@"
