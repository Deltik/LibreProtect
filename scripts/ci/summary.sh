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

# How many failed unit tests to show
FAILED_TESTS=20

# The unit tests that failed, from Surefire's XML reports, each with its failure's type and message. Its plain
# reports leave out the failures of nested test classes. Its XML writer puts each element on a line of its own,
# with newlines in attribute values as character references, and what tests print, and stack traces, in CDATA
# sections, which are skipped. Bytes, not characters, so that every awk counts alike.
# shellcheck disable=SC2016 # The dollar signs in single quotes are awk's
failed_tests() {
    # Not in build/, which has upstream's build, nor in hidden directories, such as other worktrees
    find "$ROOT" \( -path "$ROOT/build" -o -path "$ROOT/.*" \) -prune -o -path '*/target/surefire-reports/TEST-*.xml' \
        -print0 2>/dev/null \
        | sort -z | LC_ALL=C xargs -0 -r awk -v root="$ROOT" -v max="$FAILED_TESTS" -v apostrophe="'" '
        function attribute(line, name) {
            if (!match(line, " " name "=\"[^\"]*\"")) return ""
            return substr(line, RSTART + length(name) + 3, RLENGTH - length(name) - 4)
        }
        function text(value) {
            gsub(/&lt;/, "<", value); gsub(/&gt;/, ">", value); gsub(/&quot;/, "\"", value)
            gsub(/&apos;/, apostrophe, value); gsub(/&#10;/, "\n", value); gsub(/&#9;/, "\t", value)
            gsub(/&#[0-9]+;/, "?", value); gsub(/&#x[0-9A-Fa-f]+;/, "?", value); gsub(/&amp;/, "\\&", value)
            gsub(/[\001-\010\013-\037\177]/, "?", value)
            return value
        }
        function simple(name) { sub(/^.*\./, "", name); return name }
        # The first bytes of a value, without the start of a character that they would cut off
        function cut(value, bytes,   lead, need) {
            if (length(value) <= bytes) return value
            value = substr(value, 1, bytes)
            for (lead = bytes; lead > 0 && substr(value, lead, 1) ~ /[\200-\277]/; lead--) continue
            if (lead == 0) return value
            need = substr(value, lead, 1) ~ /[\360-\367]/ ? 4 : substr(value, lead, 1) ~ /[\340-\357]/ ? 3 \
                : substr(value, lead, 1) ~ /[\300-\337]/ ? 2 : 1
            return bytes - lead + 1 < need ? substr(value, 1, lead - 1) : value
        }
        # Backquotes longer than any run of them in a value, which nothing in it can end
        function fence(value, least,   longest, rest, result) {
            longest = least - 1
            rest = value
            while (match(rest, /`+/)) { if (RLENGTH > longest) longest = RLENGTH; rest = substr(rest, RSTART + RLENGTH) }
            result = ""
            while (length(result) <= longest) result = result "`"
            return result
        }
        function span(value,   marks, padding) {
            marks = fence(value, 1)
            padding = value ~ /^`/ || value ~ /`$/ ? " " : ""
            return marks padding value padding marks
        }
        FNR == 1 {
            module = FILENAME
            if (index(module, root "/") == 1) module = substr(module, length(root) + 2)
            sub(/\/target\/.*/, "", module)
            cdata = 0
            test = ""
        }
        {
            # What of the line is outside CDATA sections
            line = $0
            outside = ""
            while (line != "") {
                if (cdata) {
                    end = index(line, "]]>")
                    if (!end) break
                    cdata = 0
                    line = substr(line, end + 3)
                } else {
                    start = index(line, "<![CDATA[")
                    if (!start) { outside = outside line; break }
                    outside = outside substr(line, 1, start - 1)
                    cdata = 1
                    line = substr(line, start + 9)
                }
            }
        }
        outside ~ /<testcase / { test = simple(text(attribute(outside, "classname"))) "." text(attribute(outside, "name")) }
        outside ~ /<(failure|error)[ >\/]/ && test != "" {
            if (++count <= max) {
                message = text(attribute(outside, "message"))
                lines = split(message, parts, "\n")
                message = ""
                for (i = 1; i <= lines && i <= 12 && length(message) < 1500; i++) message = message parts[i] "\n"
                if (i <= lines || length(message) > 1500) message = cut(message, 1500) "...\n"
                marks = fence(message, 3)
                printf "%s in %s, with %s:\n\n%stext\n%s%s\n\n", span(test), span(module),
                    span(simple(text(attribute(outside, "type")))), marks, message, marks
            }
            test = ""
        }
        END { if (count > max) printf "%d more failed. The job log lists them all.\n\n", count - max }'
}

failures="$(failed_tests)"
if [[ -n "$failures" ]]; then
    echo "## Failed Unit Tests"
    echo
    printf '%s\n\n' "$failures"
fi

if [[ ! -f "$AUDIT" ]]; then
    echo "## No Build Output"
    echo
    if [[ -n "$failures" ]]; then
        echo "The build stopped at the failed unit tests, before the transformer ran."
    else
        echo "The build stopped before the transformer finished. See the job log."
    fi
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
