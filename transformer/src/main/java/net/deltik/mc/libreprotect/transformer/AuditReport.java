/*
 * Copyright (C) 2026 Deltik <https://www.deltik.net/>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of LibreProtect.
 *
 * LibreProtect is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LibreProtect is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LibreProtect.  If not, see <https://www.gnu.org/licenses/>.
 */

package net.deltik.mc.libreprotect.transformer;

import java.util.ArrayList;
import java.util.List;

/**
 * Result of an {@link Audit}, written as {@code audit-report.json}.
 */
final class AuditReport {

    enum Severity {
        /** Breaks LibreProtect's guarantees: the build fails */
        FAIL,
        /** Needs a maintainer's review before release */
        REVIEW,
        /** For the record only */
        INFO
    }

    /** What resolves a finding once a maintainer has reviewed it */
    enum Resolution {
        /**
         * Accepting the build into the baseline ({@code scripts/lp accept}),
         * since its line then has what the build observed
         */
        ACCEPT,
        /** Only an allowance in the baseline, with a reason, or a change to upstream or to LibreProtect */
        ALLOW
    }

    /**
     * @param resolution what resolves it, or {@code null} for a finding that is only for the record
     */
    record Finding(Severity severity, String rule, String site, String detail, Resolution resolution) {
    }

    boolean failed;
    boolean reviewRequired;
    final List<Finding> findings = new ArrayList<>();
    /** What this build observed, which accepting it makes its line's reviewed state */
    AuditBaseline.Line observed;

    void add(Severity severity, String rule, String site, String detail, Resolution resolution) {
        findings.add(new Finding(severity, rule, site, detail, resolution));
        if (severity == Severity.FAIL) {
            failed = true;
        } else if (severity == Severity.REVIEW) {
            reviewRequired = true;
        }
    }

    long count(Severity severity) {
        return findings.stream().filter(finding -> finding.severity() == severity).count();
    }
}
