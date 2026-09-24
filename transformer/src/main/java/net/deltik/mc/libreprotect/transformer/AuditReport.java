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

    record Finding(Severity severity, String rule, String site, String detail) {
    }

    boolean failed;
    boolean reviewRequired;
    final List<Finding> findings = new ArrayList<>();
    AuditBaseline observed;

    void add(Severity severity, String rule, String site, String detail) {
        findings.add(new Finding(severity, rule, site, detail));
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
