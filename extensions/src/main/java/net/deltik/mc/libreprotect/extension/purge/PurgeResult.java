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

package net.deltik.mc.libreprotect.extension.purge;

/**
 * How one purge run ended.
 */
final class PurgeResult {

    private final long removed;
    private final StopReason stopReason;
    private final String detail;
    private final long elapsedMillis;
    private final boolean orphansCleaned;

    PurgeResult(long removed, StopReason stopReason, String detail, long elapsedMillis, boolean orphansCleaned) {
        this.removed = removed;
        this.stopReason = stopReason;
        this.detail = detail;
        this.elapsedMillis = elapsedMillis;
        this.orphansCleaned = orphansCleaned;
    }

    /**
     * @return rows removed, including orphaned entity rows
     */
    long removed() {
        return removed;
    }

    /**
     * @return why the run stopped early, or {@code null} if it finished
     */
    StopReason stopReason() {
        return stopReason;
    }

    /**
     * @return more about the stop, such as a database error message, or {@code null}
     */
    String detail() {
        return detail;
    }

    long elapsedMillis() {
        return elapsedMillis;
    }

    /**
     * @return whether the orphan cleanup ran to the end
     */
    boolean orphansCleaned() {
        return orphansCleaned;
    }

    boolean completed() {
        return stopReason == null;
    }
}
