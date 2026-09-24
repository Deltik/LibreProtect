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

/**
 * {@code /co migrate-db} across database engines, using the MySQL container
 * and, for CoreProtect 25, the ClickHouse container. The test plugin's side
 * is {@code MigrationScenario}.
 *
 * <p>No checks yet.
 */
final class MigrationChecks {

    private MigrationChecks() {
    }

    static void run(Harness.Suite suite) throws Exception {
    }
}
