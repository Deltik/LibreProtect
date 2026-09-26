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

package net.deltik.mc.libreprotect.extension.common;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.*;

class DatabaseSettingsTest {

    private static DatabaseSettings mysql(String host, String password, String prefix) {
        return DatabaseSettings.server(Engine.MYSQL, host, 3306, "coreprotect", "coreprotect", password, false, prefix);
    }

    @Test
    @DisplayName("should call settings the same database only when every setting is equal")
    void sameAs() {
        DatabaseSettings server = mysql("db.example", "secret", "co_");

        assertTrue(server.sameAs(mysql("db.example", "secret", "co_")));
        assertFalse(server.sameAs(mysql("other.example", "secret", "co_")));
        assertFalse(server.sameAs(mysql("db.example", "changed", "co_")));
        assertFalse(server.sameAs(mysql("db.example", "secret", "cp_")));
        assertFalse(server.sameAs(DatabaseSettings.server(Engine.MYSQL, "db.example", 3306, "coreprotect",
            "coreprotect", "secret", true, "co_")));
        assertFalse(server.sameAs(null));
        DatabaseSettings file = DatabaseSettings.embedded(Engine.SQLITE, new File("plugins/CoreProtect/database.db"));
        assertTrue(file.sameAs(DatabaseSettings.embedded(Engine.SQLITE, new File("plugins/CoreProtect/database.db"))));
        assertFalse(file.sameAs(DatabaseSettings.embedded(Engine.DUCKDB, new File("plugins/CoreProtect/database.db"))));
        assertFalse(file.sameAs(DatabaseSettings.embedded(Engine.SQLITE, new File("plugins/CoreProtect/other.db"))));
    }
}
