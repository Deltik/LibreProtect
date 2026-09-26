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

package net.deltik.mc.libreprotect.extension.upstream.clickhouse;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.opentest4j.AssertionFailedError;
import org.opentest4j.TestAbortedException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * When the ClickHouse tests run, skip, or fail for want of a server.
 */
class ClickHouseTestServerTest {

    @TempDir
    Path folder;

    @Test
    @DisplayName("should skip without a ClickHouse endpoint outside CI")
    void skipOutsideCi() throws IOException {
        Path mysqlOnly = Files.writeString(folder.resolve("containers.env"), "MYSQL_HOST=127.0.0.1\n");

        assertThrows(TestAbortedException.class, () -> ClickHouseTestServer.endpoints(null, null));
        assertThrows(TestAbortedException.class, () -> ClickHouseTestServer.endpoints("", "false"));
        assertThrows(TestAbortedException.class, () -> ClickHouseTestServer.endpoints(mysqlOnly.toString(), ""));
    }

    @Test
    @DisplayName("should fail without a ClickHouse endpoint in CI")
    void failInCi() throws IOException {
        Path mysqlOnly = Files.writeString(folder.resolve("containers.env"), "MYSQL_HOST=127.0.0.1\n"
            + "CLICKHOUSE_HOST=\n");

        for (String containers : new String[]{null, folder.resolve("missing.env").toString(), mysqlOnly.toString()}) {
            AssertionFailedError failure = assertThrows(AssertionFailedError.class,
                () -> ClickHouseTestServer.endpoints(containers, "true"));
            assertTrue(failure.getMessage().contains("CI must test ClickHouse"), failure.getMessage());
        }
    }

    @Test
    @DisplayName("should find the ClickHouse endpoint, in CI or not")
    void endpoint() throws IOException {
        Path containers = Files.writeString(folder.resolve("containers.env"), "CLICKHOUSE_HOST=127.0.0.1\n"
            + "CLICKHOUSE_PORT=8123\n");

        assertEquals("8123", ClickHouseTestServer.endpoints(containers.toString(), "true")
            .getProperty("CLICKHOUSE_PORT"));
        assertEquals("127.0.0.1", ClickHouseTestServer.endpoints(containers.toString(), null)
            .getProperty("CLICKHOUSE_HOST"));
    }
}
