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

import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The checked-in {@code audit/baseline.json}, which the audit reads with
 * Gson, which ignores what it doesn't know: a misspelled or outdated key
 * would leave what it holds unaccepted, or accepted by nothing.
 */
class AuditBaselineFileTest {

    /** Tests run in the module's directory */
    private static final Path BASELINE = Path.of("..", "audit", "baseline.json");

    private static String read() throws IOException {
        return Files.readString(BASELINE, StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("has nothing that the audit doesn't read")
    void onlyWhatTheAuditReads() throws IOException {
        String json = read();
        assertEquals(JsonParser.parseString(json),
            JsonParser.parseString(Reports.toJson(Reports.fromJson(json, AuditBaseline.class))));
    }

    @Test
    @DisplayName("names the upstream build that each line was accepted from")
    void linesNameTheirBuilds() throws IOException {
        AuditBaseline baseline = Reports.fromJson(read(), AuditBaseline.class);
        assertFalse(baseline.lines.isEmpty());
        baseline.lines.forEach((name, line) -> {
            assertFalse(line.upstream.ref == null || line.upstream.ref.isEmpty(), name);
            assertTrue(line.upstream.commit != null && line.upstream.commit.matches("[0-9a-f]{40}"), name);
            assertTrue(line.upstream.jarSha256 != null && line.upstream.jarSha256.matches("[0-9a-f]{64}"), name);
        });
    }
}
