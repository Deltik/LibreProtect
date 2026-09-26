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

import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.upstream.Capabilities;
import net.deltik.mc.libreprotect.extension.upstream.CoreProtectPurge;
import net.deltik.mc.libreprotect.extension.upstream.Names;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import net.deltik.mc.libreprotect.testutil.AssumeCapability;
import net.deltik.mc.libreprotect.testutil.CoreProtectFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Instant;
import java.time.ZoneId;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * What the console says as auto-purge starts on a CoreProtect that renamed
 * one of its settings: {@code auto-purge: 180d} is configured, and it must
 * either run or say why not.
 */
class CoreProtectPurgeAnnouncingTest {

    private static final String SCHEDULE = "INFO: Auto-purge keeps 180 days of data. Next run: 2026-09-25 03:30"
        + " (server time).";

    @RegisterExtension
    final CoreProtectFixture coreProtect = new CoreProtectFixture();

    private final RecordingLog log = new RecordingLog();
    private AutoPurgeScheduler scheduler;

    @BeforeEach
    void configured() {
        coreProtect.set("ConfigHandler.serverRunning", true).set("Config.AUTO_PURGE", "180d")
            .set("Config.AUTO_PURGE_TIME", "03:30").useEngine(Engine.SQLITE);
    }

    @AfterEach
    void stop() {
        if (scheduler != null) {
            scheduler.stop();
        }
    }

    /**
     * @return what starting auto-purge logs, on an upstream without some members
     */
    private List<String> start(String... hidden) {
        CoreProtectPurge bridge = CoreProtectPurge.create(Capabilities.probe(Upstream.coreProtect().hiding(hidden)));
        scheduler = new AutoPurgeScheduler(bridge, log, new MutableClock(Instant.parse("2026-09-24T12:00:00Z")),
            () -> ZoneId.of("UTC"), 60_000);
        scheduler.start();
        return log.messages;
    }

    @Test
    @DisplayName("should say that it can't read auto-purge, rather than keep quiet as if it were off")
    void retentionRenamed() {
        assertEquals(List.of("WARNING: Auto-purge can't read its settings with this CoreProtect build:"
            + " CoreProtect has no Config.AUTO_PURGE."), start(Names.CONFIG + "#AUTO_PURGE"));
    }

    @Test
    @DisplayName("should run as usual on SQLite without database-lock, which only ClickHouse needs")
    void databaseLockRenamed() {
        assertEquals(List.of(SCHEDULE), start(Names.CONFIG + "#DATABASE_LOCK"));
    }

    @Test
    @DisplayName("should say why it can't purge ClickHouse without database-lock, and not blame the setting")
    void databaseLockRenamedOnClickHouse() {
        AssumeCapability.strategy("auto-purge.engine.clickhouse", "retention");
        coreProtect.useEngine(Engine.CLICKHOUSE);

        assertEquals(List.of("WARNING: Auto-purge won't work with this CoreProtect build: CoreProtect has no"
            + " Config.DATABASE_LOCK, which purging ClickHouse needs."), start(Names.CONFIG + "#DATABASE_LOCK"));
    }

    @Test
    @DisplayName("should say why it can't run, and announce no run, when auto-purge-time is renamed")
    void timeRenamed() {
        assertEquals(List.of("WARNING: Auto-purge won't work with this CoreProtect build: CoreProtect has no"
            + " Config.AUTO_PURGE_TIME."), start(Names.CONFIG + "#AUTO_PURGE_TIME"));
    }
}
