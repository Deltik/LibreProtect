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

package net.deltik.mc.libreprotect.routing.action;

import net.deltik.mc.libreprotect.EgressBlockedException;
import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.routing.Route;
import net.deltik.mc.libreprotect.routing.RouteActionType;
import net.deltik.mc.libreprotect.routing.RouteRegistry;
import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Map;
import java.util.logging.Level;

import static org.junit.jupiter.api.Assertions.*;

class BlockActionTest {

    private BlockAction action;
    private TestLogger testLogger;

    @BeforeEach
    void setUp() {
        action = new BlockAction();
        testLogger = new TestLogger();
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(testLogger);
    }

    @AfterEach
    void tearDown() {
        LibreProtectLogger.reset();
    }

    @Test
    @DisplayName("getType() should return BLOCK")
    void getTypeReturnsBlock() {
        assertEquals(RouteActionType.BLOCK, action.getType());
    }

    @Nested
    @DisplayName("createConnection")
    class CreateConnection {

        @Test
        @DisplayName("should throw EgressBlockedException instead of returning a connection")
        void throwsBlocked() {
            Route route = new Route(".*", RouteActionType.BLOCK);
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.of(route, Map.of());

            assertThrows(EgressBlockedException.class,
                () -> action.createConnection(MockUrlFactory.createUrl("https://example.com"), null, match));
        }

        @Test
        @DisplayName("should throw an IOException so callers take their offline path")
        void throwsIOException() {
            Route route = new Route(".*", RouteActionType.BLOCK);
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.of(route, Map.of());

            IOException ex = assertThrows(IOException.class,
                () -> action.createConnection(MockUrlFactory.statsUrl(), null, match));
            assertInstanceOf(EgressBlockedException.class, ex);
        }

        @Test
        @DisplayName("should log blocked URL when verbose logging enabled")
        void logsBlockedUrlWhenVerbose() {
            LibreProtectLogger.setVerbose(true);
            Route route = new Route(".*", RouteActionType.BLOCK);
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.of(route, Map.of());

            assertThrows(EgressBlockedException.class,
                () -> action.createConnection(MockUrlFactory.httpsStatsUrl(), null, match));

            assertTrue(testLogger.hasMessageContaining("Blocked"));
            assertTrue(testLogger.hasMessageContaining("stats.coreprotect.net"));
            assertTrue(testLogger.hasMessageContaining(Level.INFO, "[DEBUG]"));
        }

        @Test
        @DisplayName("should NOT log blocked URL when verbose logging disabled")
        void doesNotLogBlockedUrlWhenNotVerbose() {
            LibreProtectLogger.setVerbose(false);
            Route route = new Route(".*", RouteActionType.BLOCK);
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.of(route, Map.of());

            assertThrows(EgressBlockedException.class,
                () -> action.createConnection(MockUrlFactory.httpsStatsUrl(), null, match));

            assertFalse(testLogger.hasMessageContaining("Blocked"));
            assertTrue(testLogger.getRecords().isEmpty());
        }

        @Test
        @DisplayName("should log exactly the exception message when verbose")
        void logsExceptionMessage() {
            LibreProtectLogger.setVerbose(true);
            Route route = new Route("https://stats\\.coreprotect\\.net/.*", RouteActionType.BLOCK);
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.of(route, Map.of());

            EgressBlockedException ex = assertThrows(EgressBlockedException.class,
                () -> action.createConnection(MockUrlFactory.httpsStatsUrl(), null, match));

            assertEquals(1, testLogger.getRecords().size());
            assertTrue(testLogger.getMessages().get(0).endsWith(ex.getMessage()));
        }

        @Test
        @DisplayName("should include route pattern in block reason")
        void includesRoutePatternInReason() {
            Route route = new Route("test-pattern", RouteActionType.BLOCK);
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.of(route, Map.of());

            EgressBlockedException ex = assertThrows(EgressBlockedException.class,
                () -> action.createConnection(MockUrlFactory.createUrl("https://example.com"), null, match));

            assertEquals("route test-pattern", ex.getReason());
            assertTrue(ex.getMessage().contains("route test-pattern"), ex.getMessage());
        }

        @Test
        @DisplayName("should handle default match")
        void handlesDefaultMatch() {
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.defaultMatch(RouteActionType.BLOCK);

            EgressBlockedException ex = assertThrows(EgressBlockedException.class,
                () -> action.createConnection(MockUrlFactory.createUrl("https://unknown.com"), null, match));

            assertEquals("default action", ex.getReason());
        }

        @Test
        @DisplayName("should put the normalized URL in the message")
        void messageHasNormalizedUrl() {
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.defaultMatch(RouteActionType.BLOCK);

            EgressBlockedException ex = assertThrows(EgressBlockedException.class,
                () -> action.createConnection(
                    MockUrlFactory.createUrl("https://user:secret@bStats.org/api/v2/data/bukkit#frag"), null, match));

            assertTrue(ex.getMessage().endsWith("https://bstats.org/api/v2/data/bukkit"), ex.getMessage());
            assertFalse(ex.getMessage().contains("secret"), ex.getMessage());
        }

        @Test
        @DisplayName("should block regardless of the proxy")
        void ignoresProxy() {
            RouteRegistry.RouteMatch match = RouteRegistry.RouteMatch.defaultMatch(RouteActionType.BLOCK);
            Proxy proxy = new Proxy(Proxy.Type.HTTP, InetSocketAddress.createUnresolved("proxy.invalid", 8080));

            assertThrows(EgressBlockedException.class,
                () -> action.createConnection(MockUrlFactory.statsUrl(), proxy, match));
            assertThrows(EgressBlockedException.class,
                () -> action.createConnection(MockUrlFactory.statsUrl(), Proxy.NO_PROXY, match));
        }
    }
}
