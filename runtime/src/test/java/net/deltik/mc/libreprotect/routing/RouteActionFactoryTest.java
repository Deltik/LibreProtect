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

package net.deltik.mc.libreprotect.routing;

import net.deltik.mc.libreprotect.routing.action.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.*;

class RouteActionFactoryTest {

    @Nested
    @DisplayName("getAction")
    class GetAction {

        @Test
        @DisplayName("should return BlockAction for BLOCK type")
        void returnsBlockAction() {
            RouteAction action = RouteActionFactory.getAction(RouteActionType.BLOCK);
            assertInstanceOf(BlockAction.class, action);
            assertEquals(RouteActionType.BLOCK, action.getType());
        }

        @Test
        @DisplayName("should return MockAction for MOCK type")
        void returnsMockAction() {
            RouteAction action = RouteActionFactory.getAction(RouteActionType.MOCK);
            assertInstanceOf(MockAction.class, action);
            assertEquals(RouteActionType.MOCK, action.getType());
        }

        @Test
        @DisplayName("should return RedirectAction for REDIRECT type")
        void returnsRedirectAction() {
            RouteAction action = RouteActionFactory.getAction(RouteActionType.REDIRECT);
            assertInstanceOf(RedirectAction.class, action);
            assertEquals(RouteActionType.REDIRECT, action.getType());
        }

        @Test
        @DisplayName("should return PassthroughAction for PASSTHROUGH type")
        void returnsPassthroughAction() {
            RouteAction action = RouteActionFactory.getAction(RouteActionType.PASSTHROUGH);
            assertInstanceOf(PassthroughAction.class, action);
            assertEquals(RouteActionType.PASSTHROUGH, action.getType());
        }

        @ParameterizedTest
        @DisplayName("should return action for all action types")
        @EnumSource(RouteActionType.class)
        void returnsActionForAllTypes(RouteActionType type) {
            RouteAction action = RouteActionFactory.getAction(type);
            assertNotNull(action);
            assertEquals(type, action.getType());
        }

        @Test
        @DisplayName("should return singleton instances")
        void returnsSingletonInstances() {
            RouteAction first = RouteActionFactory.getAction(RouteActionType.BLOCK);
            RouteAction second = RouteActionFactory.getAction(RouteActionType.BLOCK);
            assertSame(first, second);
        }

        @ParameterizedTest
        @DisplayName("should return same instance on repeated calls")
        @EnumSource(RouteActionType.class)
        void returnsSameInstanceForAllTypes(RouteActionType type) {
            RouteAction first = RouteActionFactory.getAction(type);
            RouteAction second = RouteActionFactory.getAction(type);
            assertSame(first, second);
        }
    }
}
