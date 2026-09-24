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
import net.deltik.mc.libreprotect.routing.answer.Response;
import net.deltik.mc.libreprotect.testutil.LocalHttpServer;
import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import net.deltik.mc.libreprotect.testutil.RecordingAnswer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.IOException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RouteActionFactoryTest {

    @Nested
    @DisplayName("getAction")
    class GetAction {

        @Test
        @DisplayName("should return BlockAction for BLOCK type")
        void returnsBlockAction() {
            RouteAction action = RouteActionFactory.defaults().getAction(RouteActionType.BLOCK);
            assertInstanceOf(BlockAction.class, action);
            assertEquals(RouteActionType.BLOCK, action.getType());
        }

        @Test
        @DisplayName("should return AnswerAction for ANSWER type")
        void returnsAnswerAction() {
            RouteAction action = RouteActionFactory.defaults().getAction(RouteActionType.ANSWER);
            assertInstanceOf(AnswerAction.class, action);
            assertEquals(RouteActionType.ANSWER, action.getType());
        }

        @Test
        @DisplayName("should return RedirectAction for REDIRECT type")
        void returnsRedirectAction() {
            RouteAction action = RouteActionFactory.defaults().getAction(RouteActionType.REDIRECT);
            assertInstanceOf(RedirectAction.class, action);
            assertEquals(RouteActionType.REDIRECT, action.getType());
        }

        @Test
        @DisplayName("should return PassthroughAction for PASSTHROUGH type")
        void returnsPassthroughAction() {
            RouteAction action = RouteActionFactory.defaults().getAction(RouteActionType.PASSTHROUGH);
            assertInstanceOf(PassthroughAction.class, action);
            assertEquals(RouteActionType.PASSTHROUGH, action.getType());
        }

        @ParameterizedTest
        @DisplayName("should return action for all action types")
        @EnumSource(RouteActionType.class)
        void returnsActionForAllTypes(RouteActionType type) {
            RouteAction action = RouteActionFactory.defaults().getAction(type);
            assertNotNull(action);
            assertEquals(type, action.getType());
        }

        @Test
        @DisplayName("should return singleton instances")
        void returnsSingletonInstances() {
            RouteAction first = RouteActionFactory.defaults().getAction(RouteActionType.BLOCK);
            RouteAction second = RouteActionFactory.defaults().getAction(RouteActionType.BLOCK);
            assertSame(first, second);
        }

        @ParameterizedTest
        @DisplayName("should return same instance on repeated calls")
        @EnumSource(RouteActionType.class)
        void returnsSameInstanceForAllTypes(RouteActionType type) {
            RouteAction first = RouteActionFactory.defaults().getAction(type);
            RouteAction second = RouteActionFactory.defaults().getAction(type);
            assertSame(first, second);
        }
    }

    @Nested
    @DisplayName("With answers")
    class WithAnswers {

        private final RouteRegistry.RouteMatch match =
            RouteRegistry.RouteMatch.of(new Route(".*", RouteActionType.ANSWER), Map.of());

        @Test
        @DisplayName("should answer ANSWER routes with the given answer")
        void answersWithGivenAnswer() throws IOException {
            RecordingAnswer answer = RecordingAnswer.replying(Response.text("24.1.1"));
            RouteActionFactory factory = new RouteActionFactory(answer);

            RouteAction action = factory.getAction(RouteActionType.ANSWER);

            assertEquals("24.1.1", LocalHttpServer.read(action.createConnection(MockUrlFactory.updateUrl(), null, match)));
            assertEquals(1, answer.calls());
        }

        @ParameterizedTest
        @DisplayName("should have an action of the right type for every type")
        @EnumSource(RouteActionType.class)
        void everyType(RouteActionType type) {
            RouteActionFactory factory = new RouteActionFactory(RecordingAnswer.replying(Response.text("")));
            assertEquals(type, factory.getAction(type).getType());
            assertSame(factory.getAction(type), factory.getAction(type));
        }

        @Test
        @DisplayName("should leave the default factory's answers alone")
        void defaultsUnaffected() {
            RouteActionFactory factory = new RouteActionFactory(RecordingAnswer.replying(Response.text("")));

            assertNotSame(factory.getAction(RouteActionType.ANSWER),
                RouteActionFactory.defaults().getAction(RouteActionType.ANSWER));
            assertSame(RouteActionFactory.defaults(), RouteActionFactory.defaults());
        }
    }
}
