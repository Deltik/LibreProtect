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

package net.deltik.mc.libreprotect.routing.answer;

import java.io.IOException;

/**
 * Answers a request in place of the server it was meant for.
 *
 * <p>An {@link IOException} fails the request the way a network failure
 * would, so callers take the same path they take when offline.
 */
@FunctionalInterface
public interface Answer {

    /**
     * @param request what the caller asked for
     * @return the reply to give the caller
     * @throws IOException if there is no answer for this request
     */
    Response answer(Request request) throws IOException;
}
