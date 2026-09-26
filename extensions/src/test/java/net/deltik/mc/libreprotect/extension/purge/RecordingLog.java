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

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * A {@link PurgeLog} that keeps its messages, prefixed with {@code INFO: }
 * or {@code WARNING: }.
 */
final class RecordingLog implements PurgeLog {

    final List<String> messages = new CopyOnWriteArrayList<>();

    @Override
    public void info(String message) {
        messages.add("INFO: " + message);
    }

    @Override
    public void warning(String message) {
        messages.add("WARNING: " + message);
    }

    List<String> warnings() {
        return messages.stream().filter(message -> message.startsWith("WARNING: ")).collect(Collectors.toList());
    }

    /**
     * @return the messages that contain {@code text}
     */
    List<String> containing(String text) {
        return messages.stream().filter(message -> message.contains(text)).collect(Collectors.toList());
    }

    @Override
    public String toString() {
        return String.join("\n", messages);
    }
}
