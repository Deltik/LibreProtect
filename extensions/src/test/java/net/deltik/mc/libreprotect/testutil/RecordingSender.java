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

package net.deltik.mc.libreprotect.testutil;

import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * A minimal {@link CommandSender} of any sender type that records what is
 * done to it. It's safe to use from several threads.
 */
public final class RecordingSender {

    private final List<String> messages = Collections.synchronizedList(new ArrayList<>());
    private final Set<String> methodsCalled = Collections.synchronizedSet(new TreeSet<>());
    private final CommandSender sender;

    public RecordingSender(Class<? extends CommandSender> type) {
        sender = type.cast(Proxy.newProxyInstance(
            RecordingSender.class.getClassLoader(),
            new Class<?>[]{type},
            (proxy, method, args) -> {
                switch (method.getName()) {
                    case "equals":
                        return proxy == args[0];
                    case "hashCode":
                        return System.identityHashCode(proxy);
                    case "toString":
                        return "RecordingSender";
                    default:
                        break;
                }
                methodsCalled.add(method.getName());
                if (method.getName().equals("sendMessage")
                    && method.getParameterCount() == 1
                    && method.getParameterTypes()[0] == String.class) {
                    messages.add((String) args[0]);
                    return null;
                }
                if (method.getName().equals("getName")) {
                    return "CONSOLE";
                }
                throw new UnsupportedOperationException(method.toString());
            }));
    }

    public CommandSender sender() {
        return sender;
    }

    /**
     * @return the messages as sent, with color codes
     */
    public List<String> messages() {
        synchronized (messages) {
            return new ArrayList<>(messages);
        }
    }

    /**
     * @return the messages without color codes
     */
    public List<String> plainMessages() {
        List<String> plain = new ArrayList<>();
        for (String message : messages()) {
            plain.add(ChatColor.stripColor(message));
        }
        return plain;
    }

    /**
     * @return all messages without color codes, one per line
     */
    public String text() {
        return String.join("\n", plainMessages());
    }

    public Set<String> methodsCalled() {
        synchronized (methodsCalled) {
            return new TreeSet<>(methodsCalled);
        }
    }
}
