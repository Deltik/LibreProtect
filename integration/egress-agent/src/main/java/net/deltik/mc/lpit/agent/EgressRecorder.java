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

package net.deltik.mc.lpit.agent;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * Called from instrumented JDK networking methods before they touch the
 * network. It appends one tab-separated line per attempt to the log:
 *
 * <pre>
 * kind  target  attribution  thread  frame|frame|...
 * </pre>
 *
 * <p>The attribution is {@code plugin} when a CoreProtect or LibreProtect
 * frame is on the stack, and {@code server} otherwise.
 *
 * <p>This class is loaded by the bootstrap class loader and runs inside JDK
 * networking code, so it may only use {@code java.base}. It must not do
 * anything that reaches the network itself. It lives outside LibreProtect's
 * package so its own frames are never mistaken for LibreProtect's.
 */
public final class EgressRecorder {

    static volatile Path log;
    static volatile boolean deny = true;

    private static final StackWalker WALKER = StackWalker.getInstance();
    private static final List<String> PLUGIN_PREFIXES = List.of("net.coreprotect.", "net.deltik.mc.libreprotect.");
    private static final String OWN_PREFIX = "net.deltik.mc.lpit.agent.";
    private static final ThreadLocal<Boolean> ACTIVE = new ThreadLocal<>();

    private EgressRecorder() {
    }

    /**
     * Before a TCP connect or a UDP connect/send.
     */
    public static void socket(String kind, SocketAddress address) throws IOException {
        if (!(address instanceof InetSocketAddress inet)) {
            return; // Unix domain sockets are local
        }
        InetAddress resolved = inet.getAddress();
        if (resolved != null && (resolved.isLoopbackAddress() || resolved.isAnyLocalAddress())) {
            return;
        }
        String host = inet.getHostString();
        if (resolved == null && isLocalName(host)) {
            return;
        }
        String target = host + ":" + inet.getPort();
        record(kind, target);
        if (deny) {
            throw new ConnectException("Blocked by LibreProtect's egress test agent: " + target);
        }
    }

    /**
     * Before a host name is resolved.
     */
    public static void resolve(String host) throws UnknownHostException {
        if (host == null || host.isEmpty() || isLocalName(host) || isLoopbackLiteral(host)) {
            return;
        }
        record("resolve", host);
        if (deny) {
            throw new UnknownHostException(host + " (blocked by LibreProtect's egress test agent)");
        }
    }

    private static boolean isLocalName(String host) {
        String lower = host.toLowerCase(Locale.ROOT);
        return lower.equals("localhost") || lower.endsWith(".localhost");
    }

    private static boolean isLoopbackLiteral(String host) {
        return host.startsWith("127.") || host.equals("::1") || host.equals("[::1]") || host.equals("0.0.0.0");
    }

    private static void record(String kind, String target) {
        Path destination = log;
        if (destination == null || ACTIVE.get() != null) {
            return;
        }
        ACTIVE.set(Boolean.TRUE);
        try {
            List<String> frames = WALKER.walk(stream -> stream
                .map(frame -> frame.getClassName() + "." + frame.getMethodName() + ":" + frame.getLineNumber())
                .filter(frame -> !frame.startsWith(OWN_PREFIX))
                .collect(Collectors.toList()));
            boolean plugin = frames.stream().anyMatch(frame ->
                PLUGIN_PREFIXES.stream().anyMatch(frame::startsWith));
            String line = kind + "\t" + target + "\t" + (plugin ? "plugin" : "server") + "\t"
                + Thread.currentThread().getName().replace('\t', ' ') + "\t" + String.join("|", frames) + "\n";
            synchronized (EgressRecorder.class) {
                Files.writeString(destination, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            }
        } catch (IOException | RuntimeException e) {
            // Recording must never break the program under test
        } finally {
            ACTIVE.remove();
        }
    }
}
