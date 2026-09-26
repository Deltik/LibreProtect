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

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * A loopback port that accepts connections and never says anything, like an
 * HTTP port that a mistyped {@code mysql-port} points to, or a MySQL server
 * that hangs.
 */
public final class SilentServer implements AutoCloseable {

    private final ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
    private final List<Socket> accepted = new CopyOnWriteArrayList<>();
    private final CountDownLatch connected = new CountDownLatch(1);

    public SilentServer() throws IOException {
        Thread acceptor = new Thread(() -> {
            try {
                while (true) {
                    accepted.add(server.accept());
                    connected.countDown();
                }
            } catch (IOException e) {
                // Closed
            }
        }, "silent server");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    public int port() {
        return server.getLocalPort();
    }

    /**
     * @return whether something connected within the time
     */
    public boolean awaitConnection(long seconds) throws InterruptedException {
        return connected.await(seconds, TimeUnit.SECONDS);
    }

    @Override
    public void close() throws IOException {
        server.close();
        for (Socket socket : accepted) {
            socket.close();
        }
    }
}
