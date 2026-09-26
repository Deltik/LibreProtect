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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A loopback TCP proxy to a server that can stop passing data on, keeping
 * the connections open, like a network that drops everything in the middle
 * of a conversation.
 */
public final class FreezingProxy implements AutoCloseable {

    private final ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
    private final List<Socket> sockets = new CopyOnWriteArrayList<>();
    private volatile boolean frozen;

    public FreezingProxy(String host, int port) throws IOException {
        Thread acceptor = new Thread(() -> {
            try {
                while (true) {
                    Socket client = server.accept();
                    Socket upstream = new Socket(host, port);
                    sockets.add(client);
                    sockets.add(upstream);
                    pump(client, upstream);
                    pump(upstream, client);
                }
            } catch (IOException e) {
                // Closed
            }
        }, "freezing proxy");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    private void pump(Socket from, Socket to) {
        Thread thread = new Thread(() -> {
            byte[] buffer = new byte[16 * 1024];
            try (InputStream in = from.getInputStream(); OutputStream out = to.getOutputStream()) {
                while (true) {
                    int read = in.read(buffer);
                    if (read < 0) {
                        return;
                    }
                    while (frozen) {
                        Thread.sleep(50);
                    }
                    out.write(buffer, 0, read);
                    out.flush();
                }
            } catch (IOException | InterruptedException e) {
                // Closed
            }
        }, "freezing proxy pump");
        thread.setDaemon(true);
        thread.start();
    }

    public int port() {
        return server.getLocalPort();
    }

    /**
     * Stop passing data on, in both directions
     */
    public void freeze() {
        frozen = true;
    }

    @Override
    public void close() throws IOException {
        server.close();
        for (Socket socket : sockets) {
            socket.close();
        }
    }
}
