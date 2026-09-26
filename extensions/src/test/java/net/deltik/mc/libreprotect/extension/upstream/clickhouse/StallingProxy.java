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

package net.deltik.mc.libreprotect.extension.upstream.clickhouse;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A loopback TCP proxy in front of a server that can stop passing data on,
 * in both directions, while keeping every connection open: a server that
 * hangs mid-conversation, as seen by its client.
 */
final class StallingProxy implements AutoCloseable {

    private final ServerSocket listener;
    private final String targetHost;
    private final int targetPort;
    private final List<Socket> sockets = new CopyOnWriteArrayList<>();
    private final Object gate = new Object();
    private boolean stalled;
    private volatile boolean closed;

    StallingProxy(String targetHost, int targetPort) throws IOException {
        this.targetHost = targetHost;
        this.targetPort = targetPort;
        listener = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        thread("StallingProxy accept", this::accept).start();
    }

    int port() {
        return listener.getLocalPort();
    }

    /**
     * Stop passing data on, until {@link #resume()}.
     */
    void stall() {
        synchronized (gate) {
            stalled = true;
        }
    }

    void resume() {
        synchronized (gate) {
            stalled = false;
            gate.notifyAll();
        }
    }

    private void accept() {
        while (!closed) {
            try {
                Socket client = listener.accept();
                Socket server = new Socket(targetHost, targetPort);
                sockets.add(client);
                sockets.add(server);
                thread("StallingProxy to server", () -> pump(client, server)).start();
                thread("StallingProxy to client", () -> pump(server, client)).start();
            } catch (IOException e) {
                return;
            }
        }
    }

    private void pump(Socket from, Socket to) {
        byte[] buffer = new byte[8192];
        try (InputStream input = from.getInputStream(); OutputStream output = to.getOutputStream()) {
            int read;
            while ((read = input.read(buffer)) >= 0) {
                synchronized (gate) {
                    while (stalled && !closed) {
                        gate.wait();
                    }
                }
                output.write(buffer, 0, read);
                output.flush();
            }
        } catch (IOException e) {
            // A side closed
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            closeQuietly(from);
            closeQuietly(to);
        }
    }

    private static Thread thread(String name, Runnable runnable) {
        Thread thread = new Thread(runnable, name);
        thread.setDaemon(true);
        return thread;
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException e) {
            // Closing anyway
        }
    }

    @Override
    public void close() throws IOException {
        closed = true;
        resume();
        listener.close();
        for (Socket socket : sockets) {
            closeQuietly(socket);
        }
    }
}
