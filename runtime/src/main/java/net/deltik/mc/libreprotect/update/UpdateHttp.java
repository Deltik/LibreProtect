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

package net.deltik.mc.libreprotect.update;

import net.deltik.mc.libreprotect.PrivacyConstants;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Makes the requests that update sources need: a {@code GET} with a fixed
 * {@code User-Agent} that names LibreProtect without its version, time
 * limits, and a cap on how much of the response is read.
 *
 * <p>Redirects are followed only within the API that was asked: the same
 * scheme, host and port. GitHub, for one, redirects requests about a renamed
 * repository within its API. A redirect anywhere else fails the request
 * without contacting that place.
 *
 * <p>These are real connections. The transformer doesn't rewrite
 * LibreProtect's own classes, and the network policy has already decided
 * that update checks go to the update sources by the time one is asked.
 */
final class UpdateHttp {

    /** Names LibreProtect, without its version, the server's port or a key */
    static final String USER_AGENT = PrivacyConstants.FORK_NAME + " (+" + PrivacyConstants.FORK_URL + ")";

    static final int MAX_RESPONSE_BYTES = 1024 * 1024;
    static final int MAX_REDIRECTS = 3;

    private static final int CONNECT_TIMEOUT_MILLIS = 5_000;
    private static final int READ_TIMEOUT_MILLIS = 10_000;
    /** How long a whole request may take, redirects included, even if the response arrives a little at a time */
    private static final int TOTAL_TIMEOUT_MILLIS = 30_000;

    private final int connectTimeoutMillis;
    private final int readTimeoutMillis;
    private final int totalTimeoutMillis;

    UpdateHttp() {
        this(CONNECT_TIMEOUT_MILLIS, READ_TIMEOUT_MILLIS, TOTAL_TIMEOUT_MILLIS);
    }

    UpdateHttp(int connectTimeoutMillis, int readTimeoutMillis, int totalTimeoutMillis) {
        this.connectTimeoutMillis = connectTimeoutMillis;
        this.readTimeoutMillis = readTimeoutMillis;
        this.totalTimeoutMillis = totalTimeoutMillis;
    }

    /**
     * @param headers request headers besides the {@code User-Agent}, such as
     *                {@code Accept}
     * @return the body of a {@code 200 OK} response, decoded as UTF-8
     * @throws IOException if the request fails or times out, the status
     *         isn't 200, a redirect leaves the API, or the body is larger than
     *         {@value #MAX_RESPONSE_BYTES} bytes
     */
    String get(URL url, Map<String, String> headers) throws IOException {
        // The timeouts only bound each wait, and some waits have no timeout at all: a name lookup, or the JDK
        // draining a connection it keeps alive. So the request runs on a thread of its own, and the caller stops
        // waiting for it at the deadline.
        AtomicBoolean expired = new AtomicBoolean();
        AtomicReference<HttpURLConnection> current = new AtomicReference<>();
        FutureTask<String> request = new FutureTask<>(() -> fetch(url, headers, expired, current));
        Thread thread = new Thread(request, PrivacyConstants.FORK_NAME + " update check");
        thread.setDaemon(true);
        thread.start();
        try {
            return request.get(totalTimeoutMillis, TimeUnit.MILLISECONDS);
        } catch (ExecutionException e) {
            throw rethrow(e.getCause());
        } catch (TimeoutException e) {
            abandon(expired, current);
            throw deadlinePassed();
        } catch (InterruptedException e) {
            abandon(expired, current);
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted while waiting for the response");
        }
    }

    /**
     * Keep the request from going any further, and close its connection on
     * yet another thread, since closing can wait for a read to finish
     */
    private static void abandon(AtomicBoolean expired, AtomicReference<HttpURLConnection> current) {
        expired.set(true);
        HttpURLConnection connection = current.get();
        if (connection != null) {
            Thread closer = new Thread(connection::disconnect, PrivacyConstants.FORK_NAME + " update check cleanup");
            closer.setDaemon(true);
            closer.start();
        }
    }

    private static IOException rethrow(Throwable cause) {
        if (cause instanceof IOException) {
            return (IOException) cause;
        }
        if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        }
        if (cause instanceof Error) {
            throw (Error) cause;
        }
        return new IOException(cause);
    }

    /**
     * Make the request, following redirects within the API, until the
     * deadline has passed
     */
    private String fetch(URL url, Map<String, String> headers, AtomicBoolean expired,
                         AtomicReference<HttpURLConnection> current) throws IOException {
        URL target = url;
        for (int redirects = 0; ; redirects++) {
            HttpURLConnection connection = open(target, headers);
            current.set(connection);
            try {
                // Nothing more is sent once the caller has stopped waiting
                checkDeadline(expired);
                int status = connection.getResponseCode();
                checkDeadline(expired);
                if (isRedirect(status)) {
                    target = redirect(url, target, status, connection.getHeaderField("Location"), redirects);
                    continue;
                }
                if (status != HttpURLConnection.HTTP_OK) {
                    throw new IOException("HTTP " + status + reason(status));
                }
                if (connection.getContentLengthLong() > MAX_RESPONSE_BYTES) {
                    throw tooLarge();
                }
                try (InputStream in = connection.getInputStream()) {
                    return new String(read(in, expired), StandardCharsets.UTF_8);
                }
            } catch (IOException e) {
                // A read that failed because the deadline closed the connection
                checkDeadline(expired);
                throw e;
            } finally {
                connection.disconnect();
            }
        }
    }

    private HttpURLConnection open(URL url, Map<String, String> headers) throws IOException {
        URLConnection opened = url.openConnection();
        if (!(opened instanceof HttpURLConnection)) {
            throw new IOException("not an HTTP URL");
        }
        HttpURLConnection connection = (HttpURLConnection) opened;
        connection.setInstanceFollowRedirects(false);
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(connectTimeoutMillis);
        connection.setReadTimeout(readTimeoutMillis);
        connection.setRequestProperty("User-Agent", USER_AGENT);
        for (Map.Entry<String, String> header : headers.entrySet()) {
            connection.setRequestProperty(header.getKey(), header.getValue());
        }
        return connection;
    }

    private static boolean isRedirect(int status) {
        return status == HttpURLConnection.HTTP_MOVED_PERM || status == HttpURLConnection.HTTP_MOVED_TEMP
            || status == HttpURLConnection.HTTP_SEE_OTHER || status == 307 || status == 308;
    }

    /**
     * @param origin    the URL first asked, which names the API
     * @param from      the URL that answered with the redirect
     * @param location  the redirect's {@code Location}, or {@code null}
     * @param redirects how many redirects were followed before this one
     * @return where the redirect leads
     * @throws IOException if the redirect has no location, leaves the API, or
     *         is one too many
     */
    private static URL redirect(URL origin, URL from, int status, String location, int redirects) throws IOException {
        if (location == null || location.isEmpty()) {
            throw new IOException("HTTP " + status + " without a Location");
        }
        if (redirects >= MAX_REDIRECTS) {
            throw new IOException("HTTP " + status + " after " + MAX_REDIRECTS + " redirects");
        }
        URL to;
        try {
            to = new URL(from, location);
        } catch (MalformedURLException e) {
            throw new IOException("HTTP " + status + " to an invalid Location");
        }
        if (!sameOrigin(origin, to)) {
            throw new IOException("HTTP " + status + " to somewhere other than the API: "
                + to.getProtocol() + "://" + to.getHost() + ":" + port(to));
        }
        return to;
    }

    /**
     * @return whether both URLs have the same scheme, host and port, and the
     *         second has no user info
     */
    static boolean sameOrigin(URL origin, URL to) {
        return sameAscii(origin.getProtocol(), to.getProtocol())
            && sameAscii(origin.getHost(), to.getHost())
            && port(origin) == port(to)
            && to.getUserInfo() == null;
    }

    /**
     * Compare ignoring case, but only ASCII text, since Unicode case folding
     * lets other letters stand in for ASCII ones, such as the Kelvin sign
     * for {@code k}
     */
    private static boolean sameAscii(String a, String b) {
        return a.chars().allMatch(c -> c < 0x80) && b.chars().allMatch(c -> c < 0x80) && a.equalsIgnoreCase(b);
    }

    private static int port(URL url) {
        return url.getPort() != -1 ? url.getPort() : url.getDefaultPort();
    }

    private void checkDeadline(AtomicBoolean expired) throws IOException {
        if (expired.get()) {
            throw deadlinePassed();
        }
    }

    private IOException deadlinePassed() {
        return new IOException("the response took longer than " + (totalTimeoutMillis % 1000 == 0
            ? totalTimeoutMillis / 1000 + " s" : totalTimeoutMillis + " ms"));
    }

    private static String reason(int status) {
        switch (status) {
            case HttpURLConnection.HTTP_NOT_FOUND:
                return " (not found)";
            case HttpURLConnection.HTTP_FORBIDDEN:
                return " (forbidden or rate limited)";
            case 429:
                return " (rate limited)";
            default:
                return "";
        }
    }

    private byte[] read(InputStream in, AtomicBoolean expired) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) != -1) {
            checkDeadline(expired);
            body.write(buffer, 0, read);
            if (body.size() > MAX_RESPONSE_BYTES) {
                throw tooLarge();
            }
        }
        checkDeadline(expired);
        return body.toByteArray();
    }

    private static IOException tooLarge() {
        return new IOException("the response is larger than " + MAX_RESPONSE_BYTES / 1024 / 1024 + " MiB");
    }
}
