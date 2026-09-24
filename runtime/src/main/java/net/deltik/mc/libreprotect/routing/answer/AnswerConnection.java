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

import net.deltik.mc.libreprotect.LibreProtectVersion;
import net.deltik.mc.libreprotect.PrivacyConstants;
import net.deltik.mc.libreprotect.routing.UrlNormalizer;

import javax.net.ssl.HttpsURLConnection;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.security.Permission;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * A connection that LibreProtect answers itself, without connecting to
 * anything.
 *
 * <p>It extends {@link HttpsURLConnection} rather than {@link HttpURLConnection}
 * so it survives both casts that callers make: CoreProtect casts to
 * {@code HttpURLConnection}, and bStats casts to {@code HttpsURLConnection}.
 *
 * <p>The {@link Answer} is asked once, by the first call that needs the reply:
 * {@link #connect()}, {@link #getResponseCode()}, {@link #getInputStream()}, or
 * a header getter such as {@link #getContentType()}. It sees the request
 * properties and whatever was written to {@link #getOutputStream()} by then.
 * If the answer fails, its {@link IOException} comes out of every call that
 * can throw one, as a failed connection's would, and the header getters
 * return nothing.
 */
public class AnswerConnection extends HttpsURLConnection {

    private static final String REASON = "Answered by " + PrivacyConstants.FORK_NAME;

    private final Answer answer;
    private final Map<String, String> requestProperties = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private ByteArrayOutputStream requestBody;
    private Response response;
    private IOException failure;

    public AnswerConnection(URL url, Answer answer) {
        super(url);
        this.answer = Objects.requireNonNull(answer, "answer");
    }

    /**
     * @return the answer's reply, asking for it on the first call
     * @throws IOException the answer's failure, on this and every later call
     */
    private Response response() throws IOException {
        if (response == null && failure == null) {
            try {
                response = Objects.requireNonNull(answer.answer(request()), "The answer gave no response");
                connected = true;
            } catch (IOException e) {
                failure = e;
            } catch (RuntimeException e) {
                // A broken answer fails the request like any other answer failure
                failure = new IOException(PrivacyConstants.FORK_NAME + " couldn't answer "
                    + UrlNormalizer.normalize(url) + ": " + e, e);
            }
        }
        if (failure != null) {
            throw failure;
        }
        return response;
    }

    /**
     * @return the answer's reply, or {@code null} if the answer failed
     */
    private Response responseOrNull() {
        try {
            return response();
        } catch (IOException e) {
            return null;
        }
    }

    private Request request() {
        byte[] body = requestBody == null ? new byte[0] : requestBody.toByteArray();
        return new Request(url, method, requestProperties, body);
    }

    @Override
    public void connect() throws IOException {
        response();
    }

    @Override
    public void disconnect() {
        connected = false;
        requestBody = null;
    }

    @Override
    public boolean usingProxy() {
        return true; // We are effectively a proxy
    }

    @Override
    public int getResponseCode() throws IOException {
        return response().status();
    }

    @Override
    public String getResponseMessage() throws IOException {
        response();
        return REASON;
    }

    /**
     * @throws FileNotFoundException for status 404 or 410, and
     *         {@link IOException} for any other status from 400 up, as
     *         {@code HttpURLConnection} does; the body is in
     *         {@link #getErrorStream()} then
     */
    @Override
    public InputStream getInputStream() throws IOException {
        Response reply = response();
        if (reply.status() >= HTTP_BAD_REQUEST) {
            String message = PrivacyConstants.FORK_NAME + " answered with HTTP response code " + reply.status()
                + " for URL: " + UrlNormalizer.normalize(url);
            if (reply.status() == HTTP_NOT_FOUND || reply.status() == HTTP_GONE) {
                throw new FileNotFoundException(message);
            }
            throw new IOException(message);
        }
        return new ByteArrayInputStream(reply.body());
    }

    /**
     * @return the body of an error reply (status 400 and up), or {@code null}
     *         if there is none yet; this doesn't ask the answer
     */
    @Override
    public InputStream getErrorStream() {
        if (response == null || response.status() < HTTP_BAD_REQUEST) {
            return null;
        }
        return new ByteArrayInputStream(response.body());
    }

    /**
     * @throws ProtocolException if the answer was already asked, because it
     *         wouldn't see anything written now
     */
    @Override
    public OutputStream getOutputStream() throws IOException {
        if (response != null || failure != null) {
            throw new ProtocolException("Cannot write output after " + PrivacyConstants.FORK_NAME
                + " answered the request");
        }
        if (requestBody == null) {
            requestBody = new ByteArrayOutputStream();
        }
        return requestBody;
    }

    @Override
    public String getHeaderField(String name) {
        Response reply = responseOrNull();
        if (reply == null) {
            return null;
        }
        if ("Content-Type".equalsIgnoreCase(name)) {
            return reply.contentType();
        }
        if ("Server".equalsIgnoreCase(name)) {
            return serverHeader();
        }
        return null;
    }

    @Override
    public String getHeaderField(int n) {
        Response reply = responseOrNull();
        if (reply == null) {
            return null;
        }
        switch (n) {
            case 0: return "HTTP/1.1 " + reply.status() + " " + REASON;
            case 1: return reply.contentType();
            case 2: return serverHeader();
            default: return null;
        }
    }

    @Override
    public String getHeaderFieldKey(int n) {
        if (responseOrNull() == null) {
            return null;
        }
        switch (n) {
            case 1: return "Content-Type";
            case 2: return "Server";
            default: return null;
        }
    }

    @Override
    public Map<String, List<String>> getHeaderFields() {
        Response reply = responseOrNull();
        if (reply == null) {
            return Collections.emptyMap();
        }
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Content-Type", Collections.singletonList(reply.contentType()));
        headers.put("Server", Collections.singletonList(serverHeader()));
        return Collections.unmodifiableMap(headers);
    }

    private static String serverHeader() {
        return PrivacyConstants.FORK_NAME + "/" + LibreProtectVersion.getForkVersion();
    }

    @Override
    public Permission getPermission() {
        return null;
    }

    @Override
    public void setRequestProperty(String key, String value) {
        requestProperties.put(key, value);
    }

    @Override
    public void addRequestProperty(String key, String value) {
        requestProperties.put(key, value);
    }

    @Override
    public String getRequestProperty(String key) {
        return key == null ? null : requestProperties.get(key);
    }

    @Override
    public Map<String, List<String>> getRequestProperties() {
        Map<String, List<String>> result = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (Map.Entry<String, String> entry : requestProperties.entrySet()) {
            result.put(entry.getKey(), Collections.singletonList(entry.getValue()));
        }
        return Collections.unmodifiableMap(result);
    }

    @Override
    public void setRequestMethod(String method) {
        this.method = method;
    }

    @Override
    public void setConnectTimeout(int timeout) {
        // Nothing to time out
    }

    @Override
    public int getConnectTimeout() {
        return 0;
    }

    @Override
    public void setReadTimeout(int timeout) {
        // Nothing to time out
    }

    @Override
    public int getReadTimeout() {
        return 0;
    }

    // HttpsURLConnection

    @Override
    public String getCipherSuite() {
        return "NONE";
    }

    @Override
    public Certificate[] getLocalCertificates() {
        return null;
    }

    @Override
    public Certificate[] getServerCertificates() {
        return new Certificate[0];
    }
}
