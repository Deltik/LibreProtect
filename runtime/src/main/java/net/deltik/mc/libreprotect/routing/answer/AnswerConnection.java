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

import javax.net.ssl.HttpsURLConnection;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Permission;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A connection that LibreProtect answers itself, without connecting to
 * anything.
 *
 * <p>It extends {@link HttpsURLConnection} rather than {@link HttpURLConnection}
 * so it survives both casts that callers make: CoreProtect casts to
 * {@code HttpURLConnection}, and bStats casts to {@code HttpsURLConnection}.
 *
 * <p>The license endpoint is deliberately not answerable. CoreProtect saves
 * validated keys to {@code plugins/CoreProtect/.license}, and stock CoreProtect
 * trusts that file when it is offline, so an answered license would leak out
 * of LibreProtect.
 */
public class AnswerConnection extends HttpsURLConnection {

    /** The answer to a translation request: no translations */
    private static final String TRANSLATION_ANSWER = "{}";

    private ByteArrayOutputStream outputStream;
    private final Map<String, String> requestProperties = new HashMap<>();

    public AnswerConnection(URL url) {
        super(url);
    }

    @Override
    public void connect() {
        connected = true;
    }

    @Override
    public void disconnect() {
        connected = false;
        outputStream = null;
    }

    @Override
    public boolean usingProxy() {
        return true; // We are effectively a proxy
    }

    @Override
    public int getResponseCode() {
        return HttpURLConnection.HTTP_OK;
    }

    @Override
    public String getResponseMessage() {
        return "OK (Answered by " + PrivacyConstants.FORK_NAME + ")";
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return new ByteArrayInputStream(generateAnswer().getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public InputStream getErrorStream() {
        return null;
    }

    @Override
    public OutputStream getOutputStream() {
        if (outputStream == null) {
            outputStream = new ByteArrayOutputStream();
        }
        return outputStream;
    }

    /**
     * Generate the answer for the endpoint
     */
    private String generateAnswer() throws IOException {
        String host = url.getHost().toLowerCase(Locale.ROOT);
        String path = url.getPath() != null ? url.getPath().toLowerCase(Locale.ROOT) : "";

        // Translation endpoint: no translations
        if (host.equals("coreprotect.net") && (path.equals("/translate/") || path.equals("/translate"))) {
            return TRANSLATION_ANSWER;
        }

        // Version check endpoints: report the running version so no update is announced
        if (host.equals("update.coreprotect.net")) {
            String userAgent = requestProperties.get("User-Agent");
            if (userAgent != null && userAgent.startsWith("CoreProtect/v")) {
                // User-Agent: "CoreProtect/vX.Y.Z (by Intelli)"
                return userAgent.substring("CoreProtect/v".length()).split(" ")[0];
            }
            return "0.0";
        }

        // Statistics endpoint: accepted and discarded
        if (host.equals("stats.coreprotect.net")) {
            return "";
        }

        throw new IOException(PrivacyConstants.FORK_NAME + " can't answer requests to "
            + url.getProtocol() + "://" + url.getHost() + url.getPath()
            + "; use BLOCK for it instead. If upstream added this endpoint, please report it at "
            + PrivacyConstants.FORK_ISSUE_URL);
    }

    @Override
    public String getHeaderField(String name) {
        if ("Content-Type".equalsIgnoreCase(name)) {
            return getContentType();
        }
        if ("Server".equalsIgnoreCase(name)) {
            return serverHeader();
        }
        return null;
    }

    @Override
    public String getContentType() {
        String path = url.getPath();
        if (path != null && path.contains("translate")) {
            return "application/json; charset=utf-8";
        }
        return "text/plain; charset=utf-8";
    }

    @Override
    public String getHeaderField(int n) {
        switch (n) {
            case 0: return "HTTP/1.1 200 OK";
            case 1: return getContentType();
            case 2: return serverHeader();
            default: return null;
        }
    }

    @Override
    public String getHeaderFieldKey(int n) {
        switch (n) {
            case 1: return "Content-Type";
            case 2: return "Server";
            default: return null;
        }
    }

    @Override
    public Map<String, List<String>> getHeaderFields() {
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("Content-Type", Collections.singletonList(getContentType()));
        headers.put("Server", Collections.singletonList(serverHeader()));
        return headers;
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
        return requestProperties.get(key);
    }

    @Override
    public Map<String, List<String>> getRequestProperties() {
        Map<String, List<String>> result = new HashMap<>();
        for (Map.Entry<String, String> entry : requestProperties.entrySet()) {
            result.put(entry.getKey(), Collections.singletonList(entry.getValue()));
        }
        return result;
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
