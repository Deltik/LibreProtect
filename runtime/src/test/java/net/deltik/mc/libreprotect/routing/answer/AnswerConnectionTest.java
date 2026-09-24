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

import net.deltik.mc.libreprotect.PrivacyConstants;
import net.deltik.mc.libreprotect.testutil.MockUrlFactory;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class AnswerConnectionTest {

    @Nested
    @DisplayName("Connection Type")
    class ConnectionType {

        @Test
        @DisplayName("should survive a cast to HttpURLConnection, as CoreProtect does")
        void castsToHttpURLConnection() {
            URLConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            HttpURLConnection http = assertInstanceOf(HttpURLConnection.class, conn);
            assertDoesNotThrow(() -> http.setRequestMethod("GET"));
        }

        @Test
        @DisplayName("should survive a cast to HttpsURLConnection, as bStats does")
        void castsToHttpsURLConnection() {
            URLConnection conn = new AnswerConnection(MockUrlFactory.httpsStatsUrl());
            HttpsURLConnection https = assertInstanceOf(HttpsURLConnection.class, conn);
            assertEquals("NONE", https.getCipherSuite());
        }

        @Test
        @DisplayName("should be an HttpsURLConnection even for http:// URLs")
        void httpsEvenForHttpUrls() {
            URLConnection conn = new AnswerConnection(MockUrlFactory.statsUrl());
            assertInstanceOf(HttpsURLConnection.class, conn);
            assertInstanceOf(HttpURLConnection.class, conn);
        }

        @Test
        @DisplayName("HttpsURLConnection accessors should not throw")
        void httpsAccessorsDoNotThrow() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.httpsStatsUrl());
            assertNull(conn.getLocalCertificates());
            assertEquals(0, conn.getServerCertificates().length);
            assertNotNull(conn.getHostnameVerifier());
            assertNotNull(conn.getSSLSocketFactory());
        }
    }

    @Nested
    @DisplayName("HTTP Response Behavior")
    class HttpResponseBehavior {

        @Test
        @DisplayName("should return HTTP 200 OK")
        void returnsHttp200() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            assertEquals(HttpURLConnection.HTTP_OK, conn.getResponseCode());
        }

        @Test
        @DisplayName("should say in the response message that LibreProtect answered")
        void returnsAnsweredResponseMessage() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            String message = conn.getResponseMessage();
            assertTrue(message.contains(PrivacyConstants.FORK_NAME));
            assertTrue(message.contains("Answered"));
        }

        @Test
        @DisplayName("should return null error stream")
        void returnsNullErrorStream() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            assertNull(conn.getErrorStream());
        }
    }

    @Nested
    @DisplayName("License Endpoint")
    class LicenseEndpoint {

        // An answered license would be saved to plugins/CoreProtect/.license and
        // trusted by stock CoreProtect later, so the license is never answered.

        @Test
        @DisplayName("should refuse to answer the license endpoint")
        void refusesLicense() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.licenseUrl());
            IOException ex = assertThrows(IOException.class, conn::getInputStream);
            assertTrue(ex.getMessage().contains("coreprotect.net/license/"), ex.getMessage());
        }

        @ParameterizedTest
        @DisplayName("should refuse any license key over http or https")
        @ValueSource(strings = {
            "http://coreprotect.net/license/ANYKEY12",
            "https://coreprotect.net/license/TESTKEY",
            "https://CoreProtect.net/license/12345678"
        })
        void refusesAnyLicenseKey(String spec) {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.createUrl(spec));
            assertThrows(IOException.class, conn::getInputStream);
        }

        @Test
        @DisplayName("should tell the operator to BLOCK the route instead")
        void suggestsBlock() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.httpsLicenseUrl());
            IOException ex = assertThrows(IOException.class, conn::getInputStream);
            assertTrue(ex.getMessage().contains("BLOCK"), ex.getMessage());
            assertTrue(ex.getMessage().contains(PrivacyConstants.FORK_NAME), ex.getMessage());
        }

        @Test
        @DisplayName("should refuse to produce content through getContent()")
        void refusesContent() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.licenseUrl());
            assertThrows(IOException.class, conn::getContent);
        }
    }

    @Nested
    @DisplayName("Translation Endpoint")
    class TranslationEndpoint {

        @Test
        @DisplayName("should return empty JSON response")
        void returnsEmptyJsonResponse() throws IOException {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.translateUrl());
            String response = readInputStream(conn.getInputStream());
            assertEquals("{}", response);
        }

        @Test
        @DisplayName("should return JSON content type")
        void returnsJsonContentType() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.translateUrl());
            String contentType = conn.getHeaderField("Content-Type");
            assertTrue(contentType.contains("application/json"));
        }

        @Test
        @DisplayName("should match the host case-insensitively")
        void matchesHostCaseInsensitively() throws IOException {
            AnswerConnection conn = new AnswerConnection(
                MockUrlFactory.createUrl("https://CoreProtect.NET/translate/"));
            assertEquals("{}", readInputStream(conn.getInputStream()));
        }
    }

    @Nested
    @DisplayName("Update Endpoint")
    class UpdateEndpoint {

        @Test
        @DisplayName("should extract version from User-Agent header")
        void extractsVersionFromUserAgent() throws IOException {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            conn.setRequestProperty("User-Agent", "CoreProtect/v21.3 (by Intelli)");

            String response = readInputStream(conn.getInputStream());
            assertEquals("21.3", response);
        }

        @Test
        @DisplayName("should extract version when User-Agent was added rather than set")
        void extractsVersionFromAddedUserAgent() throws IOException {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateEdgeUrl());
            conn.addRequestProperty("User-Agent", "CoreProtect/v24.1 (by Intelli)");

            assertEquals("24.1", readInputStream(conn.getInputStream()));
        }

        @Test
        @DisplayName("should report no newer version when there is no User-Agent")
        void reportsNoUpdateWithoutUserAgent() throws IOException {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            String response = readInputStream(conn.getInputStream());
            assertEquals("0.0", response);
        }

        @Test
        @DisplayName("should report no newer version for a foreign User-Agent")
        void reportsNoUpdateForForeignUserAgent() throws IOException {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            conn.setRequestProperty("User-Agent", "Java/21");
            assertEquals("0.0", readInputStream(conn.getInputStream()));
        }

        @Test
        @DisplayName("should work for edge update endpoint")
        void worksForEdgeEndpoint() throws IOException {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateEdgeUrl());
            String response = readInputStream(conn.getInputStream());
            assertEquals("0.0", response);
        }
    }

    @Nested
    @DisplayName("Stats Endpoint")
    class StatsEndpoint {

        @Test
        @DisplayName("should return empty response")
        void returnsEmptyResponse() throws IOException {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.statsUrl());
            String response = readInputStream(conn.getInputStream());
            assertEquals("", response);
        }

        @Test
        @DisplayName("should accept and discard a request body")
        void acceptsRequestBody() throws IOException {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.httpsStatsUrl());
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write("{\"players\":1}".getBytes(StandardCharsets.UTF_8));
            }
            assertEquals(HttpURLConnection.HTTP_OK, conn.getResponseCode());
            assertEquals("", readInputStream(conn.getInputStream()));
        }
    }

    @Nested
    @DisplayName("Unknown Endpoint Handling")
    class UnknownEndpoint {

        @Test
        @DisplayName("should throw IOException for unknown endpoint")
        void throwsForUnknownEndpoint() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.unknownUrl());
            IOException ex = assertThrows(IOException.class, () -> conn.getInputStream());
            assertTrue(ex.getMessage().contains("can't answer requests to"), ex.getMessage());
            assertTrue(ex.getMessage().contains("unknown.example.com/path"), ex.getMessage());
            assertTrue(ex.getMessage().contains(PrivacyConstants.FORK_NAME));
            assertTrue(ex.getMessage().contains(PrivacyConstants.FORK_ISSUE_URL));
        }

        @ParameterizedTest
        @DisplayName("should throw IOException for other CoreProtect and bStats endpoints")
        @ValueSource(strings = {
            "https://error-reporting.coreprotect.net/submit",
            "https://bStats.org/api/v2/data/bukkit",
            "http://coreprotect.net/somewhere-else/"
        })
        void throwsForOtherEndpoints(String spec) {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.createUrl(spec));
            assertThrows(IOException.class, conn::getInputStream);
        }

        @Test
        @DisplayName("should not leak user info from the URL into the message")
        void doesNotLeakUserInfo() {
            AnswerConnection conn = new AnswerConnection(
                MockUrlFactory.createUrl("https://user:secret@unknown.example.com/path?q=1#frag"));
            IOException ex = assertThrows(IOException.class, conn::getInputStream);
            assertFalse(ex.getMessage().contains("secret"), ex.getMessage());
        }
    }

    @Nested
    @DisplayName("Connection Lifecycle")
    class ConnectionLifecycle {

        @Test
        @DisplayName("connect() should mark as connected")
        void connectMarksAsConnected() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            conn.connect();
            // Connected connections refuse further configuration
            assertThrows(IllegalStateException.class, () -> conn.setDoOutput(true));
        }

        @Test
        @DisplayName("disconnect() should clean up")
        void disconnectCleansUp() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            conn.connect();
            OutputStream first = conn.getOutputStream();
            conn.disconnect();
            assertNotSame(first, conn.getOutputStream());
        }

        @Test
        @DisplayName("usingProxy() should return true")
        void usingProxyReturnsTrue() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            assertTrue(conn.usingProxy());
        }

        @Test
        @DisplayName("getPermission() should return null")
        void getPermissionReturnsNull() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            assertNull(conn.getPermission());
        }
    }

    @Nested
    @DisplayName("Request Properties")
    class RequestProperties {

        @Test
        @DisplayName("should store and retrieve request properties")
        void storesRequestProperties() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            conn.setRequestProperty("Custom-Header", "custom-value");
            assertEquals("custom-value", conn.getRequestProperty("Custom-Header"));
        }

        @Test
        @DisplayName("addRequestProperty should behave like setRequestProperty")
        void addRequestPropertyWorks() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            conn.addRequestProperty("Header", "value");
            assertEquals("value", conn.getRequestProperty("Header"));
        }

        @Test
        @DisplayName("getRequestProperties() should return map")
        void getRequestPropertiesReturnsMap() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            conn.setRequestProperty("Key", "Value");
            var props = conn.getRequestProperties();
            assertTrue(props.containsKey("Key"));
            assertEquals(java.util.List.of("Value"), props.get("Key"));
        }
    }

    @Nested
    @DisplayName("Headers")
    class Headers {

        @Test
        @DisplayName("should return a Server header naming LibreProtect")
        void returnsServerHeader() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            String server = conn.getHeaderField("Server");
            assertTrue(server.contains(PrivacyConstants.FORK_NAME));
        }

        @Test
        @DisplayName("should return Content-Type header")
        void returnsContentTypeHeader() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            String contentType = conn.getHeaderField("Content-Type");
            assertNotNull(contentType);
            assertTrue(contentType.startsWith("text/plain"));
        }

        @Test
        @DisplayName("should match header names case-insensitively")
        void headerNamesCaseInsensitive() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            assertEquals(conn.getHeaderField("Content-Type"), conn.getHeaderField("content-type"));
            assertNull(conn.getHeaderField("X-Unknown"));
        }

        @Test
        @DisplayName("getHeaderFields() should return map")
        void getHeaderFieldsReturnsMap() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            var headers = conn.getHeaderFields();
            assertNotNull(headers);
            assertTrue(headers.containsKey("Content-Type"));
            assertTrue(headers.containsKey("Server"));
        }

        @Test
        @DisplayName("getHeaderField(int) should return header by index")
        void getHeaderFieldByIndex() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            assertEquals("HTTP/1.1 200 OK", conn.getHeaderField(0)); // Status line
            assertEquals(conn.getContentType(), conn.getHeaderField(1));
            assertNull(conn.getHeaderField(3));
        }

        @Test
        @DisplayName("getHeaderFieldKey(int) should return key by index")
        void getHeaderFieldKeyByIndex() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            assertNull(conn.getHeaderFieldKey(0)); // Status line has no key
            assertEquals("Content-Type", conn.getHeaderFieldKey(1));
            assertEquals("Server", conn.getHeaderFieldKey(2));
        }

        @Test
        @DisplayName("getContentLength() should be unknown")
        void contentLengthUnknown() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            assertEquals(-1, conn.getContentLength());
        }
    }

    @Nested
    @DisplayName("Input/Output Settings")
    class InputOutputSettings {

        @Test
        @DisplayName("setDoInput should be accepted")
        void setDoInputWorks() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            conn.setDoInput(true);
            assertTrue(conn.getDoInput());
        }

        @Test
        @DisplayName("setDoOutput should be accepted")
        void setDoOutputWorks() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            conn.setDoOutput(true);
            assertTrue(conn.getDoOutput());
        }

        @Test
        @DisplayName("getOutputStream should return writable stream")
        void getOutputStreamReturnsStream() throws IOException {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            OutputStream os = conn.getOutputStream();
            assertNotNull(os);
            os.write("test".getBytes());
            assertSame(os, conn.getOutputStream());
        }
    }

    @Nested
    @DisplayName("Request Method")
    class RequestMethod {

        @Test
        @DisplayName("setRequestMethod should be accepted")
        void setRequestMethodWorks() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            conn.setRequestMethod("POST");
            assertEquals("POST", conn.getRequestMethod());
        }
    }

    @Nested
    @DisplayName("Redirect Settings")
    class RedirectSettings {

        @Test
        @DisplayName("setInstanceFollowRedirects should be accepted")
        void setFollowRedirectsWorks() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            conn.setInstanceFollowRedirects(false);
            assertFalse(conn.getInstanceFollowRedirects());
        }
    }

    @Nested
    @DisplayName("Timeout Settings")
    class TimeoutSettings {

        @Test
        @DisplayName("setConnectTimeout should be ignored")
        void connectTimeoutIgnored() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            conn.setConnectTimeout(5000);
            assertEquals(0, conn.getConnectTimeout());
        }

        @Test
        @DisplayName("setReadTimeout should be ignored")
        void readTimeoutIgnored() {
            AnswerConnection conn = new AnswerConnection(MockUrlFactory.updateUrl());
            conn.setReadTimeout(5000);
            assertEquals(0, conn.getReadTimeout());
        }
    }

    @Nested
    @DisplayName("URL")
    class UrlAccess {

        @Test
        @DisplayName("getURL() should return the requested URL")
        void returnsRequestedUrl() {
            URL url = MockUrlFactory.updateUrl();
            assertSame(url, new AnswerConnection(url).getURL());
        }
    }

    // Helper method
    private String readInputStream(InputStream is) throws IOException {
        try (is) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
