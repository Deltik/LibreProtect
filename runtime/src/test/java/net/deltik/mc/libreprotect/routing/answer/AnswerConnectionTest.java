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
import net.deltik.mc.libreprotect.testutil.RecordingAnswer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class AnswerConnectionTest {

    /**
     * @return a connection that LibreProtect's own answers answer
     */
    private static AnswerConnection connection(URL url) {
        return new AnswerConnection(url, AnswerRegistry.defaults());
    }

    private static AnswerConnection connection(Answer answer) {
        return new AnswerConnection(MockUrlFactory.updateUrl(), answer);
    }

    private interface Call {
        Object on(AnswerConnection conn) throws IOException;
    }

    /**
     * Calls that need the answer's reply
     */
    enum ReplyCall {
        CONNECT(conn -> {
            conn.connect();
            return null;
        }),
        GET_RESPONSE_CODE(HttpURLConnection::getResponseCode),
        GET_RESPONSE_MESSAGE(HttpURLConnection::getResponseMessage),
        GET_INPUT_STREAM(URLConnection::getInputStream),
        GET_CONTENT(URLConnection::getContent),
        GET_CONTENT_TYPE(URLConnection::getContentType),
        GET_CONTENT_LENGTH(URLConnection::getContentLength),
        GET_HEADER_FIELD(conn -> conn.getHeaderField("Server")),
        GET_HEADER_FIELD_BY_INDEX(conn -> conn.getHeaderField(0)),
        GET_HEADER_FIELD_KEY(conn -> conn.getHeaderFieldKey(1)),
        GET_HEADER_FIELDS(URLConnection::getHeaderFields);

        private final Call call;

        ReplyCall(Call call) {
            this.call = call;
        }

        Object on(AnswerConnection conn) throws IOException {
            return call.on(conn);
        }
    }

    @Nested
    @DisplayName("Connection Type")
    class ConnectionType {

        @Test
        @DisplayName("should survive a cast to HttpURLConnection, as CoreProtect does")
        void castsToHttpURLConnection() {
            URLConnection conn = connection(MockUrlFactory.updateUrl());
            HttpURLConnection http = assertInstanceOf(HttpURLConnection.class, conn);
            assertDoesNotThrow(() -> http.setRequestMethod("GET"));
        }

        @Test
        @DisplayName("should survive a cast to HttpsURLConnection, as bStats does")
        void castsToHttpsURLConnection() {
            URLConnection conn = connection(MockUrlFactory.httpsStatsUrl());
            HttpsURLConnection https = assertInstanceOf(HttpsURLConnection.class, conn);
            assertEquals("NONE", https.getCipherSuite());
        }

        @Test
        @DisplayName("should be an HttpsURLConnection even for http:// URLs")
        void httpsEvenForHttpUrls() {
            URLConnection conn = connection(MockUrlFactory.statsUrl());
            assertInstanceOf(HttpsURLConnection.class, conn);
            assertInstanceOf(HttpURLConnection.class, conn);
        }

        @Test
        @DisplayName("HttpsURLConnection accessors should not throw")
        void httpsAccessorsDoNotThrow() {
            AnswerConnection conn = connection(MockUrlFactory.httpsStatsUrl());
            assertNull(conn.getLocalCertificates());
            assertEquals(0, conn.getServerCertificates().length);
            assertNotNull(conn.getHostnameVerifier());
            assertNotNull(conn.getSSLSocketFactory());
        }

        @Test
        @DisplayName("should require an answer")
        void requiresAnswer() {
            assertThrows(NullPointerException.class, () -> new AnswerConnection(MockUrlFactory.updateUrl(), null));
        }
    }

    @Nested
    @DisplayName("HTTP Response Behavior")
    class HttpResponseBehavior {

        @Test
        @DisplayName("should return HTTP 200 OK")
        void returnsHttp200() throws IOException {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            assertEquals(HttpURLConnection.HTTP_OK, conn.getResponseCode());
        }

        @Test
        @DisplayName("should return the answer's status")
        void returnsAnswerStatus() throws IOException {
            AnswerConnection conn = connection(RecordingAnswer.replying(
                new Response(HttpURLConnection.HTTP_ACCEPTED, "text/plain", new byte[0])));
            assertEquals(HttpURLConnection.HTTP_ACCEPTED, conn.getResponseCode());
        }

        @Test
        @DisplayName("should say in the response message that LibreProtect answered")
        void returnsAnsweredResponseMessage() throws IOException {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            String message = conn.getResponseMessage();
            assertTrue(message.contains(PrivacyConstants.FORK_NAME));
            assertTrue(message.contains("Answered"));
        }

        @Test
        @DisplayName("should return the answer's body")
        void returnsAnswerBody() throws IOException {
            AnswerConnection conn = connection(RecordingAnswer.replying(Response.text("héllo")));
            assertEquals("héllo", readInputStream(conn.getInputStream()));
        }

        @Test
        @DisplayName("should return a fresh input stream each time")
        void freshInputStream() throws IOException {
            AnswerConnection conn = connection(RecordingAnswer.replying(Response.text("body")));
            assertEquals("body", readInputStream(conn.getInputStream()));
            assertEquals("body", readInputStream(conn.getInputStream()));
        }

        @Test
        @DisplayName("should return null error stream")
        void returnsNullErrorStream() throws IOException {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            conn.getResponseCode();
            assertNull(conn.getErrorStream());
        }
    }

    @Nested
    @DisplayName("Asking the Answer")
    class AskingTheAnswer {

        private final RecordingAnswer answer = RecordingAnswer.replying(Response.text("reply"));

        @Test
        @DisplayName("should not ask the answer while the request is being built")
        void notAskedEarly() throws IOException {
            AnswerConnection conn = connection(answer);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("User-Agent", "test");
            conn.setDoOutput(true);
            conn.getOutputStream().write(1);
            conn.getRequestProperties();
            assertNull(conn.getErrorStream());

            assertEquals(0, answer.calls());
        }

        @ParameterizedTest
        @DisplayName("should ask the answer on the first call that needs the reply")
        @EnumSource(ReplyCall.class)
        void askedByCall(ReplyCall call) throws IOException {
            call.on(connection(answer));
            assertEquals(1, answer.calls());
        }

        @Test
        @DisplayName("should ask the answer only once")
        void askedOnce() throws IOException {
            AnswerConnection conn = connection(answer);
            for (ReplyCall call : ReplyCall.values()) {
                call.on(conn);
                call.on(conn);
            }
            assertEquals(1, answer.calls());
        }

        @Test
        @DisplayName("should show the answer the URL, method, request properties and body")
        void passesRequest() throws IOException {
            URL url = MockUrlFactory.translateUrl();
            AnswerConnection conn = new AnswerConnection(url, answer);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write("data={}".getBytes(StandardCharsets.UTF_8));
            }
            conn.getResponseCode();

            Request request = answer.lastRequest();
            assertSame(url, request.url());
            assertEquals("POST", request.method());
            assertEquals("application/x-www-form-urlencoded; charset=utf-8", request.header("content-type"));
            assertEquals("data={}", new String(request.body(), StandardCharsets.UTF_8));
        }

        @Test
        @DisplayName("should show the answer a GET with no body when nothing was set")
        void passesDefaultRequest() throws IOException {
            connection(answer).connect();

            Request request = answer.lastRequest();
            assertEquals("GET", request.method());
            assertTrue(request.headers().isEmpty());
            assertEquals(0, request.body().length);
        }

        @Test
        @DisplayName("should refuse a request body once the answer was asked, since the answer wouldn't see it")
        void refusesLateOutput() throws IOException {
            AnswerConnection conn = connection(answer);
            conn.connect();
            assertThrows(ProtocolException.class, conn::getOutputStream);
        }

        @Test
        @DisplayName("should mark the connection as connected once answered")
        void connectedOnceAnswered() throws IOException {
            AnswerConnection conn = connection(answer);
            conn.getResponseCode();
            // Connected connections refuse further configuration
            assertThrows(IllegalStateException.class, () -> conn.setDoOutput(true));
        }
    }

    @Nested
    @DisplayName("Answer Failure")
    class AnswerFailure {

        private final IOException failure = new IOException("offline");
        private final RecordingAnswer answer = RecordingAnswer.failing(failure);

        @ParameterizedTest
        @DisplayName("should throw the answer's IOException, as a failed connection would")
        @EnumSource(value = ReplyCall.class,
            names = {"CONNECT", "GET_RESPONSE_CODE", "GET_RESPONSE_MESSAGE", "GET_INPUT_STREAM", "GET_CONTENT"})
        void throwsFailure(ReplyCall call) {
            AnswerConnection conn = connection(answer);
            assertSame(failure, assertThrows(IOException.class, () -> call.on(conn)));
        }

        @Test
        @DisplayName("should keep failing with the same IOException without asking again")
        void keepsFailing() {
            AnswerConnection conn = connection(answer);

            assertSame(failure, assertThrows(IOException.class, conn::connect));
            assertSame(failure, assertThrows(IOException.class, conn::getResponseCode));
            assertSame(failure, assertThrows(IOException.class, conn::getInputStream));
            assertEquals(1, answer.calls());
        }

        @Test
        @DisplayName("header getters should return nothing")
        void headersEmpty() {
            AnswerConnection conn = connection(answer);

            assertNull(conn.getContentType());
            assertNull(conn.getHeaderField("Server"));
            assertNull(conn.getHeaderField(0));
            assertNull(conn.getHeaderFieldKey(1));
            assertTrue(conn.getHeaderFields().isEmpty());
            assertEquals(-1, conn.getContentLength());
            assertNull(conn.getErrorStream());
            assertEquals(1, answer.calls());
        }

        @Test
        @DisplayName("a failed connect() should leave the connection unconnected")
        void unconnectedAfterFailure() {
            AnswerConnection conn = connection(answer);
            assertThrows(IOException.class, conn::connect);
            assertDoesNotThrow(() -> conn.setDoOutput(true));
        }

        @Test
        @DisplayName("should refuse a request body after the answer failed")
        void refusesOutputAfterFailure() {
            AnswerConnection conn = connection(answer);
            assertThrows(IOException.class, conn::connect);
            assertThrows(ProtocolException.class, conn::getOutputStream);
        }

        @Test
        @DisplayName("should turn a RuntimeException from the answer into an IOException")
        void wrapsRuntimeException() {
            IllegalStateException bug = new IllegalStateException("broken");
            AnswerConnection conn = new AnswerConnection(
                MockUrlFactory.createUrl("http://user:secret@update.coreprotect.net/version/"), request -> {
                    throw bug;
                });

            IOException ex = assertThrows(IOException.class, conn::getResponseCode);
            assertSame(bug, ex.getCause());
            assertTrue(ex.getMessage().contains(PrivacyConstants.FORK_NAME), ex.getMessage());
            assertTrue(ex.getMessage().contains("http://update.coreprotect.net/version/"), ex.getMessage());
            assertFalse(ex.getMessage().contains("secret"), ex.getMessage());
        }

        @Test
        @DisplayName("should fail when the answer gives no response")
        void failsWithoutResponse() {
            AnswerConnection conn = connection(request -> null);
            assertThrows(IOException.class, conn::getInputStream);
        }
    }

    @Nested
    @DisplayName("Error Replies")
    class ErrorReplies {

        private AnswerConnection replying(int status) {
            return connection(RecordingAnswer.replying(
                new Response(status, "text/plain; charset=utf-8", "error body".getBytes(StandardCharsets.UTF_8))));
        }

        @ParameterizedTest
        @DisplayName("should report the status and give the body through getErrorStream()")
        @ValueSource(ints = {400, 404, 410, 500, 503})
        void errorStream(int status) throws IOException {
            AnswerConnection conn = replying(status);
            assertEquals(status, conn.getResponseCode());
            assertEquals("error body", readInputStream(conn.getErrorStream()));
        }

        @ParameterizedTest
        @DisplayName("getInputStream() should throw FileNotFoundException for 404 and 410, as HttpURLConnection does")
        @ValueSource(ints = {404, 410})
        void fileNotFound(int status) {
            AnswerConnection conn = replying(status);
            IOException ex = assertThrows(FileNotFoundException.class, conn::getInputStream);
            assertTrue(ex.getMessage().contains(String.valueOf(status)), ex.getMessage());
        }

        @ParameterizedTest
        @DisplayName("getInputStream() should throw IOException for other error statuses")
        @ValueSource(ints = {400, 500, 503})
        void ioException(int status) {
            AnswerConnection conn = replying(status);
            IOException ex = assertThrows(IOException.class, conn::getInputStream);
            assertFalse(ex instanceof FileNotFoundException);
            assertTrue(ex.getMessage().contains(PrivacyConstants.FORK_NAME), ex.getMessage());
            assertTrue(ex.getMessage().contains("HTTP response code " + status), ex.getMessage());
        }

        @Test
        @DisplayName("getErrorStream() should be null before the answer was asked, without asking it")
        void noErrorStreamBeforeAnswer() {
            RecordingAnswer answer = RecordingAnswer.replying(Response.text(""));
            assertNull(connection(answer).getErrorStream());
            assertEquals(0, answer.calls());
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
            AnswerConnection conn = connection(MockUrlFactory.licenseUrl());
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
            AnswerConnection conn = connection(MockUrlFactory.createUrl(spec));
            assertThrows(IOException.class, conn::connect);
            assertThrows(IOException.class, conn::getInputStream);
        }

        @Test
        @DisplayName("should tell the operator to BLOCK the route instead")
        void suggestsBlock() {
            AnswerConnection conn = connection(MockUrlFactory.httpsLicenseUrl());
            IOException ex = assertThrows(IOException.class, conn::getInputStream);
            assertTrue(ex.getMessage().contains("BLOCK"), ex.getMessage());
            assertTrue(ex.getMessage().contains(PrivacyConstants.FORK_NAME), ex.getMessage());
        }

        @Test
        @DisplayName("should refuse to produce content through getContent()")
        void refusesContent() {
            AnswerConnection conn = connection(MockUrlFactory.licenseUrl());
            assertThrows(IOException.class, conn::getContent);
        }
    }

    @Nested
    @DisplayName("Translation Endpoint")
    class TranslationEndpoint {

        // An empty answer would become an empty language cache, so the
        // request fails until LibreProtect bundles translations.

        @Test
        @DisplayName("should fail, since no translations are bundled yet")
        void fails() {
            AnswerConnection conn = connection(MockUrlFactory.translateUrl());
            IOException ex = assertThrows(IOException.class, conn::getResponseCode);
            assertTrue(ex.getMessage().contains("translations"), ex.getMessage());
            assertNull(conn.getHeaderField("Content-Type"));
        }

        @Test
        @DisplayName("should match the host case-insensitively")
        void matchesHostCaseInsensitively() {
            AnswerConnection conn = connection(MockUrlFactory.createUrl("https://CoreProtect.NET/translate/"));
            IOException ex = assertThrows(IOException.class, conn::getInputStream);
            assertTrue(ex.getMessage().contains("translations"), ex.getMessage());
        }
    }

    @Nested
    @DisplayName("Update Endpoint")
    class UpdateEndpoint {

        @Test
        @DisplayName("should extract version from User-Agent header")
        void extractsVersionFromUserAgent() throws IOException {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            conn.setRequestProperty("User-Agent", "CoreProtect/v21.3 (by Intelli)");

            String response = readInputStream(conn.getInputStream());
            assertEquals("21.3", response);
        }

        @Test
        @DisplayName("should extract version when User-Agent was added rather than set")
        void extractsVersionFromAddedUserAgent() throws IOException {
            AnswerConnection conn = connection(MockUrlFactory.updateEdgeUrl());
            conn.addRequestProperty("User-Agent", "CoreProtect/v24.1 (by Intelli)");

            assertEquals("24.1", readInputStream(conn.getInputStream()));
        }

        @Test
        @DisplayName("should find the User-Agent whatever its case")
        void findsUserAgentInAnyCase() throws IOException {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            conn.setRequestProperty("user-agent", "CoreProtect/v23.0 (by Intelli)");

            assertEquals("23.0", readInputStream(conn.getInputStream()));
        }

        @Test
        @DisplayName("should report no newer version when there is no User-Agent")
        void reportsNoUpdateWithoutUserAgent() throws IOException {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            String response = readInputStream(conn.getInputStream());
            assertEquals("0.0", response);
        }

        @Test
        @DisplayName("should report no newer version for a foreign User-Agent")
        void reportsNoUpdateForForeignUserAgent() throws IOException {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            conn.setRequestProperty("User-Agent", "Java/21");
            assertEquals("0.0", readInputStream(conn.getInputStream()));
        }

        @Test
        @DisplayName("should work for edge update endpoint")
        void worksForEdgeEndpoint() throws IOException {
            AnswerConnection conn = connection(MockUrlFactory.updateEdgeUrl());
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
            AnswerConnection conn = connection(MockUrlFactory.statsUrl());
            String response = readInputStream(conn.getInputStream());
            assertEquals("", response);
        }

        @Test
        @DisplayName("should accept and discard a request body")
        void acceptsRequestBody() throws IOException {
            AnswerConnection conn = connection(MockUrlFactory.httpsStatsUrl());
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
            AnswerConnection conn = connection(MockUrlFactory.unknownUrl());
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
            AnswerConnection conn = connection(MockUrlFactory.createUrl(spec));
            assertThrows(IOException.class, conn::getInputStream);
        }

        @Test
        @DisplayName("should not leak user info from the URL into the message")
        void doesNotLeakUserInfo() {
            AnswerConnection conn = connection(
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
        void connectMarksAsConnected() throws IOException {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            conn.connect();
            // Connected connections refuse further configuration
            assertThrows(IllegalStateException.class, () -> conn.setDoOutput(true));
        }

        @Test
        @DisplayName("disconnect() should drop the request body")
        void disconnectCleansUp() throws IOException {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            OutputStream first = conn.getOutputStream();
            conn.disconnect();
            assertNotSame(first, conn.getOutputStream());
        }

        @Test
        @DisplayName("usingProxy() should return true")
        void usingProxyReturnsTrue() {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            assertTrue(conn.usingProxy());
        }

        @Test
        @DisplayName("getPermission() should return null")
        void getPermissionReturnsNull() {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            assertNull(conn.getPermission());
        }
    }

    @Nested
    @DisplayName("Request Properties")
    class RequestProperties {

        @Test
        @DisplayName("should store and retrieve request properties")
        void storesRequestProperties() {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            conn.setRequestProperty("Custom-Header", "custom-value");
            assertEquals("custom-value", conn.getRequestProperty("Custom-Header"));
        }

        @Test
        @DisplayName("addRequestProperty should behave like setRequestProperty")
        void addRequestPropertyWorks() {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            conn.addRequestProperty("Header", "value");
            assertEquals("value", conn.getRequestProperty("Header"));
        }

        @Test
        @DisplayName("should match property names case-insensitively, as HttpURLConnection does")
        void caseInsensitive() {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            conn.setRequestProperty("User-Agent", "first");
            conn.setRequestProperty("user-agent", "second");
            assertEquals("second", conn.getRequestProperty("USER-AGENT"));
            assertEquals(1, conn.getRequestProperties().size());
            assertNull(conn.getRequestProperty(null));
        }

        @Test
        @DisplayName("getRequestProperties() should return map")
        void getRequestPropertiesReturnsMap() {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
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
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            String server = conn.getHeaderField("Server");
            assertTrue(server.contains(PrivacyConstants.FORK_NAME));
        }

        @Test
        @DisplayName("should return Content-Type header")
        void returnsContentTypeHeader() {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            String contentType = conn.getHeaderField("Content-Type");
            assertNotNull(contentType);
            assertTrue(contentType.startsWith("text/plain"));
        }

        @Test
        @DisplayName("should take the Content-Type from the answer")
        void contentTypeFromAnswer() {
            AnswerConnection conn = connection(RecordingAnswer.replying(Response.json("{}")));
            assertEquals("application/json; charset=utf-8", conn.getContentType());
            assertEquals(conn.getContentType(), conn.getHeaderField("Content-Type"));
        }

        @Test
        @DisplayName("should match header names case-insensitively")
        void headerNamesCaseInsensitive() {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            assertEquals(conn.getHeaderField("Content-Type"), conn.getHeaderField("content-type"));
            assertNull(conn.getHeaderField("X-Unknown"));
        }

        @Test
        @DisplayName("getHeaderFields() should return map")
        void getHeaderFieldsReturnsMap() {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            var headers = conn.getHeaderFields();
            assertNotNull(headers);
            assertTrue(headers.containsKey("Content-Type"));
            assertTrue(headers.containsKey("Server"));
        }

        @Test
        @DisplayName("getHeaderField(int) should return header by index")
        void getHeaderFieldByIndex() {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            assertEquals("HTTP/1.1 200 Answered by " + PrivacyConstants.FORK_NAME, conn.getHeaderField(0));
            assertEquals(conn.getContentType(), conn.getHeaderField(1));
            assertNull(conn.getHeaderField(3));
        }

        @Test
        @DisplayName("getHeaderField(0) should carry the answer's status")
        void statusLineCarriesStatus() {
            AnswerConnection conn = connection(RecordingAnswer.replying(
                new Response(HttpURLConnection.HTTP_UNAVAILABLE, "text/plain", new byte[0])));
            assertTrue(conn.getHeaderField(0).startsWith("HTTP/1.1 503 "), conn.getHeaderField(0));
        }

        @Test
        @DisplayName("getHeaderFieldKey(int) should return key by index")
        void getHeaderFieldKeyByIndex() {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            assertNull(conn.getHeaderFieldKey(0)); // Status line has no key
            assertEquals("Content-Type", conn.getHeaderFieldKey(1));
            assertEquals("Server", conn.getHeaderFieldKey(2));
        }

        @Test
        @DisplayName("getContentLength() should be unknown")
        void contentLengthUnknown() {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            assertEquals(-1, conn.getContentLength());
        }
    }

    @Nested
    @DisplayName("Input/Output Settings")
    class InputOutputSettings {

        @Test
        @DisplayName("setDoInput should be accepted")
        void setDoInputWorks() {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            conn.setDoInput(true);
            assertTrue(conn.getDoInput());
        }

        @Test
        @DisplayName("setDoOutput should be accepted")
        void setDoOutputWorks() {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            conn.setDoOutput(true);
            assertTrue(conn.getDoOutput());
        }

        @Test
        @DisplayName("getOutputStream should return writable stream")
        void getOutputStreamReturnsStream() throws IOException {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
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
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
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
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
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
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
            conn.setConnectTimeout(5000);
            assertEquals(0, conn.getConnectTimeout());
        }

        @Test
        @DisplayName("setReadTimeout should be ignored")
        void readTimeoutIgnored() {
            AnswerConnection conn = connection(MockUrlFactory.updateUrl());
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
            assertSame(url, connection(url).getURL());
        }
    }

    // Helper method
    private String readInputStream(InputStream is) throws IOException {
        try (is) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
