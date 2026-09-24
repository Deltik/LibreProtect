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

package net.deltik.mc.libreprotect.transformer;

import net.deltik.mc.libreprotect.Egress;
import net.deltik.mc.libreprotect.EgressBlockedException;
import net.deltik.mc.libreprotect.routing.RouteActionType;
import net.deltik.mc.libreprotect.routing.RouteRegistry;
import net.deltik.mc.libreprotect.routing.RouteResolver;
import net.deltik.mc.libreprotect.transformer.fixture.EgressFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;

import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.Proxy;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EgressRewriterTest {

    private static final List<TransformReport.EgressSite> SITES = new ArrayList<>();
    private static byte[] rewritten;
    private static Class<?> fixture;

    @BeforeAll
    static void rewrite() {
        ClassReader reader = new ClassReader(TestClasses.bytesOf(EgressFixture.class));
        ClassWriter writer = new ClassWriter(0);
        reader.accept(new EgressRewriter(writer, "fixture.class", Origin.UPSTREAM, SITES), 0);
        rewritten = writer.toByteArray();
        fixture = TestClasses.define(EgressFixture.class.getName(), rewritten);
    }

    @AfterEach
    void uninstall() {
        Egress.uninstall();
    }

    private static Object invoke(String method, Object... arguments) throws Throwable {
        for (Method candidate : fixture.getMethods()) {
            if (candidate.getName().equals(method)) {
                try {
                    return candidate.invoke(null, arguments);
                } catch (InvocationTargetException e) {
                    throw e.getCause();
                }
            }
        }
        throw new NoSuchMethodException(method);
    }

    @Nested
    @DisplayName("Rewriting")
    class Rewriting {

        @Test
        @DisplayName("records every direct call, including the one inside a lambda body")
        void recordsDirectCalls() {
            List<String> calls = SITES.stream().filter(site -> site.kind().equals("call"))
                .map(site -> site.method().substring(0, site.method().indexOf('(')) + " " + site.api()).toList();
            assertEquals(6, calls.size(), calls.toString());
            assertTrue(calls.contains("direct openConnection()Ljava/net/URLConnection;"));
            assertTrue(calls.contains("withProxy openConnection(Ljava/net/Proxy;)Ljava/net/URLConnection;"));
            assertTrue(calls.contains("stream openStream()Ljava/io/InputStream;"));
            assertTrue(calls.contains("content getContent()Ljava/lang/Object;"));
            assertTrue(calls.contains("typedContent getContent([Ljava/lang/Class;)Ljava/lang/Object;"));
            assertTrue(calls.stream().anyMatch(call -> call.startsWith("lambda$")), calls.toString());
        }

        @Test
        @DisplayName("records method references as method handles")
        void recordsMethodReferences() {
            List<String> handles = SITES.stream().filter(site -> site.kind().equals("method handle"))
                .map(TransformReport.EgressSite::api).toList();
            assertEquals(List.of("openStream()Ljava/io/InputStream;", "openConnection()Ljava/net/URLConnection;"),
                handles);
        }

        @Test
        @DisplayName("leaves no direct java.net.URL connection calls")
        void leavesNoRawEgress() {
            assertTrue(ClassScan.of(TestClasses.bytesOf(EgressFixture.class)).hasRawEgress());
            assertFalse(ClassScan.of(rewritten).hasRawEgress());
        }

        @Test
        @DisplayName("produces bytecode that passes verification")
        void verifies() {
            TestClasses.verify(rewritten, true);
        }
    }

    @Nested
    @DisplayName("Rewritten code")
    class RewrittenCode {

        @TempDir
        Path directory;

        private URL fileUrl() throws Exception {
            Path file = directory.resolve("data.txt");
            Files.writeString(file, "hello");
            return file.toUri().toURL();
        }

        @Test
        @DisplayName("is blocked by Egress when no policy is installed")
        void blockedWithoutPolicy() throws Exception {
            URL url = fileUrl();
            assertThrows(EgressBlockedException.class, () -> invoke("direct", url));
            assertThrows(EgressBlockedException.class, () -> invoke("withProxy", url));
            assertThrows(EgressBlockedException.class, () -> invoke("stream", url));
            assertThrows(EgressBlockedException.class, () -> invoke("content", url));
            assertThrows(EgressBlockedException.class, () -> invoke("typedContent", url));
        }

        @Test
        @DisplayName("method references and lambdas are blocked by Egress too")
        @SuppressWarnings("unchecked")
        void referencesBlocked() throws Throwable {
            URL url = fileUrl();
            Callable<InputStream> bound = (Callable<InputStream>) invoke("boundReference", url);
            assertThrows(EgressBlockedException.class, bound::call);

            EgressFixture.UrlOpener unbound = (EgressFixture.UrlOpener) invoke("unboundReference");
            assertThrows(EgressBlockedException.class, () -> unbound.open(url));

            Function<URL, URLConnection> lambda = (Function<URL, URLConnection>) invoke("lambda");
            UncheckedIOException thrown = assertThrows(UncheckedIOException.class, () -> lambda.apply(url));
            assertInstanceOf(EgressBlockedException.class, thrown.getCause());
        }

        @Test
        @DisplayName("works normally when the policy lets the request through")
        void passesThroughWhenAllowed() throws Throwable {
            Egress.install(new RouteResolver(RouteRegistry.builder()
                .setDefaultAction(RouteActionType.PASSTHROUGH).build()));
            URL url = fileUrl();

            try (InputStream in = (InputStream) invoke("stream", url)) {
                assertEquals("hello", new String(in.readAllBytes(), StandardCharsets.UTF_8));
            }
            URLConnection connection = (URLConnection) invoke("withProxy", url);
            assertEquals(url, connection.getURL());
        }

        @Test
        @DisplayName("leaves unrelated URL methods alone")
        void unrelatedMethods() throws Throwable {
            assertEquals("example.com", invoke("notEgress", URI.create("https://example.com/").toURL()));
            assertTrue(Proxy.NO_PROXY.type() == Proxy.Type.DIRECT);
        }
    }
}
