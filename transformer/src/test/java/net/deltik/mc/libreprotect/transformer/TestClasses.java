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
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Helpers for loading, defining and verifying classes in tests.
 */
final class TestClasses {

    private static final long ENTRY_TIME = 1_700_000_000_000L;

    private TestClasses() {
    }

    static byte[] bytesOf(Class<?> type) {
        String resource = "/" + type.getName().replace('.', '/') + ".class";
        try (InputStream in = type.getResourceAsStream(resource)) {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Define a class from bytes in its own class loader, so it can share a
     * name with a class that is already loaded.
     */
    static Class<?> define(String binaryName, byte[] bytes) {
        return new ClassLoader(TestClasses.class.getClassLoader()) {
            Class<?> defineIt() {
                return defineClass(binaryName, bytes, 0, bytes.length);
            }
        }.defineIt();
    }

    /**
     * Run ASM's structural checks and, with {@code dataFlow}, its bytecode
     * verifier (which needs the class's dependencies to be loadable).
     */
    static void verify(byte[] bytes, boolean dataFlow) {
        if (dataFlow) {
            StringWriter errors = new StringWriter();
            CheckClassAdapter.verify(new ClassReader(bytes), TestClasses.class.getClassLoader(), false,
                new PrintWriter(errors));
            assertEquals("", errors.toString(), "bytecode verification failed");
        } else {
            new ClassReader(bytes).accept(new CheckClassAdapter(new ClassWriter(0), false), 0);
        }
    }

    /**
     * Write a JAR whose bytes depend only on its entries, so that its SHA-256 does too.
     */
    static Path writeJar(Path jar, Map<String, byte[]> entries) throws IOException {
        try (OutputStream out = Files.newOutputStream(jar); ZipOutputStream zip = new ZipOutputStream(out)) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                ZipEntry zipEntry = new ZipEntry(entry.getKey());
                zipEntry.setTime(ENTRY_TIME);
                zip.putNextEntry(zipEntry);
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        }
        return jar;
    }

    /**
     * @return a JAR of the runtime module's classes, as the build would produce
     */
    static Path runtimeJar(Path directory) throws IOException {
        Path location;
        try {
            location = Path.of(Egress.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        } catch (URISyntaxException e) {
            throw new IOException(e);
        }
        if (Files.isRegularFile(location)) {
            return location;
        }

        Path jar = directory.resolve("runtime.jar");
        try (OutputStream out = Files.newOutputStream(jar); ZipOutputStream zip = new ZipOutputStream(out);
             Stream<Path> files = Files.walk(location)) {
            for (Path file : (Iterable<Path>) files.filter(Files::isRegularFile).sorted()::iterator) {
                zip.putNextEntry(new ZipEntry(location.relativize(file).toString().replace('\\', '/')));
                zip.write(Files.readAllBytes(file));
                zip.closeEntry();
            }
        }
        return jar;
    }
}
