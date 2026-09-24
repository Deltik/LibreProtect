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

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * The file entries of a JAR (directory entries are dropped and regenerated on
 * write).
 */
final class JarContents {

    static final String MANIFEST = "META-INF/MANIFEST.MF";
    static final String VERSIONS_PREFIX = "META-INF/versions/";

    private final Map<String, byte[]> entries;

    JarContents() {
        this(new LinkedHashMap<>());
    }

    private JarContents(Map<String, byte[]> entries) {
        this.entries = entries;
    }

    static JarContents read(Path jar) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            Enumeration<? extends ZipEntry> iterator = zip.entries();
            while (iterator.hasMoreElements()) {
                ZipEntry entry = iterator.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                try (InputStream in = zip.getInputStream(entry)) {
                    if (entries.put(entry.getName(), in.readAllBytes()) != null) {
                        throw new IOException("Duplicate entry " + entry.getName() + " in " + jar);
                    }
                }
            }
        }
        return new JarContents(entries);
    }

    boolean contains(String name) {
        return entries.containsKey(name);
    }

    byte[] get(String name) {
        return entries.get(name);
    }

    void put(String name, byte[] data) {
        entries.put(name, data);
    }

    List<String> names() {
        return Collections.unmodifiableList(new ArrayList<>(entries.keySet()));
    }

    static boolean isClass(String name) {
        return name.endsWith(".class") && !name.endsWith("module-info.class");
    }

    /**
     * @return the class's internal name, ignoring any {@code META-INF/versions/N/} prefix
     */
    static String internalName(String entryName) {
        String name = entryName;
        if (name.startsWith(VERSIONS_PREFIX)) {
            int slash = name.indexOf('/', VERSIONS_PREFIX.length());
            name = name.substring(slash + 1);
        }
        return name.substring(0, name.length() - ".class".length());
    }

    static boolean isVersioned(String entryName) {
        return entryName.startsWith(VERSIONS_PREFIX);
    }

    /**
     * Write a reproducible JAR: manifest first, then directories and files in
     * name order, all with the same timestamp.
     */
    void write(Path jar, long epochSeconds) throws IOException {
        LocalDateTime time = LocalDateTime.ofEpochSecond(epochSeconds, 0, ZoneOffset.UTC);

        TreeSet<String> directories = new TreeSet<>();
        for (String name : entries.keySet()) {
            for (int slash = name.indexOf('/'); slash >= 0; slash = name.indexOf('/', slash + 1)) {
                directories.add(name.substring(0, slash + 1));
            }
        }
        TreeSet<String> files = new TreeSet<>(entries.keySet());

        Files.createDirectories(jar.toAbsolutePath().getParent());
        // Buffered, since the ZIP format is written a few bytes at a time: unbuffered, a JAR with the ClickHouse
        // client took some 750,000 system calls to write
        try (OutputStream out = new BufferedOutputStream(Files.newOutputStream(jar), 1 << 16);
             ZipOutputStream zip = new ZipOutputStream(out)) {
            if (files.remove(MANIFEST)) {
                directories.remove("META-INF/");
                writeEntry(zip, "META-INF/", null, time);
                writeEntry(zip, MANIFEST, entries.get(MANIFEST), time);
            }
            for (String directory : directories) {
                writeEntry(zip, directory, null, time);
            }
            for (String file : files) {
                writeEntry(zip, file, entries.get(file), time);
            }
        }
    }

    private static void writeEntry(ZipOutputStream zip, String name, byte[] data, LocalDateTime time) throws IOException {
        ZipEntry entry = new ZipEntry(name);
        entry.setTimeLocal(time);
        zip.putNextEntry(entry);
        if (data != null) {
            zip.write(data);
        }
        zip.closeEntry();
    }
}
