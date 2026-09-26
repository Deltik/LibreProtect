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

package net.deltik.mc.libreprotect.extension.purge;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;

/**
 * Values that change when CoreProtect's active database is replaced, for
 * {@link PurgeBridge#databaseIdentity()}.
 */
public final class DatabaseIdentity {

    private DatabaseIdentity() {
    }

    /**
     * A manual purge on SQLite rebuilds the database in a new file and moves
     * it over the old one, and rowids in the new file can differ, so a purge
     * in progress must notice.
     *
     * @return the file's identity (its inode where the platform has one,
     *         otherwise its creation time), or {@code null} if it can't be read
     */
    public static Object ofFile(String path) {
        try {
            BasicFileAttributes attributes = Files.readAttributes(Paths.get(path), BasicFileAttributes.class);
            Object key = attributes.fileKey();
            return key != null ? key : attributes.creationTime();
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /**
     * @return the identity of a database on a server
     */
    public static Object ofServer(String host, int port, String database) {
        return Arrays.asList(host, port, database);
    }
}
