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

/*
 * Portions of this file are copied or adapted from CoreProtect
 * <https://github.com/PlayPro/CoreProtect>:
 *
 * Copyright (c) Intelli and the CoreProtect contributors
 *
 * CoreProtect is licensed under the Artistic License 2.0 (see
 * LICENSES/Artistic-2.0.txt). As section 4(c)(ii) of that license
 * permits, LibreProtect distributes these portions under the
 * GNU General Public License, version 3 or later. See NOTICE.
 */

package net.deltik.mc.libreprotect.extension.migration;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.Arrays;

/**
 * Changes one setting of CoreProtect's config.yml in place, for CoreProtect
 * 24, which has no writer of its own (CoreProtect 25's
 * {@code DatabaseConfigWriter} does the same for {@code database-type}).
 *
 * <p>A line sets a key the way CoreProtect 24 reads config.yml: it doesn't
 * start with {@code #}, and the text before its first colon, trimmed, is
 * the key. Every such line gets the new value; quotes around the old value,
 * an end-of-line comment, the whitespace and every other byte of the file
 * stay as they were. Without such a line, {@code key: value} is appended,
 * as CoreProtect itself appends missing settings when it starts.
 *
 * <p>The file is replaced atomically: the new content goes to a temporary
 * file in the same directory, which is flushed to disk and moved over the
 * original. The file must be a regular file, not a symbolic link.
 */
public final class ConfigValueWriter {

    private ConfigValueWriter() {
    }

    /**
     * Set a key in a config file.
     *
     * @param value the new value, written without quotes unless the old
     *              value was quoted
     * @return whether the file changed
     * @throws IOException if the file can't be read or replaced; it stays
     *                     unchanged then
     */
    public static boolean set(Path file, String key, String value) throws IOException {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException(file + " is not a regular file");
        }
        byte[] original = Files.readAllBytes(file);
        byte[] updated = update(original, key, value);
        if (Arrays.equals(original, updated)) {
            return false;
        }
        replace(file, updated);
        return true;
    }

    /**
     * Check, without changing it, that a config file can be replaced the way
     * {@link #set} and CoreProtect 25's {@code DatabaseConfigWriter} replace
     * it: a regular file, not a symbolic link, readable and writable, in a
     * directory where a temporary file can be created and atomically moved.
     *
     * @param copyOwner whether the replacement must also get the file's owner
     *                  and group, as CoreProtect 25's writer insists
     * @throws IOException saying what's wrong
     */
    public static void checkReplaceable(Path file, boolean copyOwner) throws IOException {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException(file + " is not a regular file");
        }
        if (!Files.isReadable(file) || !Files.isWritable(file)) {
            throw new IOException(file + " is not readable and writable");
        }
        Path directory = file.toAbsolutePath().getParent();
        Path temporary = Files.createTempFile(directory, "." + file.getFileName() + ".", ".tmp");
        Path moved = temporary.resolveSibling(temporary.getFileName() + ".check");
        try {
            if (copyOwner) {
                PosixFileAttributeView source = Files.getFileAttributeView(file, PosixFileAttributeView.class,
                    LinkOption.NOFOLLOW_LINKS);
                PosixFileAttributeView target = Files.getFileAttributeView(temporary, PosixFileAttributeView.class,
                    LinkOption.NOFOLLOW_LINKS);
                if (source != null && target != null) {
                    PosixFileAttributes attributes = source.readAttributes();
                    target.setOwner(attributes.owner());
                    target.setGroup(attributes.group());
                    target.setPermissions(attributes.permissions());
                }
            }
            try {
                Files.move(temporary, moved, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                throw new IOException("The file system of " + file + " can't replace it atomically", e);
            }
        } finally {
            Files.deleteIfExists(temporary);
            Files.deleteIfExists(moved);
        }
    }

    /**
     * @return the file's content with the key set to the value
     */
    static byte[] update(byte[] content, String key, String value) {
        ByteArrayOutputStream updated = new ByteArrayOutputStream(content.length + key.length() + value.length() + 4);
        byte[] separator = lineSeparator(content);
        boolean found = false;
        int offset = 0;
        while (offset < content.length) {
            int end = offset;
            while (end < content.length && content[end] != '\n' && content[end] != '\r') {
                end++;
            }
            int next = end;
            if (next < content.length) {
                next += content[next] == '\r' && next + 1 < content.length && content[next + 1] == '\n' ? 2 : 1;
            }
            byte[] line = Arrays.copyOfRange(content, offset, end);
            byte[] replaced = replaceValue(line, key, value);
            if (replaced != null) {
                found = true;
                updated.write(replaced, 0, replaced.length);
            } else {
                updated.write(line, 0, line.length);
            }
            updated.write(content, end, next - end);
            offset = next;
        }
        if (!found) {
            if (content.length > 0 && content[content.length - 1] != '\n' && content[content.length - 1] != '\r') {
                updated.write(separator, 0, separator.length);
            }
            byte[] line = (key + ": " + value).getBytes(StandardCharsets.UTF_8);
            updated.write(line, 0, line.length);
            updated.write(separator, 0, separator.length);
        }
        return updated.toByteArray();
    }

    /**
     * @return the line with its value replaced, or {@code null} if the line
     *         doesn't set the key
     */
    private static byte[] replaceValue(byte[] line, String key, String value) {
        if (line.length == 0 || line[0] == '#') {
            return null;
        }
        int colon = indexOf(line, (byte) ':', 0);
        if (colon < 0 || !trimmed(line, 0, colon).equals(key)) {
            return null;
        }
        int valueStart = colon + 1;
        while (valueStart < line.length && isSpace(line[valueStart])) {
            valueStart++;
        }
        int valueEnd = commentStart(line, valueStart);
        while (valueEnd > valueStart && isSpace(line[valueEnd - 1])) {
            valueEnd--;
        }
        String replacement = value;
        if (valueEnd > valueStart && (line[valueStart] == '"' || line[valueStart] == '\'')) {
            char quote = (char) line[valueStart];
            replacement = quote + value + quote;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(line.length + value.length());
        out.write(line, 0, colon + 1);
        if (valueStart == colon + 1) {
            out.write(' ');
        } else {
            out.write(line, colon + 1, valueStart - colon - 1);
        }
        byte[] replacementBytes = replacement.getBytes(StandardCharsets.UTF_8);
        out.write(replacementBytes, 0, replacementBytes.length);
        if (valueEnd == valueStart && valueEnd < line.length && line[valueEnd] == '#') {
            out.write(' ');
        }
        out.write(line, valueEnd, line.length - valueEnd);
        return out.toByteArray();
    }

    /**
     * @return where a comment starts: a {@code #} after whitespace, outside
     *         quotes, or the line's end
     */
    private static int commentStart(byte[] line, int from) {
        boolean single = false;
        boolean dual = false;
        for (int i = from; i < line.length; i++) {
            byte b = line[i];
            if (b == '"' && !single) {
                dual = !dual;
            } else if (b == '\'' && !dual) {
                single = !single;
            } else if (b == '#' && !single && !dual && (i == from || isSpace(line[i - 1]))) {
                return i;
            }
        }
        return line.length;
    }

    private static String trimmed(byte[] line, int from, int to) {
        return new String(line, from, to - from, StandardCharsets.UTF_8).trim();
    }

    private static int indexOf(byte[] line, byte wanted, int from) {
        for (int i = from; i < line.length; i++) {
            if (line[i] == wanted) {
                return i;
            }
        }
        return -1;
    }

    private static boolean isSpace(byte b) {
        return b == ' ' || b == '\t';
    }

    private static byte[] lineSeparator(byte[] content) {
        for (int i = 0; i < content.length; i++) {
            if (content[i] == '\n') {
                return i > 0 && content[i - 1] == '\r' ? new byte[]{'\r', '\n'} : new byte[]{'\n'};
            }
            if (content[i] == '\r' && (i + 1 >= content.length || content[i + 1] != '\n')) {
                return new byte[]{'\r'};
            }
        }
        return new byte[]{'\n'};
    }

    private static void replace(Path file, byte[] content) throws IOException {
        Path directory = file.toAbsolutePath().getParent();
        Path temporary = Files.createTempFile(directory, "." + file.getFileName() + ".", ".tmp");
        boolean moved = false;
        try {
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
                java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(content);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            copyPermissions(file, temporary);
            try {
                Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                throw new IOException("The file system of " + file + " can't replace it atomically", e);
            }
            moved = true;
            try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
                channel.force(true);
            } catch (IOException | UnsupportedOperationException e) {
                // Not every platform can flush a directory; the file itself is on disk
            }
        } finally {
            if (!moved) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    private static void copyPermissions(Path from, Path to) throws IOException {
        PosixFileAttributeView source = Files.getFileAttributeView(from, PosixFileAttributeView.class,
            LinkOption.NOFOLLOW_LINKS);
        PosixFileAttributeView target = Files.getFileAttributeView(to, PosixFileAttributeView.class,
            LinkOption.NOFOLLOW_LINKS);
        if (source != null && target != null) {
            PosixFileAttributes attributes = source.readAttributes();
            target.setPermissions(attributes.permissions());
            try {
                target.setOwner(attributes.owner());
                target.setGroup(attributes.group());
            } catch (IOException e) {
                // Only the owner or root can give a file away; the server's own files already are its own
            }
        }
    }
}
