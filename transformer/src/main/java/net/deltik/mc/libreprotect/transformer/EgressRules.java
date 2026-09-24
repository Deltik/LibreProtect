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

import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;

import java.util.List;

/**
 * The network APIs that the transformer redirects through LibreProtect's
 * {@code Egress} gate.
 *
 * <p>{@link java.net.URL} is final, so every call to these methods compiles
 * to {@code INVOKEVIRTUAL java/net/URL}, whatever the calling code looks
 * like. Swapping that instruction for {@code INVOKESTATIC Egress} with the
 * receiver as an extra first parameter leaves the operand stack unchanged.
 */
final class EgressRules {

    static final String URL = "java/net/URL";
    static final String EGRESS = "net/deltik/mc/libreprotect/Egress";

    /** Name and descriptor of each {@code java.net.URL} method that opens a connection. */
    static final List<String> METHODS = List.of(
        "openConnection()Ljava/net/URLConnection;",
        "openConnection(Ljava/net/Proxy;)Ljava/net/URLConnection;",
        "openStream()Ljava/io/InputStream;",
        "getContent()Ljava/lang/Object;",
        "getContent([Ljava/lang/Class;)Ljava/lang/Object;"
    );

    private EgressRules() {
    }

    static boolean isEgress(String owner, String name, String descriptor) {
        return URL.equals(owner) && METHODS.contains(name + descriptor);
    }

    static boolean isEgress(Handle handle) {
        return handle.getTag() == Opcodes.H_INVOKEVIRTUAL
            && isEgress(handle.getOwner(), handle.getName(), handle.getDesc());
    }

    /**
     * @return the descriptor of the static replacement for an instance method descriptor
     */
    static String staticDescriptor(String instanceDescriptor) {
        return "(L" + URL + ";" + instanceDescriptor.substring(1);
    }

    static Handle rewrite(Handle handle) {
        return new Handle(Opcodes.H_INVOKESTATIC, EGRESS, handle.getName(), staticDescriptor(handle.getDesc()), false);
    }
}
