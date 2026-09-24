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

package net.deltik.mc.lpit.agent;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Instruments the JDK's lowest public or long-stable entry points for
 * outbound traffic so that {@link EgressRecorder} sees every attempt:
 * <ul>
 *   <li>{@code java.net.Socket#connect(SocketAddress, int)}, which all
 *       {@code Socket}-based clients use, including {@code HttpURLConnection}</li>
 *   <li>{@code sun.nio.ch.SocketChannelImpl#connect}, used by NIO and
 *       {@code java.net.http.HttpClient}</li>
 *   <li>{@code sun.nio.ch.DatagramChannelImpl#connect} and {@code #send}, used
 *       by UDP including {@code DatagramSocket}</li>
 *   <li>{@code java.net.InetAddress#getAllByName(String)}, which DNS lookups
 *       go through, including {@code getByName}</li>
 * </ul>
 *
 * <p>Agent arguments: {@code log=<file>} (required) and
 * {@code mode=deny|log} (default {@code deny}).
 *
 * <p>If any hook can't be installed, the agent fails the JVM start: a test
 * that can't see egress must not pass.
 */
public final class EgressAgent {

    private static final String RECORDER = EgressRecorder.class.getName().replace('.', '/');
    private static final String SOCKET_ADDRESS = "Ljava/net/SocketAddress;";

    /** Class to method names; each hooked method gets a call with its first SocketAddress or String argument */
    private static final Map<String, Set<String>> HOOKS = Map.of(
        "java/net/Socket", Set.of("connect"),
        "sun/nio/ch/SocketChannelImpl", Set.of("connect"),
        "sun/nio/ch/DatagramChannelImpl", Set.of("connect", "send"),
        "java/net/InetAddress", Set.of("getAllByName"));

    private EgressAgent() {
    }

    public static void premain(String arguments, Instrumentation instrumentation) throws Exception {
        for (String argument : (arguments == null ? "" : arguments).split(",")) {
            int equals = argument.indexOf('=');
            if (equals < 0) {
                continue;
            }
            String key = argument.substring(0, equals);
            String value = argument.substring(equals + 1);
            if (key.equals("log")) {
                Path log = Path.of(value).toAbsolutePath();
                Files.createDirectories(log.getParent());
                Files.deleteIfExists(log);
                Files.createFile(log);
                EgressRecorder.log = log;
            } else if (key.equals("mode")) {
                EgressRecorder.deny = !value.equals("log");
            }
        }
        if (EgressRecorder.log == null) {
            throw new IllegalArgumentException("libreprotect-egress-agent needs log=<file>");
        }

        List<String> hooked = new ArrayList<>();
        instrumentation.addTransformer(new ClassFileTransformer() {
            @Override
            public byte[] transform(Module module, ClassLoader loader, String className, Class<?> classBeingRedefined,
                                    ProtectionDomain protectionDomain, byte[] classfileBuffer) {
                Set<String> methods = HOOKS.get(className);
                if (methods == null) {
                    return null;
                }
                try {
                    return instrument(classfileBuffer, methods, hooked);
                } catch (Throwable t) {
                    t.printStackTrace();
                    return null;
                }
            }
        }, true);

        List<Class<?>> loaded = new ArrayList<>();
        for (String className : HOOKS.keySet()) {
            loaded.add(Class.forName(className.replace('/', '.'), false, null));
        }
        instrumentation.retransformClasses(loaded.toArray(new Class<?>[0]));

        for (String className : HOOKS.keySet()) {
            for (String method : HOOKS.get(className)) {
                if (hooked.stream().noneMatch(entry -> entry.startsWith(className + "." + method + "("))) {
                    throw new IllegalStateException("libreprotect-egress-agent could not hook " + className + "." + method
                        + "; this JDK's internals changed. Hooked: " + hooked);
                }
            }
        }
        System.err.println("[libreprotect-egress-agent] " + (EgressRecorder.deny ? "Blocking" : "Recording")
            + " outbound network access, logging to " + EgressRecorder.log);
    }

    static byte[] instrument(byte[] bytes, Set<String> methods, List<String> hooked) {
        ClassReader reader = new ClassReader(bytes);
        ClassWriter writer = new ClassWriter(reader, 0);
        String className = reader.getClassName();
        reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature,
                                             String[] exceptions) {
                MethodVisitor next = super.visitMethod(access, name, descriptor, signature, exceptions);
                if (!methods.contains(name) || (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
                    return next;
                }
                boolean isStatic = (access & Opcodes.ACC_STATIC) != 0;
                int slot = isStatic ? 0 : 1;
                Type[] arguments = Type.getArgumentTypes(descriptor);
                for (Type argument : arguments) {
                    String hookDescriptor;
                    String hook;
                    if (argument.getDescriptor().equals(SOCKET_ADDRESS)) {
                        hook = "socket";
                        hookDescriptor = "(Ljava/lang/String;" + SOCKET_ADDRESS + ")V";
                    } else if (className.equals("java/net/InetAddress") && argument.getDescriptor().equals("Ljava/lang/String;")
                        && descriptor.equals("(Ljava/lang/String;)[Ljava/net/InetAddress;")) {
                        hook = "resolve";
                        hookDescriptor = "(Ljava/lang/String;)V";
                    } else {
                        slot += argument.getSize();
                        continue;
                    }
                    int argumentSlot = slot;
                    String kind = className.contains("Datagram") ? "datagram" : "connect";
                    hooked.add(className + "." + name + descriptor);
                    return new MethodVisitor(Opcodes.ASM9, next) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            if (hook.equals("socket")) {
                                super.visitLdcInsn(kind);
                            }
                            super.visitVarInsn(Opcodes.ALOAD, argumentSlot);
                            super.visitMethodInsn(Opcodes.INVOKESTATIC, RECORDER, hook, hookDescriptor, false);
                        }

                        @Override
                        public void visitMaxs(int maxStack, int maxLocals) {
                            super.visitMaxs(Math.max(maxStack, 2), maxLocals);
                        }
                    };
                }
                return next;
            }
        }, 0);
        return writer.toByteArray();
    }
}
