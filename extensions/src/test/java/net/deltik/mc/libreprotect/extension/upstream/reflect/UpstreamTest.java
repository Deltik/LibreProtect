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

package net.deltik.mc.libreprotect.extension.upstream.reflect;

import net.deltik.mc.libreprotect.extension.upstream.reflect.fake.Child;
import net.deltik.mc.libreprotect.extension.upstream.reflect.fake.Colors;
import net.deltik.mc.libreprotect.extension.upstream.reflect.fake.Engines;
import net.deltik.mc.libreprotect.extension.upstream.reflect.fake.Holder;
import net.deltik.mc.libreprotect.extension.upstream.reflect.fake.Initialized;
import net.deltik.mc.libreprotect.extension.upstream.reflect.fake.Pristine;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.invoke.MethodHandle;
import java.sql.SQLException;
import java.util.List;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The toolkit's probing and calls, on fake upstream classes in another
 * package, with the kinds of members that CoreProtect has.
 */
class UpstreamTest {

    private static final String FAKE = "net.deltik.mc.libreprotect.extension.upstream.reflect.fake.";
    private static final String HOLDER = FAKE + "Holder";

    private final Upstream upstream = Upstream.of("Fake", UpstreamTest.class.getClassLoader());

    @AfterEach
    void restore() {
        Holder.running = true;
        Holder.engine = Engines.SQLITE;
    }

    private UpstreamClass holder() throws Missing {
        return upstream.type(HOLDER);
    }

    @Test
    @DisplayName("should probe without running any static initializer, and run it on first use")
    void neverInitializes() throws Exception {
        UpstreamClass pristine = upstream.type(FAKE + "Pristine");
        StaticField flag = pristine.writableStaticField("flag", boolean.class);
        StaticField handshake = pristine.staticField("handshake", boolean.class);
        IntSupplier constant = pristine.intConstant("CONSTANT");
        StaticMethod<String, RuntimeException> run = pristine.staticMethodShaped("run", String.class,
            Shape.enumWith("ONE"));
        UpstreamEnum kinds = upstream.type(run.parameterType(0)).asEnum();
        pristine.field("value", int.class);
        assertTrue(pristine.hasStaticSynchronizedMethod());
        assertTrue(upstream.has(FAKE + "Pristine$Kind#TWO"));
        assertTrue(upstream.has(FAKE + "Pristine#lock"));
        upstream.relyOn("locks", FAKE + "Pristine", "lock()V");
        assertEquals(List.of("ONE", "TWO"), kinds.names());

        assertFalse(Initialized.CLASSES.contains("Pristine"), "Pristine was initialized while probing");
        assertFalse(Initialized.CLASSES.contains("Pristine.Kind"), "Pristine.Kind was initialized while probing");

        assertEquals(5, constant.getAsInt());
        assertTrue(Initialized.CLASSES.contains("Pristine"));
        assertFalse(Initialized.CLASSES.contains("Pristine.Kind"));
        assertEquals("TWO", run.call(kinds.constant("TWO")));
        assertTrue(Initialized.CLASSES.contains("Pristine.Kind"));
        flag.setBoolean(true);
        assertTrue(Pristine.flag);
        assertFalse(handshake.getBoolean());
    }

    @Nested
    @DisplayName("fields")
    class Fields {

        @Test
        @DisplayName("should read and write a protected volatile static field without extending its class")
        void protectedVolatile() throws Exception {
            StaticField parked = holder().writableStaticField("parked", boolean.class);

            parked.setBoolean(true);
            assertTrue(parked.getBoolean());
            assertEquals(true, parked.get());
            parked.set(false);
            assertFalse(parked.getBoolean());
            assertTrue(parked.exists());
            assertEquals(boolean.class, parked.type());
        }

        @Test
        @DisplayName("should read and write a public static field of an object type")
        void objects() throws Exception {
            StaticField engine = holder().writableStaticField("engine", Enum.class);

            assertEquals(Engines.class, engine.type());
            assertSame(Engines.SQLITE, engine.get());
            engine.set(Engines.DUCKDB);
            assertSame(Engines.DUCKDB, Holder.engine);
        }

        @Test
        @DisplayName("should find a static field that a superclass declares")
        void inherited() throws Exception {
            StaticField running = upstream.type(FAKE + "Child").writableStaticField("running", boolean.class);

            Holder.running = false;
            assertFalse(running.getBoolean());
            running.setBoolean(true);
            assertTrue(Holder.running);
            assertNotNull(new Child().describe(1));
        }

        @Test
        @DisplayName("should read and write instance fields, private ones included")
        void instance() throws Exception {
            InstanceField enabled = holder().writableField("enabled", boolean.class);
            InstanceField label = holder().writableField("label", String.class);
            Holder target = new Holder("before");

            enabled.setBoolean(target, false);
            assertFalse(target.enabled);
            assertEquals("before", label.get(target));
            label.set(target, "after");
            assertEquals("after", target.describe(1));
        }

        @Test
        @DisplayName("should read constants from upstream when asked")
        void constants() throws Exception {
            assertEquals(7, holder().intConstant("CONSTANT").getAsInt());
            assertEquals("holder", holder().stringConstant("NAME", "fallback").get());
            assertEquals("fallback", holder().stringConstant("NO_SUCH_NAME", "fallback").get());
        }

        @Test
        @DisplayName("should refuse a field of another type or kind, saying which")
        void refusals() throws Exception {
            UpstreamClass holder = holder();

            assertEquals("Fake's Holder.NOT_AN_INT has type long, not int",
                assertThrows(Missing.class, () -> holder.intConstant("NOT_AN_INT")).getMessage());
            assertEquals("Fake's Holder.enabled isn't static",
                assertThrows(Missing.class, () -> holder.staticField("enabled", boolean.class)).getMessage());
            assertEquals("Fake's Holder.running is static",
                assertThrows(Missing.class, () -> holder.field("running", boolean.class)).getMessage());
            assertEquals("Fake has no Holder.nothing",
                assertThrows(Missing.class, () -> holder.staticField("nothing", int.class)).getMessage());
            assertEquals("Fake's Holder.NAME has type String, not Integer",
                assertThrows(Missing.class, () -> holder.staticField("NAME", Integer.class)).getMessage());
            assertThrows(Missing.class, () -> holder.stringConstant("CONSTANT", "fallback"));
        }

        @Test
        @DisplayName("should refuse to find a final field for writing, which upstream made so, saying why")
        void finalFields() throws Exception {
            UpstreamClass holder = holder();

            assertEquals("Fake's Holder.NAME is final, so LibreProtect can't set it",
                assertThrows(Missing.class, () -> holder.writableStaticField("NAME", String.class)).getMessage());
            assertEquals("Fake's Holder.created is final, so LibreProtect can't set it",
                assertThrows(Missing.class, () -> holder.writableField("created", long.class)).getMessage());
            // For reading, they're fine
            assertEquals("holder", holder.staticField("NAME", String.class).get());
            assertNotNull(holder.field("created", long.class).get(new Holder()));
        }

        @Test
        @DisplayName("should refuse to write a field found for reading only, which probing didn't check")
        void readOnly() throws Exception {
            StaticField parked = holder().staticField("parked", boolean.class);
            InstanceField enabled = holder().field("enabled", boolean.class);
            Holder target = new Holder();

            assertEquals("Fake's Holder.parked was found for reading only",
                assertThrows(IllegalStateException.class, () -> parked.setBoolean(true)).getMessage());
            assertThrows(IllegalStateException.class, () -> parked.set(true));
            assertEquals("Fake's Holder.enabled was found for reading only",
                assertThrows(IllegalStateException.class, () -> enabled.setBoolean(target, false)).getMessage());
            assertTrue(target.enabled);
        }

        @Test
        @DisplayName("should read an absent optional field as zero, and ignore writes")
        void absent() throws Exception {
            StaticField absent = holder().staticFieldIfPresent("gone", int.class);
            StaticField ofAbsentClass = upstream.typeIfPresent(FAKE + "Gone").staticFieldIfPresent("x", boolean.class);

            assertFalse(absent.exists());
            assertEquals(0, absent.getInt());
            assertEquals(0, absent.get());
            absent.setInt(3);
            assertFalse(ofAbsentClass.getBoolean());
            assertNull(holder().staticFieldIfPresent("gone", String.class).get());
        }
    }

    @Nested
    @DisplayName("methods")
    class Methods {

        @Test
        @DisplayName("should call static methods, private ones included")
        void call() throws Exception {
            StaticMethod<String, RuntimeException> greet = holder().staticMethod("greet", String.class,
                String.class);
            StaticMethod<Integer, RuntimeException> count = holder().staticMethod("count", int.class);

            assertEquals("Hello, world", greet.call("world"));
            int first = count.call();
            assertEquals(first + 1, count.call());
            assertEquals(String.class, greet.returnType());
            assertEquals(String.class, greet.parameterType(0));
        }

        @Test
        @DisplayName("should call through an exact handle for hot paths")
        void exact() throws Throwable {
            MethodHandle twice = holder().staticMethod("twice", int.class, int.class).exact();
            MethodHandle describe = holder().method("describe", String.class, int.class).exact();

            assertEquals(42, (int) twice.invokeExact(21));
            assertEquals("abab", (String) describe.invokeExact((Object) new Holder("ab"), 2));
        }

        @Test
        @DisplayName("should let the checked exception chosen with throwing through, and turn others into"
            + " UpstreamChanged")
        void checkedExceptions() throws Exception {
            StaticMethod<Void, RuntimeException> fail = holder().staticMethod("fail", void.class, String.class);
            StaticMethod<Void, IOException> failIO = fail.throwing(IOException.class);

            assertEquals("I/O", assertThrows(IOException.class, () -> failIO.call("io")).getMessage());
            UpstreamChanged changed = assertThrows(UpstreamChanged.class, () -> failIO.call("sql"));
            assertInstanceOf(SQLException.class, changed.getCause());
            assertTrue(changed.getMessage().startsWith("Fake's Holder.fail(String) failed with an unexpected"),
                changed.getMessage());
            assertInstanceOf(IOException.class, assertThrows(UpstreamChanged.class, () -> fail.call("io"))
                .getCause());
        }

        @Test
        @DisplayName("should let unchecked exceptions and errors through as they are")
        void uncheckedExceptions() throws Exception {
            StaticMethod<Void, IOException> fail = holder().staticMethod("fail", void.class, String.class)
                .throwing(IOException.class);

            assertEquals("state", assertThrows(IllegalStateException.class, () -> fail.call("state")).getMessage());
            assertEquals("error", assertThrows(AssertionError.class, () -> fail.call("error")).getMessage());
        }

        @Test
        @DisplayName("should find a method by the shapes of its parameters, only when one method fits")
        void shaped() throws Exception {
            StaticMethod<String, RuntimeException> pick = holder().staticMethodShaped("pick", String.class,
                Shape.enumWith("SQLITE", "MYSQL"), Shape.exactly(boolean.class));
            StaticMethod<String, RuntimeException> paint = holder().staticMethodShaped("paint", String.class,
                Shape.enumWith("RED"));

            assertEquals(Engines.class, pick.parameterType(0));
            assertEquals("duckdb", pick.call(Engines.DUCKDB, false));
            assertEquals("painted GREEN", paint.call(Colors.GREEN));
            Missing ambiguous = assertThrows(Missing.class, () -> holder().staticMethodShaped("paint", String.class,
                Shape.enumWith("MYSQL")));
            assertEquals("Fake has more than one Holder.paint(an enum with MYSQL)", ambiguous.getMessage());
            assertEquals("Fake has no Holder.pick(an enum with ORACLE, boolean)", assertThrows(Missing.class,
                () -> holder().staticMethodShaped("pick", String.class, Shape.enumWith("ORACLE"),
                    Shape.exactly(boolean.class))).getMessage());
        }

        @Test
        @DisplayName("should say which method is missing or different, in Java's words")
        void refusals() throws Exception {
            UpstreamClass holder = holder();

            assertEquals("Fake has no Holder.greet(String, int)", assertThrows(Missing.class,
                () -> holder.staticMethod("greet", String.class, String.class, int.class)).getMessage());
            assertEquals("Fake's Holder.twice(int) returns int, not long", assertThrows(Missing.class,
                () -> holder.staticMethod("twice", long.class, int.class)).getMessage());
            assertEquals("Fake's Holder.describe(int) isn't static", assertThrows(Missing.class,
                () -> holder.staticMethod("describe", String.class, int.class)).getMessage());
            assertEquals("Fake has no Holder.rename(byte[])", assertThrows(Missing.class,
                () -> holder.method("rename", Object.class, byte[].class)).getMessage());
            assertEquals("Fake has no class Gone", assertThrows(Missing.class,
                () -> upstream.type(FAKE + "Gone")).getMessage());
        }

        @Test
        @DisplayName("should accept a subtype of the return type asked for")
        void covariantReturn() throws Exception {
            StaticMethod<Object, RuntimeException> create = holder().staticMethod("create", Object.class);

            assertEquals(Holder.class, create.returnType());
            assertEquals("created", ((Holder) create.call()).describe(1));
        }

        @Test
        @DisplayName("should treat an absent optional method as doing nothing and returning zero")
        void absentOptional() throws Exception {
            StaticMethod<Boolean, RuntimeException> absent = holder().staticMethodIfPresent("gone", boolean.class);
            StaticMethod<Integer, RuntimeException> ofAbsentClass = upstream.typeIfPresent(FAKE + "Gone")
                .staticMethodIfPresent("count", int.class);

            assertFalse(absent.exists());
            assertFalse(absent.call());
            assertEquals(0, ofAbsentClass.call());
            assertThrows(IllegalStateException.class, absent::exact);
        }

        @Test
        @DisplayName("should refuse an optional method that upstream has in another shape")
        void optionalInAnotherShape() {
            assertThrows(Missing.class, () -> holder().staticMethodIfPresent("greet", String.class, int.class));
        }

        @Test
        @DisplayName("should find a method whatever it returns, and drop its result")
        void ignoringResult() throws Throwable {
            MethodHandle rename = holder().methodIgnoringResult("rename", String.class).exact();
            MethodHandle relabel = holder().methodIgnoringResult("relabel", String.class).exact();
            Holder target = new Holder();

            rename.invokeExact((Object) target, "renamed");
            assertEquals("renamed", target.describe(1));
            relabel.invokeExact((Object) target, "relabeled");
            assertEquals("relabeled", target.describe(1));
        }

        @Test
        @DisplayName("should call instance methods that a subclass overrides, once")
        void overridden() throws Exception {
            InstanceMethod<String, RuntimeException> describe = upstream.type(FAKE + "Child").method("describe",
                String.class, int.class);

            assertEquals("child freshfresh", describe.call(new Child(), 2));
        }

        @Test
        @DisplayName("should create instances through constructors")
        void constructors() throws Exception {
            Creator labeled = holder().constructor(String.class);

            assertEquals("made", ((Holder) labeled.create("made")).describe(1));
            assertEquals("Fake has no constructor Holder(int)", assertThrows(Missing.class,
                () -> holder().constructor(int.class)).getMessage());
        }
    }

    @Nested
    @DisplayName("enums")
    class Enums {

        @Test
        @DisplayName("should list constants in declaration order and look them up by name")
        void constants() throws Exception {
            UpstreamEnum engines = upstream.type(FAKE + "Engines").asEnum();

            assertEquals(List.of("CLICKHOUSE", "DUCKDB", "MYSQL", "POSTGRESQL", "SQLITE"), engines.names());
            assertSame(Engines.MYSQL, engines.constant("MYSQL"));
            assertTrue(engines.find("ORACLE").isEmpty());
            assertThrows(IllegalArgumentException.class, () -> engines.constant("ORACLE"));
            engines.require("SQLITE", "MYSQL");
            assertEquals("Fake's Engines has no ORACLE",
                assertThrows(Missing.class, () -> engines.require("ORACLE")).getMessage());
            assertEquals("Fake's Holder isn't an enum", assertThrows(Missing.class, () -> holder().asEnum())
                .getMessage());
        }
    }

    @Nested
    @DisplayName("hiding")
    class Hiding {

        @Test
        @DisplayName("should hide a class, and every member by name")
        void byName() throws Exception {
            Upstream hidden = upstream.hiding(FAKE + "Colors", HOLDER + "#greet", HOLDER + "#running");

            assertEquals("Fake has no class Colors", assertThrows(Missing.class, () -> hidden.type(FAKE + "Colors"))
                .getMessage());
            assertEquals("Fake has no Holder.greet(String)", assertThrows(Missing.class,
                () -> hidden.type(HOLDER).staticMethod("greet", String.class, String.class)).getMessage());
            assertEquals("Fake has no Holder.running", assertThrows(Missing.class,
                () -> hidden.type(HOLDER).staticField("running", boolean.class)).getMessage());
            assertFalse(hidden.has(HOLDER + "#greet"));
            assertTrue(hidden.has(HOLDER + "#twice"));
            assertFalse(hidden.typeIfPresent(FAKE + "Colors").exists());
        }

        @Test
        @DisplayName("should hide a member as the report writes it, and only that overload")
        void byReportForm() throws Exception {
            String member = "net/deltik/mc/libreprotect/extension/upstream/reflect/fake/Holder"
                + "#paint(Lnet/deltik/mc/libreprotect/extension/upstream/reflect/fake/Colors;)Ljava/lang/String;";
            Upstream hidden = upstream.hiding(member);

            StaticMethod<String, RuntimeException> paint = hidden.type(HOLDER).staticMethodShaped("paint",
                String.class, Shape.enumWith("MYSQL"));
            assertEquals("engine MYSQL", paint.call(Engines.MYSQL));
            assertTrue(hidden.has(HOLDER + "#paint"));
        }

        @Test
        @DisplayName("should treat a method whose signature names a hidden class as gone, saying which class")
        void hiddenTypes() {
            Upstream hidden = upstream.hiding(FAKE + "Engines");

            Missing missing = assertThrows(Missing.class, () -> hidden.type(HOLDER).staticMethodShaped("pick",
                String.class, Shape.enumWith("SQLITE"), Shape.exactly(boolean.class)));
            assertEquals("Fake has no class Engines, which Holder.pick(an enum with SQLITE, boolean) uses",
                missing.getMessage());
            assertEquals("Fake has no class Engines, the type of Holder.engine", assertThrows(Missing.class,
                () -> hidden.type(HOLDER).staticField("engine", Enum.class)).getMessage());
        }

        @Test
        @DisplayName("should refuse an older way once a trace of the newer design is there, and not before")
        void requireAbsent() throws Exception {
            Missing refused = assertThrows(Missing.class, () -> upstream.requireAbsent(HOLDER, "greet",
                "so the older way is gone"));
            assertEquals("Fake has Holder.greet, so the older way is gone", refused.getMessage());
            assertTrue(refused.newerDesign());
            assertEquals("Fake has class Colors, so colors are enums", assertThrows(Missing.class,
                () -> upstream.requireAbsent(FAKE + "Colors", null, "so colors are enums")).getMessage());

            upstream.hiding(HOLDER + "#greet").requireAbsent(HOLDER, "greet", "so the older way is gone");
            upstream.requireAbsent(FAKE + "Gone", null, "so it's gone");
        }

        @Test
        @DisplayName("should require the methods a way relies on")
        void relyOn() throws Exception {
            upstream.relyOn("counts", HOLDER, "count()I", "locked()V");

            assertEquals("Fake has no Holder.count(long)", assertThrows(Missing.class,
                () -> upstream.relyOn("counts", HOLDER, "count(J)I")).getMessage());
            assertThrows(Missing.class, () -> upstream.hiding(HOLDER + "#locked").relyOn("locks", HOLDER,
                "locked()V"));
            upstream.relyOn("labels", HOLDER, "<init>(Ljava/lang/String;)V");
            assertEquals("Fake has no constructor Holder(String)", assertThrows(Missing.class,
                () -> upstream.hiding(HOLDER + "#<init>").relyOn("labels", HOLDER, "<init>(Ljava/lang/String;)V"))
                .getMessage());
        }
    }

    @Nested
    @DisplayName("replacing")
    class Replacing {

        @Test
        @DisplayName("should put a stand-in in place of a class, for members declared with its type too")
        void standIn() throws Exception {
            Upstream replaced = upstream.replacing(FAKE + "Engines", Colors.class);

            assertEquals(Colors.class, replaced.type(FAKE + "Engines").type());
            UpstreamEnum engines = replaced.type(FAKE + "Engines").asEnum();
            assertEquals(FAKE + "Engines", engines.name());
            assertEquals(List.of("RED", "GREEN", "MYSQL"), engines.names());
            StaticField engine = replaced.type(HOLDER).staticField("engine", Enum.class);
            assertEquals(Colors.class, engine.type());
            assertEquals(FAKE + "Engines", replaced.type(engine.type()).name());
            StaticMethod<String, RuntimeException> pick = replaced.type(HOLDER).staticMethodShaped("pick",
                String.class, Shape.enumWith("RED"), Shape.exactly(boolean.class));
            assertEquals(Colors.class, pick.parameterType(0));
        }
    }

    @Nested
    @DisplayName("designs")
    class Designs {

        private final Design greetings = Design.of("greetings", FAKE + "Gone", HOLDER + "#greet");

        @Test
        @DisplayName("should know a design by any one of its traces")
        void traces() throws Exception {
            assertEquals("Fake has Holder.greet, part of its greetings", greetings.evidenceIn(upstream).orElseThrow());
            assertTrue(greetings.isIn(upstream));
            greetings.requireIn(upstream);
            Upstream before = upstream.hiding(HOLDER + "#greet");
            assertFalse(greetings.isIn(before));
            Missing absent = assertThrows(Missing.class, () -> greetings.requireIn(before));
            assertTrue(absent.absentFeature());
            assertEquals("Fake has no greetings", absent.getMessage());
            assertThrows(IllegalArgumentException.class, () -> Design.of("nothing"));
        }

        @Test
        @DisplayName("should need what a design brought while upstream has it, and do without it before")
        void since() throws Exception {
            Upstream before = upstream.hiding(HOLDER + "#greet");

            assertEquals("Fake has no Holder.gone()", assertThrows(Missing.class,
                () -> holder().staticMethodSince(greetings, "gone", void.class)).getMessage());
            assertEquals("Fake has no Holder.gone", assertThrows(Missing.class,
                () -> holder().staticFieldSince(greetings, "gone", int.class)).getMessage());
            assertTrue(holder().staticMethodSince(greetings, "twice", int.class, int.class).exists());
            assertFalse(before.type(HOLDER).staticMethodSince(greetings, "gone", void.class).exists());
            assertFalse(before.type(HOLDER).staticFieldSince(greetings, "gone", int.class).exists());
            assertEquals("Fake has no Holder.gone()", assertThrows(Missing.class,
                () -> upstream.relyOnSince(greetings, "goes", HOLDER, "gone()V")).getMessage());
            before.relyOnSince(greetings, "goes", HOLDER, "gone()V");
        }
    }

    @Test
    @DisplayName("should write members as messages do")
    void readable() {
        assertEquals("Consumer.lockDatabaseReload(long)",
            Missing.readable("net/coreprotect/consumer/Consumer#lockDatabaseReload(J)Z"));
        assertEquals("Consumer.lockDatabaseReload",
            Missing.readableName("net/coreprotect/consumer/Consumer#lockDatabaseReload(J)Z"));
        assertEquals("ConfigHandler.serverRunning", Missing.readable("net/coreprotect/config/ConfigHandler#serverRunning:Z"));
        assertEquals("Consumer.OperationStartResult",
            Missing.readable("net/coreprotect/consumer/Consumer$OperationStartResult"));
        assertEquals("Database.createDatabaseTables(String, boolean, Connection, DatabaseType, boolean)",
            Missing.readable("net/coreprotect/database/Database#createDatabaseTables(Ljava/lang/String;Z"
                + "Ljava/sql/Connection;Lnet/coreprotect/database/DatabaseType;Z)V"));
        assertEquals("BlockStatement.transcodeMetadata(byte[], DatabaseType)",
            Missing.readable("net/coreprotect/database/statement/BlockStatement#transcodeMetadata([B"
                + "Lnet/coreprotect/database/DatabaseType;)[B"));
        String constructor = "net/coreprotect/database/clickhouse/ClickHouseJdbc#<init>("
            + "Lnet/coreprotect/database/clickhouse/ClickHouseJdbcConfig;)V";
        assertEquals("constructor ClickHouseJdbc(ClickHouseJdbcConfig)", Missing.readable(constructor));
        assertEquals("constructor ClickHouseJdbc", Missing.readableName(constructor));
    }

    @Test
    @DisplayName("should find the static synchronized methods, which hold the class's lock")
    void staticSynchronized() throws Exception {
        assertEquals(List.of("locked()V"), holder().staticSynchronizedMethods());
        assertFalse(upstream.type(FAKE + "Engines").hasStaticSynchronizedMethod());
    }

    @Test
    @DisplayName("should fall back to reflection for a class file it can't read, and assume members it can't list")
    void unreadableClassFiles() throws Exception {
        String ghost = FAKE + "Ghost";
        // Class files in a format that's too new, for a class that loads and one that doesn't
        ClassLoader newFormat = new ClassLoader(UpstreamTest.class.getClassLoader()) {
            @Override
            public InputStream getResourceAsStream(String name) {
                if (name.equals(HOLDER.replace('.', '/') + ".class") || name.equals(ghost.replace('.', '/') + ".class")) {
                    return new ByteArrayInputStream(new byte[]{(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE,
                        0, 0, 0, 99, 0, 2, 99});
                }
                return super.getResourceAsStream(name);
            }
        };
        Upstream unreadable = Upstream.of("Fake", newFormat);

        assertTrue(unreadable.has(HOLDER + "#greet"));
        assertFalse(unreadable.has(HOLDER + "#nothing"));
        assertTrue(unreadable.has(ghost));
        assertTrue(unreadable.has(ghost + "#anything"));
        assertThrows(Missing.class, () -> unreadable.requireAbsent(ghost, "anything", "so it's newer"));
        assertEquals("Fake's class Ghost can't be read", assertThrows(Missing.class,
            () -> unreadable.relyOn("works", ghost, "work()V")).getMessage());
    }

    @Test
    @DisplayName("should fail every lookup in a class it can't list, never calling a member absent")
    void unlistableClass() throws Exception {
        String unreadableName = FAKE + "Unreadable";
        String unloadable = FAKE + "Unloadable";
        ClassLoader parent = UpstreamTest.class.getClassLoader();
        // A class file too new to read, and a method whose signature names a class that isn't there
        ClassLoader loader = new ClassLoader(parent) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                synchronized (getClassLoadingLock(name)) {
                    if (name.equals(unloadable)) {
                        throw new ClassNotFoundException(name);
                    }
                    if (!name.equals(unreadableName)) {
                        return super.loadClass(name, resolve);
                    }
                    Class<?> loaded = findLoadedClass(name);
                    if (loaded == null) {
                        try (InputStream in = parent.getResourceAsStream(name.replace('.', '/') + ".class")) {
                            byte[] bytes = in.readAllBytes();
                            loaded = defineClass(name, bytes, 0, bytes.length);
                        } catch (IOException e) {
                            throw new ClassNotFoundException(name, e);
                        }
                    }
                    return loaded;
                }
            }

            @Override
            public InputStream getResourceAsStream(String name) {
                if (name.equals(unreadableName.replace('.', '/') + ".class")) {
                    return new ByteArrayInputStream(new byte[]{(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE,
                        0, 0, 0, 99, 0, 2, 99});
                }
                return super.getResourceAsStream(name);
            }
        };
        Upstream unlistable = Upstream.of("Fake", loader);
        UpstreamClass type = unlistable.type(unreadableName);
        String reason = "Fake's class Unreadable can't be read";

        assertTrue(unlistable.has(unreadableName + "#optionalThing"));
        assertEquals(reason, assertThrows(Missing.class,
            () -> type.staticMethodIfPresent("optionalThing", boolean.class)).getMessage());
        assertEquals(reason, assertThrows(Missing.class,
            () -> type.staticMethod("optionalThing", boolean.class)).getMessage());
        assertEquals(reason, assertThrows(Missing.class,
            () -> type.staticFieldIfPresent("nothing", int.class)).getMessage());
        assertEquals(reason, assertThrows(Missing.class, type::staticSynchronizedMethods).getMessage());
        assertEquals(reason, assertThrows(Missing.class, type::asEnum).getMessage());
        assertEquals(reason, assertThrows(Missing.class, type::constructor).getMessage());
    }

    @Test
    @DisplayName("should give a string constant's fallback when its class is absent too")
    void constantOfAbsentClass() throws Exception {
        Supplier<String> schema = upstream.typeIfPresent(FAKE + "Gone").stringConstant("DEFAULT_SCHEMA", "main");
        assertEquals("main", schema.get());
    }
}
