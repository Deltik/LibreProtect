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

package net.deltik.mc.libreprotect.extension.migration;

import net.deltik.mc.libreprotect.extension.common.DatabaseSettings;
import net.deltik.mc.libreprotect.extension.common.Engine;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Connector;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Connectors;
import net.deltik.mc.libreprotect.extension.migration.jdbc.Dialect;
import net.deltik.mc.libreprotect.extension.migration.jdbc.DuckDBAppenderInsert;
import net.deltik.mc.libreprotect.extension.migration.jdbc.IncompleteMarker;
import net.deltik.mc.libreprotect.extension.migration.jdbc.JdbcRowSink;
import net.deltik.mc.libreprotect.extension.migration.jdbc.JdbcRowSource;

import java.io.File;
import java.sql.SQLDataException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.UnaryOperator;

/**
 * A bridge over real JDBC databases in files, without CoreProtect. Columnar
 * engines store {@code block.meta} with a header, so crossing
 * between relational and columnar engines needs transcoding, like
 * CoreProtect 25's codecs.
 */
final class FakeBridge implements MigrationBridge {

    /** How the fake columnar encoding starts, like CoreProtect 25's codecs start with "CP" */
    static final byte[] COLUMNAR_HEADER = {'C', 'P'};
    /** How metadata that the fake codec can't read starts */
    static final byte[] UNREADABLE = {(byte) 0xDE, (byte) 0xAD};

    final AtomicInteger canonicalCalls = new AtomicInteger();
    Set<Engine> engines = EnumSet.of(Engine.SQLITE, Engine.MYSQL, Engine.DUCKDB);
    Engine active;
    MigrationException refusal;
    /** Why migrations aren't available at all, or {@code null} */
    String unavailable;
    /** Why migrating to an engine isn't available */
    final Map<Engine, String> unavailableTargets = new EnumMap<>(Engine.class);
    final List<Engine> claims = new ArrayList<>();
    /** What converting metadata throws, such as a change of CoreProtect's; {@code null} to convert it */
    RuntimeException conversionFailure;
    FakeSession session;

    FakeBridge(FakeSession session) {
        this.session = session;
        this.active = session == null ? Engine.SQLITE : session.source.engine();
    }

    @Override
    public Set<Engine> engines() {
        return engines;
    }

    @Override
    public Engine activeEngine() {
        return active;
    }

    @Override
    public String unavailableReason() {
        return unavailable;
    }

    @Override
    public String unavailableReason(Engine target) {
        return unavailableTargets.get(target);
    }

    @Override
    public MigrationSession claim(Engine target) throws MigrationException {
        claims.add(target);
        if (refusal != null) {
            throw refusal;
        }
        return session;
    }

    @Override
    public Object transcode(String table, String column, Object value, Engine from, Engine to) throws SQLException {
        if (!isMeta(table, column) || !(value instanceof byte[]) || from.isColumnar() == to.isColumnar()) {
            return value;
        }
        if (conversionFailure != null) {
            throw conversionFailure;
        }
        byte[] bytes = (byte[]) value;
        checkReadable(bytes);
        return to.isColumnar() ? encode(bytes) : decode(bytes);
    }

    @Override
    public Object canonical(String table, String column, Object value) throws SQLException {
        canonicalCalls.incrementAndGet();
        if (!isMeta(table, column) || !(value instanceof byte[])) {
            return value;
        }
        checkReadable((byte[]) value);
        return decode((byte[]) value);
    }

    /**
     * Metadata that starts with {@link #UNREADABLE}, like a legacy value
     * naming a type that CoreProtect's codec doesn't know
     */
    private static void checkReadable(byte[] bytes) throws SQLDataException {
        if (bytes.length >= UNREADABLE.length && bytes[0] == UNREADABLE[0] && bytes[1] == UNREADABLE[1]) {
            throw new SQLDataException("Unknown enum constant org.bukkit.Unheard.OF");
        }
    }

    static boolean isMeta(String table, String column) {
        return table.equals("block") && column.equals("meta");
    }

    static byte[] encode(byte[] legacy) {
        byte[] columnar = new byte[legacy.length + COLUMNAR_HEADER.length];
        System.arraycopy(COLUMNAR_HEADER, 0, columnar, 0, COLUMNAR_HEADER.length);
        System.arraycopy(legacy, 0, columnar, COLUMNAR_HEADER.length, legacy.length);
        return columnar;
    }

    static boolean isEncoded(byte[] bytes) {
        return bytes.length >= COLUMNAR_HEADER.length && bytes[0] == COLUMNAR_HEADER[0]
            && bytes[1] == COLUMNAR_HEADER[1];
    }

    static byte[] decode(byte[] bytes) {
        return isEncoded(bytes) ? Arrays.copyOfRange(bytes, COLUMNAR_HEADER.length, bytes.length) : bytes;
    }

    /** Something a test does at a point of the migration */
    @FunctionalInterface
    interface Work {
        void run() throws Exception;
    }

    /**
     * A migration between two database files, recording what the migration
     * asks of it.
     */
    static final class FakeSession implements MigrationSession {

        final DatabaseSettings source;
        final DatabaseSettings target;
        final AtomicInteger pauses = new AtomicInteger();
        final AtomicInteger closes = new AtomicInteger();
        final AtomicInteger activations = new AtomicInteger();
        volatile String stopReason;
        MigrationException activationFailure;
        UnaryOperator<RowSink> sinkWrapper = UnaryOperator.identity();
        UnaryOperator<RowSource> sourceWrapper = UnaryOperator.identity();
        UnaryOperator<Connector> targetConnector = UnaryOperator.identity();
        boolean appender = true;
        List<String> pauseNotes = List.of();
        List<String> failureNotes = List.of();
        MigrationException preflightFailure;
        /** What happens while CoreProtect is paused, such as another writer finishing */
        Work duringPause = () -> { };
        Thread thread;

        FakeSession(Engine sourceEngine, File sourceFile, Engine targetEngine, File targetFile) {
            this(DatabaseSettings.embedded(sourceEngine, sourceFile), DatabaseSettings.embedded(targetEngine, targetFile));
        }

        FakeSession(DatabaseSettings source, DatabaseSettings target) {
            this.source = source;
            this.target = target;
        }

        @Override
        public Engine source() {
            return source.engine();
        }

        @Override
        public DatabaseSettings sourceSettings() {
            return source;
        }

        @Override
        public DatabaseSettings targetSettings() {
            return target;
        }

        @Override
        public void preflight() throws MigrationException {
            if (preflightFailure != null) {
                throw preflightFailure;
            }
        }

        @Override
        public List<String> pause() {
            thread = Thread.currentThread();
            pauses.incrementAndGet();
            try {
                duringPause.run();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
            return pauseNotes;
        }

        @Override
        public String stopReason() {
            return stopReason;
        }

        @Override
        public RowSource openSource() {
            return sourceWrapper.apply(new JdbcRowSource(Dialect.of(source.engine()), connector(source), true, true,
                source.prefix(), TestDatabases.TABLES));
        }

        @Override
        public RowSink openSink(DatabaseSettings settings) {
            return sinkWrapper.apply(new JdbcRowSink(Dialect.of(settings.engine()),
                targetConnector.apply(connector(settings)), settings.prefix(), TestDatabases.TABLES,
                TestDatabases.schema(settings.engine()), IncompleteMarker.status(2), settings.file(),
                settings.engine() == Engine.DUCKDB && appender ? new DuckDBAppenderInsert() : null));
        }

        @Override
        public List<String> activate(RowSink sink, DatabaseSettings settings) throws MigrationException {
            activations.incrementAndGet();
            if (activationFailure != null) {
                throw activationFailure;
            }
            try {
                sink.markComplete();
                sink.close();
            } catch (SQLException e) {
                throw new MigrationException("Activation failed: " + e.getMessage(), e);
            }
            return List.of("Activated.");
        }

        @Override
        public List<String> afterFailure() {
            return failureNotes;
        }

        @Override
        public void close() {
            closes.incrementAndGet();
        }

        static Connector connector(DatabaseSettings settings) {
            File file = settings.file();
            switch (settings.engine()) {
                case DUCKDB:
                    return Connectors.duckdb(file, TestDatabases.duckDBProperties(file));
                case MYSQL:
                    return Connectors.mysql(settings.host(), settings.port(), settings.database(), settings.username(),
                        settings.password(), false);
                default:
                    return Connectors.sqlite(file);
            }
        }
    }
}
