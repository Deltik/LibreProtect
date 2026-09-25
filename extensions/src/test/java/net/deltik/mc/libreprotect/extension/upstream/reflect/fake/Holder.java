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

package net.deltik.mc.libreprotect.extension.upstream.reflect.fake;

import java.io.IOException;
import java.sql.SQLException;

/**
 * A fake upstream class, in another package than the toolkit, with the
 * kinds of members that CoreProtect has.
 */
public class Holder {

    public static final int CONSTANT = 7;
    public static final String NAME = "holder";
    public static final long NOT_AN_INT = 3L;

    public static volatile boolean running = true;
    /** Like CoreProtect's Consumer.pausedSuccess */
    protected static volatile boolean parked;
    private static int counter;
    public static Engines engine = Engines.SQLITE;

    public boolean enabled = true;
    private String label = "fresh";
    public final long created = System.nanoTime();

    static {
        Initialized.CLASSES.add("Holder");
    }

    public Holder() {
    }

    public Holder(String label) {
        this.label = label;
    }

    public static String greet(String who) {
        return "Hello, " + who;
    }

    public static int twice(int number) {
        return 2 * number;
    }

    /**
     * @param kind what to throw
     */
    public static void fail(String kind) throws IOException, SQLException {
        switch (kind) {
            case "io":
                throw new IOException("I/O");
            case "sql":
                throw new SQLException("SQL");
            case "state":
                throw new IllegalStateException("state");
            default:
                throw new AssertionError("error");
        }
    }

    public static String pick(Engines engine, boolean loud) {
        return loud ? engine.name() : engine.name().toLowerCase();
    }

    public static String paint(Colors color) {
        return "painted " + color;
    }

    public static String paint(Engines engine) {
        return "engine " + engine;
    }

    public static Holder create() {
        return new Holder("created");
    }

    static synchronized void locked() {
    }

    public String describe(int times) {
        return label.repeat(times);
    }

    /**
     * Returns this for chaining, like newer drivers do.
     */
    public Holder rename(String label) {
        this.label = label;
        return this;
    }

    public void relabel(String label) {
        this.label = label;
    }

    private static int count() {
        return ++counter;
    }
}
