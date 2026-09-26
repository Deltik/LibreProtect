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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DifferencesTest {

    @Test
    @DisplayName("names known capabilities as features")
    void knownFeatures() {
        assertEquals("`/co migrate-db`", Differences.feature("migrate-db.protocol"));
        assertEquals("`/co migrate-db` from MySQL", Differences.feature("migrate-db.source.mysql"));
        assertEquals("`/co migrate-db` to ClickHouse", Differences.feature("migrate-db.target.clickhouse"));
        assertEquals("`auto-purge`: taking turns with CoreProtect's database work",
            Differences.feature("auto-purge.coordination"));
        assertEquals("`auto-purge` with SQLite", Differences.feature("auto-purge.engine.sqlite"));
        // Shared by several features, and shown only when unavailable
        assertEquals("Pausing CoreProtect's database writes", Differences.feature("consumer.gate"));
        assertEquals("Noticing a manual purge at work", Differences.feature("hook.purge-worker"));
    }

    @Test
    @DisplayName("shows other capabilities by ID")
    void unknownFeatures() {
        assertEquals("`/co migrate-db` from `oracle`", Differences.feature("migrate-db.source.oracle"));
        assertEquals("`migrate-db.source.`", Differences.feature("migrate-db.source."));
        assertEquals("`something.new`", Differences.feature("something.new"));
    }

    @Test
    @DisplayName("shows no capability ID for a known capability, available, unavailable or absent")
    void noCapabilityIds() {
        List<String> ids = new ArrayList<>(Differences.FEATURES.keySet());
        ids.addAll(Differences.SHARED.keySet());
        List<TransformReport.Capability> capabilities = new ArrayList<>();
        for (int i = 0; i < ids.size(); i++) {
            String value = i % 3 == 0 ? "some-way" : i % 3 == 1 ? CapabilityReport.UNAVAILABLE : CapabilityReport.ABSENT;
            boolean available = i % 3 == 0;
            capabilities.add(new TransformReport.Capability(ids.get(i), value, available ? "does what it does" : null,
                available ? null : "CoreProtect has no Thing.thing()", List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of()));
        }
        StringBuilder md = new StringBuilder();

        Differences.capabilities(md, capabilities);

        String rendered = md.toString();
        assertTrue(rendered.contains("| Feature | With this CoreProtect |"), rendered);
        for (String id : ids) {
            assertFalse(rendered.contains(id), () -> id + " in:\n" + rendered);
        }
    }

    private static TransformReport.Capability capability(String id, boolean available) {
        return new TransformReport.Capability(id, available ? "some-way" : CapabilityReport.UNAVAILABLE,
            available ? "does what it does" : null, available ? null : "CoreProtect has no Thing.thing()", List.of(),
            List.of(), List.of(), List.of(), List.of(), List.of());
    }

    /**
     * @return the table's closing sentence about the shared capabilities, for these of them
     */
    private static String sharedSentence(List<TransformReport.Capability> shared) {
        StringBuilder md = new StringBuilder();
        List<TransformReport.Capability> capabilities = new ArrayList<>(shared);
        capabilities.add(capability("auto-purge.engine.sqlite", true));
        Differences.capabilities(md, capabilities);
        String rendered = md.toString();
        return rendered.substring(rendered.indexOf("The features also rest on")).strip();
    }

    @Test
    @DisplayName("says that the shared capabilities all work only when none of them is unavailable")
    void sharedCapabilities() {
        String prefix = "that several of them share, such as telling which database CoreProtect uses. ";
        assertEquals("The features also rest on 2 capabilities " + prefix + "All of those work with this CoreProtect.",
            sharedSentence(List.of(capability("lifecycle.flags", true), capability("consumer.gate", true))));
        assertEquals("The features also rest on 1 capability " + prefix + "It works with this CoreProtect.",
            sharedSentence(List.of(capability("lifecycle.flags", true))));
        assertEquals("The features also rest on 3 capabilities " + prefix + "One of those doesn't work with this"
            + " CoreProtect, as the table shows; the others do.", sharedSentence(List.of(
                capability("lifecycle.flags", false), capability("consumer.gate", true),
                capability("server.thread", true))));
        assertEquals("The features also rest on 3 capabilities " + prefix + "2 of those don't work with this"
            + " CoreProtect, as the table shows; the others do.", sharedSentence(List.of(
                capability("lifecycle.flags", false), capability("consumer.gate", false),
                capability("server.thread", true))));
        assertEquals("The features also rest on 2 capabilities " + prefix + "None of those work with this"
            + " CoreProtect, as the table shows.", sharedSentence(List.of(capability("lifecycle.flags", false),
                capability("consumer.gate", false))));
        assertEquals("The features also rest on 1 capability " + prefix + "It doesn't work with this CoreProtect,"
            + " as the table shows.", sharedSentence(List.of(capability("lifecycle.flags", false))));
    }

    @Test
    @DisplayName("shows any value as code, whatever backticks it has")
    void code() {
        assertEquals("`plain`", Differences.code("plain"));
        assertEquals("``a`b``", Differences.code("a`b"));
        assertEquals("``` a``b` ```", Differences.code("a``b`"));
        assertEquals("`<script>`", Differences.code("<script>"), "code spans show HTML as text");
        assertEquals("`two lines`", Differences.code("two\nlines"));
    }

    @Test
    @DisplayName("escapes text in a table cell so that it shows as it is")
    void cellText() {
        assertEquals("a \\| b \\`c\\` &lt;i&gt;d&lt;/i&gt; &amp;amp; \\\\ e f",
            Differences.cellText("a | b `c` <i>d</i> &amp; \\ e\nf"));
    }
}
