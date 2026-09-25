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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Choosing among the ways to use a capability, on a fake upstream, and what
 * the choice reports.
 */
class ChoiceTest {

    private static final String FAKE = "net.deltik.mc.libreprotect.extension.upstream.reflect.fake.";
    private static final String HOLDER = FAKE + "Holder";
    private static final String HOLDER_INTERNAL = "net/deltik/mc/libreprotect/extension/upstream/reflect/fake/Holder";

    private final Upstream upstream = Upstream.of("Fake", ChoiceTest.class.getClassLoader());

    /** The newer way: needs Holder.greet and Holder.twice */
    private static String newer(Upstream upstream) throws Missing {
        UpstreamClass holder = upstream.type(HOLDER);
        holder.staticMethod("greet", String.class, String.class);
        holder.staticMethod("twice", int.class, int.class);
        holder.staticMethodIfPresent("gone", void.class);
        holder.staticFieldIfPresent("running", boolean.class);
        upstream.type(FAKE + "Engines").asEnum();
        upstream.relyOn("counts\tup", HOLDER, "count()I");
        upstream.doc("docs/fake.md", "how greetings work");
        return "newer";
    }

    /** The design of the newer way, which has only one trace */
    private static final Design GREETINGS = Design.of("greetings", HOLDER + "#greet");

    /** The older way, which the newer way's design rules out */
    private static String older(Upstream upstream) throws Missing {
        upstream.type(HOLDER).staticField("running", boolean.class);
        return "older";
    }

    private Choice<String> choose(Upstream upstream) {
        return Choice.first(upstream, "fake.greeting",
            Choice.way("newer", "the newer way", GREETINGS, ChoiceTest::newer),
            Choice.way("older", "the older way", ChoiceTest::older));
    }

    @Test
    @DisplayName("should choose the first way that works, recording what it resolved")
    void first() throws Exception {
        Choice<String> choice = choose(upstream);

        assertTrue(choice.isAvailable());
        assertFalse(choice.isAbsent());
        assertEquals("newer", choice.strategy());
        assertEquals("the newer way", choice.reason());
        assertEquals("newer", choice.require());
        assertEquals(List.of(
            "capability\tfake.greeting\tnewer\tthe newer way",
            "member\tfake.greeting\tnet/deltik/mc/libreprotect/extension/upstream/reflect/fake/Engines",
            "member\tfake.greeting\t" + HOLDER_INTERNAL,
            "member\tfake.greeting\t" + HOLDER_INTERNAL + "#greet(Ljava/lang/String;)Ljava/lang/String;",
            "member\tfake.greeting\t" + HOLDER_INTERNAL + "#twice(I)I",
            "optional\tfake.greeting\t" + HOLDER_INTERNAL + "#gone()V\tabsent",
            "optional\tfake.greeting\t" + HOLDER_INTERNAL + "#running:Z\tpresent",
            "relies\tfake.greeting\t" + HOLDER_INTERNAL + "#count()I\tcounts up",
            "enum\tfake.greeting\tnet/deltik/mc/libreprotect/extension/upstream/reflect/fake/Engines"
                + "\tCLICKHOUSE,DUCKDB,MYSQL,POSTGRESQL,SQLITE",
            "doc\tfake.greeting\tdocs/fake.md\thow greetings work"), choice.reportLines());
    }

    @Test
    @DisplayName("should take an older way only on an upstream without a trace of the newer one")
    void older() throws Exception {
        Choice<String> choice = choose(upstream.hiding(HOLDER + "#greet"));

        assertEquals("older", choice.strategy());
        assertEquals(List.of("newer: Fake has no Holder.greet(String)"), choice.rejected());
        assertTrue(choice.reportLines().contains("rejected\tfake.greeting\tnewer\tFake has no Holder.greet(String)"));
        assertTrue(choice.reportLines().contains("member\tfake.greeting\t" + HOLDER_INTERNAL + "#running:Z"));
    }

    @Test
    @DisplayName("should be unavailable, not fall back, when upstream has part of the newer way")
    void partial() {
        Choice<String> choice = choose(upstream.hiding(HOLDER + "#twice"));

        assertFalse(choice.isAvailable());
        assertFalse(choice.isAbsent());
        assertEquals("unavailable", choice.strategy());
        assertEquals("Fake has no Holder.twice(int)", choice.reason());
        assertEquals("Fake has no Holder.twice(int)", assertThrows(Missing.class, choice::require).getMessage());
        assertFalse(assertThrows(Missing.class, choice::require).absentFeature());
        assertEquals(List.of(
            "capability\tfake.greeting\tunavailable\tFake has no Holder.twice(int)",
            "rejected\tfake.greeting\tnewer\tFake has no Holder.twice(int)",
            "rejected\tfake.greeting\tolder\tFake has Holder.greet, part of its greetings, which replaced older"),
            choice.reportLines());
        assertEquals("fallback", choice.orElse("fallback"));
    }

    @Test
    @DisplayName("should rule out older ways while upstream has any one trace of a newer way's design")
    void anyTrace() {
        Design design = Design.of("greetings", HOLDER + "#greet", FAKE + "Colors#RED");
        Choice<String> choice = Choice.first(upstream.hiding(HOLDER + "#greet"), "fake.greeting",
            Choice.way("newer", "the newer way", design, ChoiceTest::newer),
            Choice.way("older", "the older way", ChoiceTest::older));

        assertEquals("unavailable", choice.strategy());
        assertEquals(List.of("newer: Fake has no Holder.greet(String)",
            "older: Fake has Colors.RED, part of its greetings, which replaced older"), choice.rejected());
    }

    @Test
    @DisplayName("should rule out older ways when the newer way's first lookup is what upstream renamed")
    void renamedFirstLookup() {
        Upstream renamed = upstream.hiding(FAKE + "Colors");
        Design design = Design.of("colorful greetings", FAKE + "Colors", HOLDER + "#greet");
        Choice<String> choice = Choice.first(renamed, "fake.rule",
            Choice.way("newer", "the newer way", design, u -> {
                u.type(FAKE + "Colors").asEnum();
                u.type(HOLDER).staticMethod("greet", String.class, String.class);
                return "newer";
            }),
            Choice.way("older", "an ordinary older way", u -> "older"));

        assertEquals("unavailable", choice.strategy(), () -> "took " + choice.strategy() + " after "
            + choice.rejected());
        assertEquals("Fake has no class Colors", choice.reason());
        assertEquals("older: Fake has Holder.greet, part of its colorful greetings, which replaced older",
            choice.rejected().get(1));
    }

    @Test
    @DisplayName("should refuse ways where one without a design has an ordinary older way after it")
    void designsRequired() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
            () -> Choice.first(upstream, "fake.rule",
                Choice.way("newer", "the newer way", ChoiceTest::newer),
                Choice.fallback("slow", "the slow way", u -> "slow"),
                Choice.way("older", "an ordinary older way", u -> "older")));
        assertEquals("The way newer has an older way after it, older, so it needs a design to rule that out",
            refused.getMessage());

        Choice.requireDesigns(List.of(Choice.way("only", "the only way", u -> "only")));
        Choice.requireDesigns(List.of(Choice.way("fast", "the fast way", u -> "fast"),
            Choice.fallback("slow", "the slow way", u -> "slow")));
        Choice.requireDesigns(List.of(Choice.way("newer", "the newer way", GREETINGS, u -> "newer"),
            Choice.way("older", "the older way", u -> "older")));
    }

    @Test
    @DisplayName("should give the reason of the oldest way that upstream didn't rule out")
    void reasonOfOldest() {
        Choice<String> choice = choose(upstream.hiding(HOLDER + "#greet", HOLDER + "#running"));

        assertEquals("unavailable", choice.strategy());
        assertEquals("Fake has no Holder.running", choice.reason());
    }

    @Test
    @DisplayName("should be quietly absent when upstream doesn't have the feature, without trying older ways")
    void absent() {
        List<String> tried = new ArrayList<>();
        Design feature = Design.of("the feature", FAKE + "Gone");
        Choice<String> choice = Choice.first(upstream, "fake.feature",
            Choice.way("newer", "the newer way", feature, u -> {
                tried.add("newer");
                feature.requireIn(u);
                return "newer";
            }),
            Choice.way("older", "the older way", u -> {
                tried.add("older");
                return "older";
            }));

        assertTrue(choice.isAbsent());
        assertFalse(choice.isAvailable());
        assertEquals("absent", choice.strategy());
        assertEquals("Fake has no the feature", choice.reason());
        assertEquals(List.of("newer"), tried);
        assertTrue(assertThrows(Missing.class, choice::require).absentFeature());
    }

    @Test
    @DisplayName("should take a fallback after a newer way that upstream has only part of")
    void fallback() {
        Choice<String> choice = Choice.first(upstream.hiding(HOLDER + "#twice"), "fake.writes",
            Choice.way("fast", "the fast way", ChoiceTest::newer),
            Choice.fallback("slow", "the slow way", u -> "slow"));

        assertEquals("slow", choice.strategy());
        assertTrue(choice.usesFallback());
        assertEquals(List.of("fast: Fake has no Holder.twice(int)"), choice.rejected());
    }

    @Test
    @DisplayName("should reject a way whose probe fails unexpectedly, with the failure")
    void crashingProbe() {
        Choice<String> choice = Choice.first(upstream, "fake.crash",
            Choice.way("crash", "a crashing way", u -> {
                throw new IllegalStateException("boom");
            }));

        assertEquals("unavailable", choice.strategy());
        assertEquals("Fake failed the crash probe: java.lang.IllegalStateException: boom", choice.reason());
    }

    @Test
    @DisplayName("should record nothing found in a library that upstream brings along")
    void library() throws Exception {
        Choice<String> choice = Choice.first(upstream, "fake.library",
            Choice.way("library", "a library's way", u -> {
                Upstream library = u.library("Fake's library");
                library.type(HOLDER).staticMethod("greet", String.class, String.class);
                assertEquals("Fake's library has no class Gone", assertThrows(Missing.class,
                    () -> library.type(FAKE + "Gone")).getMessage());
                return "library";
            }));

        assertEquals("library", choice.require());
        assertEquals(List.of("capability\tfake.library\tlibrary\ta library's way"), choice.reportLines());
    }

    @Test
    @DisplayName("should keep tabs and line breaks out of report fields")
    void cleanFields() {
        Choice<String> choice = Choice.first(upstream, "fake.messy",
            Choice.way("messy", "a\tmessy\ndescription", u -> "messy"));

        assertEquals(List.of("capability\tfake.messy\tmessy\ta messy description"), choice.reportLines());
    }
}
