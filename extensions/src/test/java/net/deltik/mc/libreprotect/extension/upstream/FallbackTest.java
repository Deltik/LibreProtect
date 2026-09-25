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

package net.deltik.mc.libreprotect.extension.upstream;

import net.deltik.mc.libreprotect.extension.upstream.reflect.Choice;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Missing;
import net.deltik.mc.libreprotect.extension.upstream.reflect.Upstream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * What happens when upstream loses what a chosen way needs, as when it
 * renames or removes it in a new version: the capability becomes
 * unavailable and says what's missing, rather than falling back to an older
 * way whose names upstream still has but whose meaning it changed. Only a
 * way declared a fallback, which is always safe, may take over.
 */
class FallbackTest {

    private static final Capabilities REAL = Capabilities.probe(Upstream.coreProtect());

    /** Optional members whose absence is harmless, which a way may do without */
    private static final Set<String> HARMLESS_OPTIONAL = Set.of(
        "net/coreprotect/database/DatabaseType#getDisplayName()Ljava/lang/String;");

    /**
     * @return the capability report's lines, each split into its fields
     */
    private static List<String[]> lines(Choice<?> choice) {
        List<String[]> lines = new ArrayList<>();
        for (String line : choice.reportLines()) {
            lines.add(line.split("\t"));
        }
        return lines;
    }

    /**
     * @return every member that the ways chosen on the CoreProtect being built need, by capability
     */
    static Stream<Arguments> members() {
        List<Arguments> members = new ArrayList<>();
        for (Choice<?> choice : REAL.all()) {
            for (String[] fields : lines(choice)) {
                if (fields[0].equals("member")) {
                    members.add(Arguments.of(choice.id(), fields[2]));
                }
            }
        }
        return members.stream();
    }

    /**
     * @return every optional member that the chosen ways found, by capability
     */
    static Stream<Arguments> optionalMembers() {
        List<Arguments> members = new ArrayList<>();
        for (Choice<?> choice : REAL.all()) {
            for (String[] fields : lines(choice)) {
                if (fields[0].equals("optional") && fields[3].equals("present")) {
                    members.add(Arguments.of(choice.id(), fields[2]));
                }
            }
        }
        return members.stream();
    }

    /**
     * @return every member of the report that the chosen ways found
     */
    private static Set<String> found() {
        Set<String> all = new TreeSet<>();
        for (Choice<?> choice : REAL.all()) {
            for (String[] fields : lines(choice)) {
                if (fields[0].equals("member") || fields[0].equals("relies")
                    || (fields[0].equals("optional") && fields[3].equals("present"))) {
                    all.add(fields[2]);
                }
            }
        }
        return all;
    }

    /**
     * @return a class with every member of the report whose signature names
     *         it, as a rename of the class would take them all
     */
    private static List<String> renamed(String type, Set<String> found) {
        List<String> group = new ArrayList<>();
        group.add(type);
        for (String member : found) {
            if (member.contains("#") && member.contains("L" + type + ";")) {
                group.add(member);
            }
        }
        return group;
    }

    /**
     * @return each class that the chosen ways need, with its uses
     */
    static Stream<Arguments> renames() {
        Set<String> found = found();
        List<Arguments> renames = new ArrayList<>();
        for (String type : found) {
            if (!type.contains("#")) {
                renames.add(Arguments.of(renamed(type, found)));
            }
        }
        return renames.stream();
    }

    /**
     * @return for each trace of CoreProtect 25's design, every other trace,
     *         a class with its uses in the report, as a sweeping rename that
     *         left only that trace would take them
     */
    static Stream<Arguments> designTraces() {
        Set<String> found = found();
        List<Arguments> renames = new ArrayList<>();
        for (String kept : Designs.MULTI_ENGINE.traces()) {
            List<String> hidden = new ArrayList<>();
            for (String trace : Designs.MULTI_ENGINE.traces()) {
                if (trace.equals(kept)) {
                    continue;
                }
                if (trace.contains("#")) {
                    hidden.add(trace);
                } else {
                    hidden.addAll(renamed(trace.replace('.', '/'), found));
                }
            }
            // A rename that left the kept trace left its signature too
            String left = kept.replace('.', '/');
            hidden.removeIf(member -> member.equals(left) || member.startsWith(left + ":")
                || member.startsWith(left + "("));
            renames.add(Arguments.of(kept, hidden));
        }
        return renames.stream();
    }

    @ParameterizedTest(name = "{0} without {1}")
    @MethodSource("members")
    @DisplayName("should become unavailable without a member it needs, saying which, and not fall back")
    void withoutMember(String id, String member) {
        assertUnavailable(id, List.of(member), Capabilities.probe(Upstream.coreProtect().hiding(member)).get(id));
    }

    // CoreProtect 24 has none of the optional members
    @ParameterizedTest(name = "{0} without {1}", allowZeroInvocations = true)
    @MethodSource("optionalMembers")
    @DisplayName("should do without an optional member only if that's harmless, and otherwise become unavailable")
    void withoutOptionalMember(String id, String member) {
        Choice<?> after = Capabilities.probe(Upstream.coreProtect().hiding(member)).get(id);

        if (HARMLESS_OPTIONAL.contains(member)) {
            assertEquals(REAL.get(id).strategy(), after.strategy(), after::toString);
            assertTrue(after.reportLines().contains("optional\t" + id + "\t" + member + "\tabsent"),
                () -> String.join("\n", after.reportLines()));
        } else {
            assertUnavailable(id, List.of(member), after);
        }
    }

    @ParameterizedTest(name = "without {0}")
    @MethodSource("renames")
    @DisplayName("should become unavailable, not fall back, when a class is renamed with its uses")
    void renamed(List<String> group) {
        Capabilities after = Capabilities.probe(Upstream.coreProtect().hiding(group.toArray(new String[0])));

        for (Choice<?> choice : REAL.all()) {
            boolean affected = false;
            for (String[] fields : lines(choice)) {
                affected |= fields.length > 2 && (group.contains(fields[2]) || fields[2].startsWith(group.get(0) + "#"));
            }
            if (affected) {
                assertUnavailable(choice.id(), group, after.get(choice.id()));
            }
        }
    }

    /**
     * A capability that decided it's absent from names of its own, such as
     * DuckDB's classes, would be quietly absent after a rename although some
     * of the design is still there, and without a member to name, since an
     * absent capability records none.
     */
    @ParameterizedTest(name = "with only {0}")
    @MethodSource("designTraces")
    @DisplayName("should keep every capability CoreProtect has from becoming absent while any trace of its design is left")
    void withOneDesignTrace(String kept, List<String> hidden) {
        Capabilities after = Capabilities.probe(Upstream.coreProtect().hiding(hidden.toArray(new String[0])));

        for (Choice<?> choice : REAL.all()) {
            if (choice.isAbsent()) {
                continue;
            }
            Choice<?> now = after.get(choice.id());
            assertFalse(now.isAbsent(), () -> choice.id() + " became absent without " + hidden + ": " + now.reason());
            for (String rejected : choice.rejected()) {
                String strategy = rejected.substring(0, rejected.indexOf(':'));
                assertNotEquals(strategy, now.strategy(), () -> choice.id() + " fell back to " + strategy
                    + " without " + hidden);
            }
        }
    }

    /**
     * Check that a capability didn't fall back to an older way after
     * upstream lost some of what its chosen way needs.
     *
     * @param hidden what upstream lost
     */
    private static void assertUnavailable(String id, List<String> hidden, Choice<?> after) {
        Choice<?> before = REAL.get(id);
        List<String> names = new ArrayList<>();
        for (String member : hidden) {
            names.add(Missing.readableName(member));
        }
        for (String rejected : before.rejected()) {
            String strategy = rejected.substring(0, rejected.indexOf(':'));
            assertNotEquals(strategy, after.strategy(), () -> id + " fell back to " + strategy
                + ", which CoreProtect doesn't support: " + after.rejected());
        }
        assertFalse(after.isAbsent(), () -> id + " became absent without " + hidden + ": " + after.reason());
        if (after.isAvailable()) {
            assertTrue(after.usesFallback(), () -> id + " fell back to " + after.strategy() + " without " + hidden
                + ": " + after.rejected());
            assertTrue(after.rejected().stream().anyMatch(reason -> names.stream().anyMatch(reason::contains)),
                () -> "No rejection of " + id + " names any of " + names + ": " + after.rejected());
        } else {
            assertTrue(names.stream().anyMatch(after.reason()::contains), () -> id + "'s reason names none of "
                + names + ": " + after.reason());
        }
    }
}
