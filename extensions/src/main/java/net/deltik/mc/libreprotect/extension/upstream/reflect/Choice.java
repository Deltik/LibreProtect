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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * How LibreProtect uses one capability of upstream: the first of its ways,
 * newest first, that upstream supports, or why none is.
 *
 * <p>A way that upstream doesn't support throws {@link Missing}, and the
 * next, older way may be tried, but only if upstream has nothing of the
 * newer ways that failed, since names outlive their meanings: an older way
 * isn't taken while upstream has any trace of the {@link Design} of a newer
 * way. So an upstream that has part of a newer design leaves the capability
 * {@code unavailable}, with the newer way's failure as the reason, rather
 * than falling back. Only a way declared as a {@link #fallback}, which is
 * always safe, only slower, is exempt; and so every other way with an older
 * way after it must be declared with its design (see {@link #requireDesigns}).
 *
 * <p>A way that throws an {@linkplain Missing#absentFeature() absent
 * feature} ends the search: upstream doesn't have the capability at all,
 * and it's quietly {@code absent}.
 *
 * @param <T> what the capability gives its users
 */
public final class Choice<T> {

    /** Probes one way, resolving everything it will use */
    @FunctionalInterface
    public interface Probe<T> {
        /**
         * @param upstream upstream, recording what the way resolves
         * @throws Missing if upstream doesn't support the way
         */
        T probe(Upstream upstream) throws Missing;
    }

    /** One way to use a capability */
    public static final class Way<T> {
        private final String strategy;
        private final String description;
        private final Design design;
        private final Probe<? extends T> probe;
        private final boolean fallback;

        private Way(String strategy, String description, Design design, Probe<? extends T> probe,
                    boolean fallback) {
            this.strategy = Objects.requireNonNull(strategy, "strategy");
            this.description = Objects.requireNonNull(description, "description");
            this.design = design;
            this.probe = Objects.requireNonNull(probe, "probe");
            this.fallback = fallback;
        }

        public String strategy() {
            return strategy;
        }

        /**
         * @return the way in short plain English, which DIFFERENCES.md shows
         *         users for a capability that takes it
         */
        public String description() {
            return description;
        }
    }

    private static final class Rejection {
        final Way<?> way;
        final Missing why;

        Rejection(Way<?> way, Missing why) {
            this.way = way;
            this.why = why;
        }
    }

    public static final String ABSENT = "absent";
    public static final String UNAVAILABLE = "unavailable";

    private final String id;
    private final Way<? extends T> chosen;
    private final T value;
    private final Findings findings;
    private final List<Rejection> rejections;
    private final Missing failure;

    private Choice(String id, Way<? extends T> chosen, T value, Findings findings, List<Rejection> rejections,
                   Missing failure) {
        this.id = id;
        this.chosen = chosen;
        this.value = value;
        this.findings = findings;
        this.rejections = Collections.unmodifiableList(rejections);
        this.failure = failure;
    }

    /**
     * A way without a design, for a way that has no older way after it, or
     * only fallbacks.
     *
     * @param strategy the way's name in the capability report, such as {@code database-type}
     * @param description the way in short plain English, such as "CoreProtect's database-type setting"
     */
    public static <T> Way<T> way(String strategy, String description, Probe<? extends T> probe) {
        return new Way<>(strategy, description, null, probe, false);
    }

    /**
     * @param design the design the way belongs to, which rules out every
     *               older way while upstream has any trace of it
     */
    public static <T> Way<T> way(String strategy, String description, Design design, Probe<? extends T> probe) {
        return new Way<>(strategy, description, Objects.requireNonNull(design, "design"), probe, false);
    }

    /**
     * @return a way that may follow a newer way that upstream has only part
     *         of, because it's always safe, only slower
     */
    public static <T> Way<T> fallback(String strategy, String description, Probe<? extends T> probe) {
        return new Way<>(strategy, description, null, probe, true);
    }

    /**
     * @param id the capability's ID in the report, such as {@code database.selector}
     * @param ways the ways, newest first
     * @throws IllegalArgumentException if the ways aren't declared as
     *                                  {@link #requireDesigns} needs
     */
    @SafeVarargs
    public static <T> Choice<T> first(Upstream upstream, String id, Way<? extends T>... ways) {
        List<Way<? extends T>> list = new ArrayList<>();
        for (Way<? extends T> way : ways) {
            list.add(way);
        }
        return first(upstream, id, list);
    }

    /**
     * @throws IllegalArgumentException if the ways aren't declared as
     *                                  {@link #requireDesigns} needs
     */
    public static <T> Choice<T> first(Upstream upstream, String id, List<? extends Way<? extends T>> ways) {
        requireDesigns(ways);
        List<Rejection> rejections = new ArrayList<>();
        for (Way<? extends T> way : ways) {
            String newer = way.fallback ? null : newerDesign(upstream, rejections);
            if (newer != null) {
                rejections.add(new Rejection(way, Missing.newerDesign(newer + ", which replaced " + way.strategy)));
                continue;
            }
            Findings findings = new Findings();
            Missing why;
            try {
                T value = way.probe.probe(upstream.recording(findings));
                return new Choice<>(id, way, value, findings, rejections, null);
            } catch (Missing e) {
                why = e;
            } catch (RuntimeException | LinkageError e) {
                why = new Missing(upstream.name() + " failed the " + way.strategy + " probe: " + e);
            }
            rejections.add(new Rejection(way, why));
            if (why.absentFeature()) {
                return new Choice<>(id, null, null, null, rejections, why);
            }
        }
        return new Choice<>(id, null, null, null, rejections, reason(rejections));
    }

    /**
     * Check that every way with an older way after it, other than a
     * fallback, is declared with its design: only a design shows whether
     * upstream has part of a way, so only it can keep an older way off an
     * upstream that has part of a newer one. What a way happens to find
     * before it fails can't: classes that every version has show nothing,
     * and a renamed first lookup hides the rest.
     *
     * @param ways the ways, newest first
     * @throws IllegalArgumentException if a way isn't declared so
     */
    public static void requireDesigns(List<? extends Way<?>> ways) {
        for (int i = 0; i < ways.size(); i++) {
            Way<?> newer = ways.get(i);
            if (newer.fallback || newer.design != null) {
                continue;
            }
            for (Way<?> older : ways.subList(i + 1, ways.size())) {
                if (!older.fallback) {
                    throw new IllegalArgumentException("The way " + newer.strategy + " has an older way after it, "
                        + older.strategy + ", so it needs a design to rule that out");
                }
            }
        }
    }

    /**
     * @return how upstream shows that it has part of a newer way that failed,
     *         which rules out older ways, or {@code null} if it shows nothing
     */
    private static String newerDesign(Upstream upstream, List<Rejection> rejections) {
        for (Rejection newer : rejections) {
            if (newer.way.design != null && !newer.why.newerDesign()) {
                Optional<String> evidence = newer.way.design.evidenceIn(upstream);
                if (evidence.isPresent()) {
                    return evidence.get();
                }
            }
        }
        return null;
    }

    /**
     * The reason a capability is unavailable is the failure of its oldest
     * way that upstream didn't rule out with a newer design: its newer ways
     * failed because upstream isn't that new.
     */
    private static Missing reason(List<Rejection> rejections) {
        if (rejections.isEmpty()) {
            return new Missing("There is no way to use it");
        }
        for (int i = rejections.size() - 1; i >= 0; i--) {
            if (!rejections.get(i).why.newerDesign()) {
                return rejections.get(i).why;
            }
        }
        return rejections.get(0).why;
    }

    public String id() {
        return id;
    }

    public boolean isAvailable() {
        return chosen != null;
    }

    /**
     * @return whether upstream doesn't have the capability at all
     */
    public boolean isAbsent() {
        return chosen == null && failure.absentFeature();
    }

    /**
     * @return the chosen way's strategy, or {@code absent} or {@code unavailable}
     */
    public String strategy() {
        return chosen != null ? chosen.strategy : failure.absentFeature() ? ABSENT : UNAVAILABLE;
    }

    /**
     * @return whether the chosen way is a {@link #fallback}
     */
    public boolean usesFallback() {
        return chosen != null && chosen.fallback;
    }

    /**
     * @return the chosen way's description, or why no way is available
     */
    public String reason() {
        return chosen != null ? chosen.description : failure.getMessage();
    }

    /**
     * @return what the capability gives
     * @throws Missing why it isn't available
     */
    public T require() throws Missing {
        if (chosen == null) {
            throw failure.absentFeature() ? Missing.absentFeature(failure.getMessage())
                : new Missing(failure.getMessage());
        }
        return value;
    }

    /**
     * @return what the capability gives, or {@code other} if it isn't available
     */
    public T orElse(T other) {
        return chosen != null ? value : other;
    }

    /**
     * @return the strategies that were rejected, in the order they were
     *         tried, with why
     */
    public List<String> rejected() {
        List<String> rejected = new ArrayList<>();
        for (Rejection rejection : rejections) {
            rejected.add(rejection.way.strategy + ": " + rejection.why.getMessage());
        }
        return rejected;
    }

    /**
     * @return the capability's lines of the capability report, tab-separated
     *         and unsorted: its outcome, and for the chosen way what it
     *         resolved and relies on
     */
    public List<String> reportLines() {
        List<String> lines = new ArrayList<>();
        lines.add(line("capability", id, strategy(), reason()));
        if (findings != null) {
            for (String member : findings.members) {
                lines.add(line("member", id, member));
            }
            for (Map.Entry<String, Boolean> optional : findings.optional.entrySet()) {
                lines.add(line("optional", id, optional.getKey(), optional.getValue() ? "present" : "absent"));
            }
            for (Map.Entry<String, String> relies : findings.relies.entrySet()) {
                lines.add(line("relies", id, relies.getKey(), relies.getValue()));
            }
            for (Map.Entry<String, List<String>> enumeration : findings.enums.entrySet()) {
                lines.add(line("enum", id, enumeration.getKey(), String.join(",", enumeration.getValue())));
            }
            for (Map.Entry<String, String> doc : findings.docs.entrySet()) {
                lines.add(line("doc", id, doc.getKey(), doc.getValue()));
            }
        }
        for (Rejection rejection : rejections) {
            lines.add(line("rejected", id, rejection.way.strategy, rejection.why.getMessage()));
        }
        return lines;
    }

    private static String line(String... fields) {
        List<String> clean = new ArrayList<>();
        for (String field : fields) {
            clean.add(field.replace('\t', ' ').replace('\r', ' ').replace('\n', ' '));
        }
        return String.join("\t", clean);
    }

    @Override
    public String toString() {
        return id + ": " + strategy() + " (" + reason() + ")";
    }
}
