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

package net.deltik.mc.libreprotect.routing.answer;

import net.deltik.mc.libreprotect.LibreProtectLogger;
import net.deltik.mc.libreprotect.routing.RouteActionType;
import net.deltik.mc.libreprotect.routing.RoutePreset;
import net.deltik.mc.libreprotect.routing.RouteRegistry;
import net.deltik.mc.libreprotect.routing.RouteResolver;
import net.deltik.mc.libreprotect.testutil.TestLogger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.logging.Level;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TranslationCacheTest {

    private static final String GERMAN = "# CoreProtect v24.1 Language Cache (de)\n\nHELP_HEADER: \"{0} Hilfe\"";
    /** Dutch, which isn't bundled, as CoreProtect's translation service gave it */
    private static final String DUTCH = "# CoreProtect v24.1 Language Cache (nl)\n\nHELP_HEADER: \"{0} Hulp\"";
    private static final String VERSION = "24.1-libre1";
    private static final String BUNDLED = TranslationCache.bundled(VERSION);

    @TempDir
    Path dataFolder;

    private final TranslationBundle bundle = TranslationBundleTest.bundle("de", "en");
    private TestLogger logger;

    @BeforeEach
    void setUp() {
        TranslationCache.reset(); // Other tests start Bootstrap, which sets where the record is
        logger = new TestLogger();
        LibreProtectLogger.reset();
        LibreProtectLogger.initialize(logger);
    }

    @AfterEach
    void tearDown() {
        TranslationCache.reset();
        LibreProtectLogger.reset();
    }

    private static RouteResolver preset(RoutePreset preset) {
        return new RouteResolver(RouteRegistry.builder().addRoutes(preset.getRoutes())
            .setDefaultAction(preset.getDefaultAction()).build());
    }

    private static RouteResolver translations(RouteActionType action, String target) {
        return new RouteResolver(RouteRegistry.builder()
            .addRoute("http://coreprotect\\.net(?<path>/translate/?)", action, target)
            .setDefaultAction(RouteActionType.BLOCK).build());
    }

    private Path cache() {
        return dataFolder.resolve(TranslationCache.CACHE);
    }

    private Path marker() {
        return dataFolder.resolve(TranslationCache.MARKER);
    }

    private void cache(String content) throws IOException {
        Files.writeString(cache(), content, StandardCharsets.UTF_8);
    }

    private void record(String source) throws IOException {
        Files.writeString(marker(), "# comment\n" + source + "\n", StandardCharsets.UTF_8);
    }

    private String recorded() throws IOException {
        return TranslationCache.recorded(marker().toFile());
    }

    private void update(RouteResolver resolver) throws IOException {
        update(resolver, VERSION);
    }

    private void update(RouteResolver resolver, String version) throws IOException {
        TranslationCache.update(dataFolder.toFile(), resolver, version, bundle);
    }

    private void assertKept(String content) throws IOException {
        assertEquals(content, Files.readString(cache()));
    }

    private void assertEmptied() throws IOException {
        assertTrue(Files.exists(cache()));
        assertEquals(0, Files.size(cache()));
    }

    @Nested
    @DisplayName("source()")
    class Source {

        @Test
        @DisplayName("should be LibreProtect and its version when LibreProtect answers")
        void answer() throws IOException {
            assertEquals(BUNDLED, TranslationCache.source(preset(RoutePreset.PRIVACY_FIRST).getRegistry(), VERSION));
            assertEquals(BUNDLED, TranslationCache.source(preset(RoutePreset.ALLOW_UPDATES).getRegistry(), VERSION));
        }

        @Test
        @DisplayName("should be the translation service, whatever LibreProtect's version, when it passes through")
        void passthrough() throws IOException {
            assertEquals(TranslationCache.SERVICE,
                TranslationCache.source(preset(RoutePreset.PASSTHROUGH).getRegistry(), VERSION));
            assertEquals(TranslationCache.SERVICE,
                TranslationCache.source(translations(RouteActionType.PASSTHROUGH, null).getRegistry(), "other"));
        }

        @ParameterizedTest(name = "target \"{0}\"")
        @ValueSource(strings = {
            "http://translations.example${path}",
            "HTTP://Translations.Example:80${path}",
            "http://translations.example${path} ",
            "http://translations.example${path}\n",
            " http://translations.example${path}",
            "http://user:secret@translations.example${path}#part",
        })
        @DisplayName("should be a redirect's URL as it connects, without whitespace or user info")
        void redirect(String target) throws IOException {
            RouteResolver resolver = translations(RouteActionType.REDIRECT, target);
            assertEquals("http://translations.example/translate/",
                TranslationCache.source(resolver.getRegistry(), VERSION));
        }

        @Test
        @DisplayName("should be nothing when the request is blocked, or redirected to something that isn't a URL")
        void nothing() throws IOException {
            assertNull(TranslationCache.source(translations(RouteActionType.BLOCK, null).getRegistry(), VERSION));
            assertNull(TranslationCache.source(translations(RouteActionType.REDIRECT, "not a url").getRegistry(),
                VERSION));
            assertNull(TranslationCache.source(translations(RouteActionType.REDIRECT, "").getRegistry(), VERSION));
        }
    }

    @Nested
    @DisplayName("update() without a record")
    class NoRecord {

        @Test
        @DisplayName("should keep a cache, as at the first start over CoreProtect, and record it as from before")
        void keepsCache() throws IOException {
            cache(DUTCH);

            update(preset(RoutePreset.PRIVACY_FIRST));

            assertKept(DUTCH);
            assertEquals(TranslationCache.KEPT, recorded());
            assertTrue(logger.getRecords().isEmpty(), logger.getMessages()::toString);
        }

        @Test
        @DisplayName("should keep a cache under passthrough, from start to start, since the service wrote it")
        void passthroughKeepsCache() throws IOException {
            cache(GERMAN);

            update(preset(RoutePreset.PASSTHROUGH));
            update(preset(RoutePreset.PASSTHROUGH));

            assertKept(GERMAN);
            assertEquals(TranslationCache.SERVICE, recorded());
            assertTrue(logger.getRecords().isEmpty(), logger.getMessages()::toString);
        }

        @Test
        @DisplayName("should empty a cache for a redirect at once, rather than at the next start")
        void redirectReplacesCache() throws IOException {
            cache(GERMAN);
            RouteResolver resolver = translations(RouteActionType.REDIRECT, "http://translations.example${path}");

            update(resolver);
            assertEmptied();
            assertEquals("http://translations.example/translate/", recorded());

            cache(GERMAN);
            update(resolver);
            assertKept(GERMAN);
        }

        @Test
        @DisplayName("should record the source when nothing is cached")
        void noCache() throws IOException {
            update(preset(RoutePreset.PASSTHROUGH));

            assertFalse(Files.exists(cache()));
            assertEquals(TranslationCache.SERVICE, recorded());
        }

        @Test
        @DisplayName("should count a cache without CoreProtect's header as nothing cached")
        void invalidHeader() throws IOException {
            cache("HELP_HEADER: \"{0} Hilfe\"");

            update(preset(RoutePreset.PASSTHROUGH));

            assertEquals(TranslationCache.SERVICE, recorded());
        }

        @Test
        @DisplayName("should repair a record that isn't UTF-8, or that it doesn't know, so later changes refresh")
        void unreadableRecord() throws IOException {
            Files.write(marker(), new byte[] {'#', ' ', (byte) 0xC3, '\n', 'x', '\n'});
            cache(GERMAN);

            update(preset(RoutePreset.PRIVACY_FIRST));
            update(preset(RoutePreset.PRIVACY_FIRST));
            assertKept(GERMAN);
            assertEquals(TranslationCache.KEPT, recorded());

            update(preset(RoutePreset.PASSTHROUGH));
            assertEmptied();
            assertEquals(TranslationCache.SERVICE, recorded());
            assertFalse(logger.hasLevel(Level.WARNING), logger.getMessages()::toString);
        }
    }

    @Nested
    @DisplayName("update() with a record")
    class WithRecord {

        @Test
        @DisplayName("should keep the cache and the record while the source stays")
        void sameSource() throws IOException {
            cache(GERMAN);
            record(TranslationCache.SERVICE);
            String before = Files.readString(marker());

            update(preset(RoutePreset.PASSTHROUGH));
            update(translations(RouteActionType.PASSTHROUGH, null), "24.1-libre2");

            assertKept(GERMAN);
            assertEquals(before, Files.readString(marker()));
        }

        @Test
        @DisplayName("should empty the cache for the translation service or a redirect, which an admin chose")
        void adminChoice() throws IOException {
            cache(DUTCH);
            record(BUNDLED);

            update(preset(RoutePreset.PASSTHROUGH));

            assertEmptied();
            assertEquals(TranslationCache.SERVICE, recorded());
            assertTrue(logger.hasMessageContaining(Level.INFO, "Refreshing translations, since they now come from "
                + TranslationCache.SERVICE + " instead of " + BUNDLED));

            cache(DUTCH);
            update(translations(RouteActionType.REDIRECT, "http://translations.example${path}"));
            assertEmptied();
            assertEquals("http://translations.example/translate/", recorded());
        }

        @Test
        @DisplayName("should keep translations from before LibreProtect, whatever LibreProtect's version")
        void keptFromBefore() throws IOException {
            for (String cached : new String[] {GERMAN, DUTCH}) {
                cache(cached);
                record(TranslationCache.KEPT);

                update(preset(RoutePreset.PRIVACY_FIRST));
                update(preset(RoutePreset.PRIVACY_FIRST), "24.1-libre2");

                assertKept(cached);
                assertEquals(TranslationCache.KEPT, recorded());
            }
        }

        @Test
        @DisplayName("should keep translations from before LibreProtect through an upgrade, from the first start")
        void upgradeKeepsUnbundledCache() throws IOException {
            cache(DUTCH);

            update(preset(RoutePreset.PRIVACY_FIRST), "24.1-libre1");
            update(preset(RoutePreset.PRIVACY_FIRST), "24.1-libre2");

            assertKept(DUTCH);
        }

        @Test
        @DisplayName("should refresh a bundled language once for a new LibreProtect version")
        void newVersion() throws IOException {
            cache(GERMAN);
            record(TranslationCache.bundled("24.1-libre0"));

            update(preset(RoutePreset.PRIVACY_FIRST));

            assertEmptied();
            assertEquals(BUNDLED, recorded());
        }

        @Test
        @DisplayName("should keep a language that isn't bundled, which the bundle can't replace")
        void notBundled() throws IOException {
            for (String previous : new String[] {TranslationCache.SERVICE, TranslationCache.bundled("24.1-libre0"),
                "http://translations.example/translate/"}) {
                cache(DUTCH);
                record(previous);

                update(preset(RoutePreset.PRIVACY_FIRST));

                assertKept(DUTCH);
                assertEquals(previous, recorded(), "the record still says what wrote the cache");
            }
        }

        @Test
        @DisplayName("should ask the translation service again after it failed")
        void serviceFailed() throws IOException {
            update(preset(RoutePreset.PASSTHROUGH));
            TranslationCache.answered(TranslationCache.SERVICE_FAILED);
            assertEquals(TranslationCache.SERVICE_FAILED, recorded());
            cache(GERMAN);

            update(preset(RoutePreset.PASSTHROUGH));

            assertEmptied();
            assertEquals(TranslationCache.SERVICE, recorded());
            assertTrue(logger.hasMessageContaining(Level.INFO, "Asking " + TranslationCache.SERVICE + " for translations "
                + "again, since it failed last time"));
        }

        @Test
        @DisplayName("should refresh from the bundle after the service failed, when the service is no longer allowed")
        void serviceFailedThenAnswer() throws IOException {
            cache(GERMAN);
            record(TranslationCache.SERVICE_FAILED);

            update(preset(RoutePreset.PRIVACY_FIRST));

            assertEmptied();
            assertEquals(BUNDLED, recorded());
            assertTrue(logger.hasMessageContaining(Level.INFO, "now come from " + BUNDLED));
        }

        @Test
        @DisplayName("should keep the cache and the record when translation requests are blocked")
        void blocked() throws IOException {
            cache(GERMAN);
            record(TranslationCache.SERVICE);

            update(translations(RouteActionType.BLOCK, null));

            assertKept(GERMAN);
            assertEquals(TranslationCache.SERVICE, recorded());
        }

        @Test
        @DisplayName("should record a new source without a log line when there is no cache to empty")
        void noCache() throws IOException {
            record(BUNDLED);

            update(preset(RoutePreset.PASSTHROUGH));

            assertFalse(Files.exists(cache()));
            assertEquals(TranslationCache.SERVICE, recorded());
            assertTrue(logger.getRecords().isEmpty(), logger.getMessages()::toString);
        }

        @ParameterizedTest(name = "target \"{0}\"")
        @ValueSource(strings = {"http://127.0.0.1:8080/translate/ ", "http://127.0.0.1:8080/translate/\n",
            " http://127.0.0.1:8080/translate/", "http://user:secret@127.0.0.1:8080/translate/",
            "http://127.0.0.1:8080/trans late/"})
        @DisplayName("should keep a redirect's cache from start to start, and never record or log user info")
        void redirectStable(String target) throws IOException {
            RouteResolver resolver = new RouteResolver(RouteRegistry.builder()
                .addRoute("https?://coreprotect\\.net/translate/?", RouteActionType.REDIRECT, target)
                .setDefaultAction(RouteActionType.BLOCK).build());
            record(TranslationCache.SERVICE);
            cache(GERMAN);

            update(resolver);
            cache(GERMAN);
            update(resolver);
            update(resolver);

            assertKept(GERMAN);
            assertEquals(1, logger.getRecords().size(), logger.getMessages()::toString);
            assertFalse(Files.readString(marker()).contains("secret"));
            assertFalse(logger.getMessages().toString().contains("secret"));
        }
    }

    @Nested
    @DisplayName("update() when files can't be written")
    class Failures {

        @Test
        @DisplayName("should keep the cache when the new source can't be recorded, so it can't empty it at every start")
        void recordFails() throws IOException {
            cache(GERMAN);
            Files.createDirectory(marker());

            TranslationCache.update(dataFolder.toFile(), preset(RoutePreset.PASSTHROUGH));

            assertKept(GERMAN);
            assertTrue(logger.hasLevel(Level.WARNING));
        }

        @Test
        @DisplayName("should keep the old record when the cache can't be emptied, so the next start tries again")
        void cacheReadOnly() throws IOException {
            cache(GERMAN);
            record(BUNDLED);
            assertTrue(cache().toFile().setWritable(false));

            TranslationCache.update(dataFolder.toFile(), preset(RoutePreset.PASSTHROUGH));

            if (!Files.isWritable(cache())) { // Unless the tests run as root
                assertKept(GERMAN);
                assertEquals(BUNDLED, recorded());
                assertTrue(logger.hasLevel(Level.WARNING));
            }
        }

        @Test
        @DisplayName("should write nothing before CoreProtect creates its folder")
        void noFolder() {
            Path missing = dataFolder.resolve("CoreProtect");

            TranslationCache.update(missing.toFile(), preset(RoutePreset.PRIVACY_FIRST));
            TranslationCache.answered(TranslationCache.SERVICE_FAILED);

            assertFalse(Files.exists(missing));
            assertTrue(logger.getRecords().isEmpty(), logger.getMessages()::toString);
        }

        @Test
        @DisplayName("should never throw")
        void neverThrows() {
            assertDoesNotThrow(() -> TranslationCache.update(null, preset(RoutePreset.PRIVACY_FIRST)));
            assertDoesNotThrow(() -> TranslationCache.update(dataFolder.toFile(), null));
            assertTrue(logger.hasLevel(Level.WARNING));
        }
    }

    @Test
    @DisplayName("answered() should do nothing before update()")
    void answeredFirst() {
        TranslationCache.answered(TranslationCache.SERVICE_FAILED);
        assertFalse(Files.exists(marker()));
        assertTrue(logger.getRecords().isEmpty());
    }

    @Test
    @DisplayName("answered() should record what wrote the cache")
    void answered() throws IOException {
        cache(DUTCH);
        update(preset(RoutePreset.PRIVACY_FIRST));
        assertEquals(TranslationCache.KEPT, recorded());

        TranslationCache.answered(BUNDLED);

        assertEquals(BUNDLED, recorded());
    }
}
