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

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Turns upstream CoreProtect's JAR into LibreProtect's JAR.
 *
 * <p>Every assumption about upstream is checked, and a failed check throws
 * {@link ContractViolation} instead of producing a JAR that might quietly not
 * do its job.
 */
final class Transformer {

    /**
     * @param extensionsJar LibreProtect's extension implementations, which reach
     *                      upstream only by reflection, or {@code null} for none
     * @param capabilities the extensions build's capability report, which it
     *                     probed against {@code upstreamJar}, or {@code null}
     *                     if the extensions JAR has no classes
     * @param upstreamDirectory upstream's source checkout, for the
     *                          documentation that the capability report
     *                          names; {@code null} only for a report that
     *                          names none
     * @param translations upstream's {@code lang/} directory, whose translations LibreProtect bundles
     * @param description plugin.yml's description, or {@code null} to derive it from upstream's
     */
    record Options(
        Path upstreamJar,
        Path originalJar,
        Path runtimeJar,
        Path extensionsJar,
        Path capabilities,
        Path upstreamDirectory,
        Path translations,
        Path outputJar,
        String version,
        String description,
        String website,
        String upstreamRef,
        String upstreamCommit,
        String forkCommit,
        long timestamp,
        List<String> exemptPrefixes
    ) {
    }

    static final String EXPECTED_PLUGIN_NAME = "CoreProtect";
    static final String EXTENSIONS_PACKAGE = "net/coreprotect/utility/extensions/";
    static final String BUILD_PROPERTIES = "libreprotect-build.properties";
    static final String REPORT_DIRECTORY = "META-INF/libreprotect/";
    /** The extensions' only way to CoreProtect: reflection, through this package */
    static final String UPSTREAM_ACCESS_PACKAGE = "net.deltik.mc.libreprotect.extension.upstream";

    private final Options options;
    private final TransformReport report = new TransformReport();
    private final JarContents output = new JarContents();
    private final Map<String, Origin> origins = new LinkedHashMap<>();
    private final Set<String> phraseRenderers = new HashSet<>();
    private JarContents upstream;

    Transformer(Options options) {
        this.options = options;
    }

    /**
     * @return upstream's JAR as it was before the transformation, available after {@link #run()}
     */
    JarContents upstream() {
        return upstream;
    }

    /**
     * @return the origin of each class entry that came from the upstream JAR
     */
    Map<String, Origin> origins() {
        return origins;
    }

    /**
     * Transform in memory. Call {@link #write} to produce the JAR.
     */
    TransformReport run() throws IOException {
        upstream = JarContents.read(options.upstreamJar());
        JarContents original = JarContents.read(options.originalJar());
        JarContents runtime = JarContents.read(options.runtimeJar());
        JarContents extensions = options.extensionsJar() == null ? new JarContents()
            : JarContents.read(options.extensionsJar());

        Set<String> upstreamClasses = original.names().stream()
            .filter(JarContents::isClass)
            .map(JarContents::internalName)
            .collect(Collectors.toSet());
        ContractViolation.require(!upstreamClasses.isEmpty(),
            "The unshaded upstream JAR " + options.originalJar() + " contains no classes");

        report.upstreamRef = options.upstreamRef();
        report.upstreamCommit = options.upstreamCommit();
        report.forkVersion = options.version();
        report.forkCommit = options.forkCommit();
        report.exemptPrefixes = options.exemptPrefixes();

        PluginYml pluginYml = readPluginYml(upstream);
        String mainClass = pluginYml.getString("main").replace('.', '/');
        int mainClassVersion = checkMainClass(upstream, mainClass);
        report.upstreamMainClass = mainClass.replace('/', '.');
        report.generatedMainClass = SubclassGenerator.CLASS_NAME.replace('/', '.');
        // As Bukkit reads it, which is what CoreProtect would compare in upstream's own build
        report.upstreamVersion = pluginYml.getString("version");
        ContractViolation.require(report.upstreamVersion != null && !report.upstreamVersion.isBlank()
                && !report.upstreamVersion.contains("${"),
            "plugin.yml version is '" + report.upstreamVersion + "'. CoreProtect compares versions with the one that "
                + "upstream's build puts there, so it must be set.");
        Object libraries = pluginYml.get("libraries");
        ContractViolation.require(libraries == null || libraries instanceof List,
            "plugin.yml's libraries is '" + libraries + "', not a list of libraries for the server to download");
        if (libraries instanceof List<?> list) {
            list.forEach(library -> report.pluginLibraries.add(String.valueOf(library)));
        }

        findPhraseRenderers(upstreamClasses);

        for (String name : upstream.names()) {
            byte[] data = upstream.get(name);
            if (JarContents.isClass(name)) {
                String internalName = JarContents.internalName(name);
                Origin origin = classify(internalName, upstreamClasses);
                origins.put(name, origin);
                count(origin, name);
                data = transformClass(name, data, origin, internalName.equals(mainClass));
            }
            output.put(name, data);
        }

        checkEditionGates();
        checkPluginVersionReads();
        checkBranding();
        ContractViolation.require(!report.egressSites.isEmpty(),
            "Found no java.net.URL connection calls to redirect. Upstream may have switched to another "
                + "network API, which the audit should report, or removed its telemetry. Review the upstream "
                + "changes before relaxing this check.");
        checkNoRawEgress(upstreamClasses);
        checkRuntime(runtime);
        checkExtensionPoints(upstream, upstreamClasses, runtime);
        checkExtensionPoints(upstream, upstreamClasses, extensions);

        for (JarContents injected : List.of(runtime, extensions)) {
            for (String name : injected.names()) {
                if (name.equals(JarContents.MANIFEST) || name.startsWith("META-INF/maven/")) {
                    continue;
                }
                ContractViolation.require(!output.contains(name), "LibreProtect's " + name
                    + " would overwrite a file that upstream now ships, or that LibreProtect adds twice");
                output.put(name, injected.get(name));
                report.injectedEntries.add(name);
            }
        }
        bundleTranslations(upstreamClasses);
        checkIsolation(runtime, extensions);
        bundleCapabilities(extensions);

        String generatedEntry = SubclassGenerator.CLASS_NAME + ".class";
        ContractViolation.require(!output.contains(generatedEntry), "Upstream ships " + generatedEntry);
        output.put(generatedEntry, SubclassGenerator.generate(mainClass, mainClassVersion));
        report.injectedEntries.add(generatedEntry);

        Map<String, String> changes = new LinkedHashMap<>();
        changes.put("main", report.generatedMainClass);
        changes.put("version", options.version());
        changes.put("description", options.description() != null ? options.description() : description(pluginYml));
        changes.put("website", options.website());
        PluginYml edited = pluginYml.with(changes);
        for (Map.Entry<String, String> change : changes.entrySet()) {
            report.pluginYmlChanges.put(change.getKey(),
                new TransformReport.ValueChange(pluginYml.getString(change.getKey()), change.getValue()));
        }
        output.put(PluginYml.ENTRY, edited.text().getBytes(StandardCharsets.UTF_8));

        output.put(BUILD_PROPERTIES, buildProperties().getBytes(StandardCharsets.UTF_8));
        report.injectedEntries.add(BUILD_PROPERTIES);
        for (String reportFile : List.of("DIFFERENCES.md", "transform-report.json", "audit-report.json")) {
            report.injectedEntries.add(REPORT_DIRECTORY + reportFile);
        }
        report.injectedEntries.sort(null);
        output.put(REPORT_DIRECTORY + "DIFFERENCES.md", Differences.render(report).getBytes(StandardCharsets.UTF_8));
        output.put(REPORT_DIRECTORY + "transform-report.json", Reports.toJson(report).getBytes(StandardCharsets.UTF_8));
        return report;
    }

    /**
     * Write the JAR, including the audit report if there is one.
     */
    void write(AuditReport audit) throws IOException {
        if (audit != null) {
            output.put(REPORT_DIRECTORY + "audit-report.json", Reports.toJson(audit).getBytes(StandardCharsets.UTF_8));
        }
        output.write(options.outputJar(), options.timestamp());
    }

    private PluginYml readPluginYml(JarContents upstream) {
        byte[] bytes = upstream.get(PluginYml.ENTRY);
        ContractViolation.require(bytes != null, "Upstream JAR has no plugin.yml");
        ContractViolation.require(!upstream.contains("paper-plugin.yml"),
            "Upstream JAR now has a paper-plugin.yml, which Paper prefers over plugin.yml. "
                + "LibreProtect only knows how to hook plugin.yml.");

        PluginYml pluginYml = new PluginYml(new String(bytes, StandardCharsets.UTF_8));
        ContractViolation.require(EXPECTED_PLUGIN_NAME.equals(pluginYml.getString("name")),
            "plugin.yml name is '" + pluginYml.getString("name") + "', expected '" + EXPECTED_PLUGIN_NAME
                + "'. LibreProtect keeps upstream's plugin name so it can replace CoreProtect in place.");
        String branch = pluginYml.getString("branch");
        ContractViolation.require(branch != null && !branch.isBlank() && !branch.contains("${"),
            "plugin.yml branch is '" + branch + "'. CoreProtect refuses to start without a branch; "
                + "build upstream with -Dproject.branch=...");
        ContractViolation.require(pluginYml.getString("main") != null, "plugin.yml has no main class");
        return pluginYml;
    }

    /**
     * @return the class file version of the main class
     */
    private int checkMainClass(JarContents upstream, String mainClass) {
        byte[] bytes = upstream.get(mainClass + ".class");
        ContractViolation.require(bytes != null, "plugin.yml main class " + mainClass + " is not in the JAR");

        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, ClassReader.SKIP_CODE);
        ContractViolation.require((node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT)) == 0,
            "Main class " + mainClass + " is abstract or an interface");
        ContractViolation.require(node.permittedSubclasses == null || node.permittedSubclasses.isEmpty(),
            "Main class " + mainClass + " is sealed, so LibreProtect's subclass would fail to load");

        boolean hasConstructor = false;
        for (MethodNode method : node.methods) {
            if (method.name.equals("<init>") && method.desc.equals("()V")) {
                hasConstructor = (method.access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) != 0;
            }
        }
        ContractViolation.require(hasConstructor,
            "Main class " + mainClass + " has no public or protected no-argument constructor");

        // Walk up to JavaPlugin, checking every class on the way that could make onEnable final
        String current = mainClass;
        Set<String> seen = new HashSet<>();
        while (!SubclassGenerator.JAVA_PLUGIN.equals(current)) {
            ContractViolation.require(seen.add(current), "Cyclic class hierarchy at " + current);
            byte[] classBytes = upstream.get(current + ".class");
            ContractViolation.require(classBytes != null,
                "Main class hierarchy leaves the JAR at " + current + " before reaching "
                    + SubclassGenerator.JAVA_PLUGIN);
            ClassNode classNode = new ClassNode();
            new ClassReader(classBytes).accept(classNode, ClassReader.SKIP_CODE);
            for (MethodNode method : classNode.methods) {
                if (method.name.equals("onEnable") && method.desc.equals("()V")) {
                    ContractViolation.require((method.access & Opcodes.ACC_FINAL) == 0,
                        current + ".onEnable() is final, so LibreProtect's subclass can't hook it");
                }
            }
            current = classNode.superName;
        }

        return ClassScan.readVersion(bytes);
    }

    private Origin classify(String internalName, Set<String> upstreamClasses) {
        if (upstreamClasses.contains(internalName)) {
            return Origin.UPSTREAM;
        }
        for (String prefix : options.exemptPrefixes()) {
            if (internalName.startsWith(prefix)) {
                return Origin.EXEMPT_LIBRARY;
            }
        }
        return Origin.LIBRARY;
    }

    private void count(Origin origin, String entry) {
        if (JarContents.isVersioned(entry)) {
            return;
        }
        switch (origin) {
            case UPSTREAM -> report.upstreamClassCount++;
            case LIBRARY -> report.libraryClassCount++;
            case EXEMPT_LIBRARY -> report.exemptLibraryClassCount++;
        }
    }

    private byte[] transformClass(String entry, byte[] data, Origin origin, boolean isMainClass) {
        int sitesBefore = report.egressSites.size();
        int gatesBefore = report.editionGates.size();
        int versionReadsBefore = report.pluginVersionReads.size();
        int brandingBefore = report.brandingSites.size();

        ClassReader reader = new ClassReader(data);
        // A fresh constant pool drops references that the rewrite leaves unused
        ClassWriter writer = new ClassWriter(0);
        ClassVisitor visitor = writer;
        if (isMainClass) {
            visitor = new ClassVisitor(Opcodes.ASM9, visitor) {
                @Override
                public void visit(int version, int access, String name, String signature, String superName,
                                  String[] interfaces) {
                    super.visit(version, access & ~Opcodes.ACC_FINAL, name, signature, superName, interfaces);
                }
            };
        }
        if (origin == Origin.UPSTREAM) {
            visitor = new EditionGateRewriter(visitor, entry, report.editionGates);
            visitor = new PluginVersionRewriter(visitor, entry, report.upstreamVersion, report.pluginVersionReads);
            visitor = new BrandingRewriter(visitor, entry, phraseRenderers, report.brandingSites);
        }
        if (origin != Origin.EXEMPT_LIBRARY) {
            visitor = new EgressRewriter(visitor, entry, origin, report.egressSites);
        }
        reader.accept(visitor, 0);

        boolean changed = isMainClass
            || report.egressSites.size() != sitesBefore
            || report.editionGates.size() != gatesBefore
            || report.pluginVersionReads.size() != versionReadsBefore
            || report.brandingSites.size() != brandingBefore;
        // Classes with nothing to change keep upstream's exact bytes
        return changed ? writer.toByteArray() : data;
    }

    private void checkEditionGates() {
        for (String gate : EditionGateRewriter.GATES.keySet()) {
            List<TransformReport.EditionGate> matches = report.editionGates.stream()
                .filter(match -> !JarContents.isVersioned(match.entry()))
                .filter(match -> match.method().startsWith(gate + "("))
                .toList();
            ContractViolation.require(matches.size() == 1,
                "Expected exactly one upstream method 'static boolean " + gate + "()' to unlock, found "
                    + matches.size() + ": " + matches + ". Upstream may have renamed or split its edition checks.");
        }
    }

    private void checkPluginVersionReads() {
        List<TransformReport.PluginVersionRead> reads = report.pluginVersionReads.stream()
            .filter(read -> !JarContents.isVersioned(read.entry()))
            .toList();
        ContractViolation.require(reads.size() == 1,
            "Expected exactly one PluginDescriptionFile.getVersion() call in an upstream method 'static String "
                + PluginVersionRewriter.METHOD + "()' to have read upstream's version, found " + reads.size() + ": "
                + reads + ". Upstream may read its own version another way now, and would compare LibreProtect's "
                + "version instead of its own with the versions of its database, patches and features.");
    }

    private void findPhraseRenderers(Set<String> upstreamClasses) {
        for (String name : upstream.names()) {
            if (JarContents.isClass(name) && upstreamClasses.contains(JarContents.internalName(name))) {
                phraseRenderers.addAll(BrandingRules.phraseRenderers(upstream.get(name)));
            }
        }
        report.phraseRenderers.addAll(phraseRenderers.stream().sorted().toList());
        ContractViolation.require(!phraseRenderers.isEmpty(),
            "Found no phrase renderer: a static method of an enum that takes one of its constants and a String[] "
                + "and returns a String, like CoreProtect's Phrase.build(Phrase, String...). LibreProtect hooks it "
                + "to leave out donation-key messages and to point links at LibreProtect.");
    }

    /**
     * Add upstream's translations unchanged, each checked against the phrases
     * of the enum that the phrase renderer renders, and the built-in English
     * from upstream's code.
     */
    private void bundleTranslations(Set<String> upstreamClasses) throws IOException {
        Translations.checkCacheName(upstream, upstreamClasses);
        Set<String> phraseEnums = phraseRenderers.stream()
            .map(renderer -> renderer.substring(0, renderer.indexOf('.')))
            .collect(Collectors.toCollection(TreeSet::new));
        Set<String> phrases = Translations.phrases(upstream, phraseEnums);
        report.phraseCount = phrases.size();
        Map<String, byte[]> files = new TreeMap<>(Translations.read(options.translations(), phrases,
            report.translations));

        Map<String, String> defaults = Translations.defaults(upstream, phraseEnums, phrases);
        phrases.stream().filter(phrase -> !defaults.containsKey(phrase)).forEach(report.phrasesWithoutDefault::add);
        report.englishDifferences.addAll(Translations.englishDifferences(Translations.parse(new String(
            files.get(Translations.DIRECTORY + Translations.ENGLISH + ".yml"), StandardCharsets.UTF_8)), defaults));
        files.put(Translations.DEFAULTS, Translations.defaultsFile(defaults));

        for (Map.Entry<String, byte[]> file : files.entrySet()) {
            ContractViolation.require(!output.contains(file.getKey()), "LibreProtect's " + file.getKey()
                + " would overwrite a file that upstream now ships, or that LibreProtect adds twice");
            output.put(file.getKey(), file.getValue());
            report.injectedEntries.add(file.getKey());
        }
    }

    private void checkBranding() {
        ContractViolation.require(report.countBranding(BrandingRewriter.KIND_PHRASE) > 0,
            "Found no calls to the phrase renderer " + report.phraseRenderers + " to hook");
        ContractViolation.require(report.countBranding(BrandingRewriter.KIND_OUTPUT) > 0,
            "Found no Bukkit sendMessage(String) or java.util.logging.Logger calls to hook. Upstream may print "
                + "messages another way now, and phrases that LibreProtect leaves out would show up.");
    }

    private void checkNoRawEgress(Set<String> upstreamClasses) {
        for (String name : output.names()) {
            if (!JarContents.isClass(name)
                || classify(JarContents.internalName(name), upstreamClasses) == Origin.EXEMPT_LIBRARY) {
                continue;
            }
            ContractViolation.require(!ClassScan.of(output.get(name)).hasRawEgress(),
                name + " still opens java.net.URL connections directly after rewriting");
        }
    }

    /**
     * LibreProtect's classes must not reference upstream's: the runtime runs
     * before CoreProtect initializes, and the extensions, including the
     * upstream entry points that they implement, reach CoreProtect only by
     * reflection.
     */
    private void checkIsolation(JarContents runtime, JarContents extensions) {
        Set<String> shipped = upstream.names().stream()
            .filter(name -> JarContents.isClass(name) && !JarContents.isVersioned(name))
            .map(JarContents::internalName)
            .collect(Collectors.toSet());
        Set<String> own = new HashSet<>();
        for (JarContents injected : List.of(runtime, extensions)) {
            injected.names().stream().filter(JarContents::isClass).map(JarContents::internalName).forEach(own::add);
        }
        IsolationCheck isolation = new IsolationCheck(shipped, own);
        for (String name : runtime.names()) {
            if (JarContents.isClass(name)) {
                isolation.check(runtime.get(name),
                    "runtime classes must not touch CoreProtect; move it to the extensions module");
            }
        }
        for (String name : extensions.names()) {
            if (JarContents.isClass(name)) {
                isolation.check(extensions.get(name), "extensions reach CoreProtect only by reflection through "
                    + UPSTREAM_ACCESS_PACKAGE);
            }
        }
        ContractViolation.require(isolation.violations().isEmpty(), "LibreProtect's classes use upstream's classes "
            + "directly:\n  " + String.join("\n  ", isolation.violations()));
    }

    /**
     * Read the capability report of the extensions' build, which must have
     * probed this upstream JAR, and bundle it.
     */
    private void bundleCapabilities(JarContents extensions) throws IOException {
        if (options.capabilities() == null) {
            ContractViolation.require(extensions.names().stream().noneMatch(JarContents::isClass),
                "The extensions JAR has classes, but no capability report was given. Pass the report that the "
                    + "extensions' build writes, target/capabilities.tsv, with --capabilities.");
            return;
        }
        ContractViolation.require(Files.isRegularFile(options.capabilities()),
            "The capability report " + options.capabilities() + " doesn't exist");
        ContractViolation.require(options.upstreamDirectory() == null || Files.isDirectory(options.upstreamDirectory()),
            "Upstream's source tree " + options.upstreamDirectory() + " doesn't exist");
        byte[] bytes = Files.readAllBytes(options.capabilities());
        String text = CapabilityReport.decode(bytes);
        String probed = CapabilityReport.probedSha256(text);
        String upstreamSha256 = CapabilityReport.sha256(Files.readAllBytes(options.upstreamJar()));
        ContractViolation.require(probed.equals(upstreamSha256),
            "The capability report was probed against another CoreProtect JAR: it names SHA-256 " + probed + ", but "
                + options.upstreamJar() + " has " + upstreamSha256
                + ". Build the extensions against the upstream JAR being transformed.");
        CapabilityReport capabilities = CapabilityReport.read(text, upstream, options.upstreamDirectory());
        ContractViolation.require(!capabilities.capabilities.isEmpty()
                || extensions.names().stream().noneMatch(JarContents::isClass),
            "The capability report lists no capabilities, but the extensions JAR has classes");
        report.capabilities.addAll(capabilities.capabilities);
        report.upstreamMemberCount = CapabilityReport.memberCount(capabilities.capabilities);

        ContractViolation.require(!output.contains(CapabilityReport.ENTRY), "LibreProtect's " + CapabilityReport.ENTRY
            + " would overwrite a file that upstream now ships, or that LibreProtect adds twice");
        output.put(CapabilityReport.ENTRY, bytes);
        report.injectedEntries.add(CapabilityReport.ENTRY);
    }

    private void checkRuntime(JarContents runtime) {
        ClassNode egress = readClass(runtime, EgressRules.EGRESS);
        for (String method : EgressRules.METHODS) {
            String name = method.substring(0, method.indexOf('('));
            String descriptor = EgressRules.staticDescriptor(method.substring(method.indexOf('(')));
            ContractViolation.require(hasPublicStatic(egress, name, descriptor),
                "Runtime is missing public static " + EgressRules.EGRESS + "." + name + descriptor);
        }
        ClassNode branding = readClass(runtime, BrandingRules.BRANDING);
        Map<String, String> brandingHooks = new LinkedHashMap<>();
        brandingHooks.put(BrandingRules.PHRASE_HOOK, BrandingRules.PHRASE_HOOK_DESCRIPTOR);
        brandingHooks.put(BrandingRules.SEND_MESSAGE, BrandingRules.SEND_MESSAGE_HOOK_DESCRIPTOR);
        BrandingRules.LOGGER_HOOKS.forEach((method, descriptor) ->
            brandingHooks.put(method.substring(0, method.indexOf('(')), descriptor));
        brandingHooks.forEach((name, descriptor) -> ContractViolation.require(hasPublicStatic(branding, name, descriptor),
            "Runtime is missing public static " + BrandingRules.BRANDING + "." + name + descriptor));

        ClassNode bootstrap = readClass(runtime, SubclassGenerator.BOOTSTRAP);
        for (String hook : List.of("init", "enabled")) {
            ContractViolation.require(hasPublicStatic(bootstrap, hook, SubclassGenerator.HOOK_DESCRIPTOR),
                "Runtime is missing public static " + SubclassGenerator.BOOTSTRAP + "." + hook
                    + SubclassGenerator.HOOK_DESCRIPTOR);
        }
    }

    /**
     * Every extension class that LibreProtect provides should still be
     * requested by upstream, by class name and by each of its public static
     * method names. Otherwise upstream has changed or dropped the extension
     * point, and LibreProtect's implementation would never run. That loses a
     * feature but not privacy, so it is recorded for the audit to report
     * rather than failing the build.
     */
    private void checkExtensionPoints(JarContents upstream, Set<String> upstreamClasses, JarContents runtime) {
        Map<String, ClassScan> upstreamScans = new LinkedHashMap<>();
        for (String name : upstream.names()) {
            if (JarContents.isClass(name) && !JarContents.isVersioned(name)
                && upstreamClasses.contains(JarContents.internalName(name))) {
                upstreamScans.put(name, ClassScan.of(upstream.get(name)));
            }
        }

        for (String name : runtime.names()) {
            if (!JarContents.isClass(name) || !name.startsWith(EXTENSIONS_PACKAGE) || name.contains("$")) {
                continue;
            }
            String internalName = JarContents.internalName(name);
            String className = internalName.replace('/', '.');
            List<ClassScan> callers = upstreamScans.values().stream()
                .filter(scan -> scan.strings.contains(className))
                .toList();
            if (callers.isEmpty()) {
                report.unrequestedExtensions.add(className);
                continue;
            }

            Set<String> callerStrings = new HashSet<>();
            callers.forEach(scan -> callerStrings.addAll(scan.strings));
            ClassNode extension = readClass(runtime, internalName);
            for (MethodNode method : extension.methods) {
                if ((method.access & Opcodes.ACC_PUBLIC) != 0 && (method.access & Opcodes.ACC_STATIC) != 0
                    && !method.name.startsWith("<") && !callerStrings.contains(method.name)) {
                    report.unrequestedExtensions.add(className + "#" + method.name);
                }
            }
            report.extensionPoints.add(new TransformReport.ExtensionPoint(className,
                callers.stream().map(scan -> scan.name.replace('/', '.')).toList()));
        }
    }

    private static ClassNode readClass(JarContents jar, String internalName) {
        byte[] bytes = jar.get(internalName + ".class");
        ContractViolation.require(bytes != null, "Missing class " + internalName);
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, ClassReader.SKIP_CODE);
        return node;
    }

    private static boolean hasPublicStatic(ClassNode node, String name, String descriptor) {
        for (MethodNode method : node.methods) {
            if (method.name.equals(name) && method.desc.equals(descriptor)
                && (method.access & Opcodes.ACC_PUBLIC) != 0 && (method.access & Opcodes.ACC_STATIC) != 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return upstream's description, introduced as LibreProtect's
     */
    private static String description(PluginYml pluginYml) {
        String upstream = pluginYml.getString("description");
        String introduction = "Privacy-hardened build of CoreProtect.";
        return upstream == null || upstream.isBlank() ? introduction : introduction + " " + upstream.strip();
    }

    private String buildProperties() {
        return "fork.version=" + options.version() + "\n"
            + "fork.commit=" + options.forkCommit() + "\n"
            + "upstream.ref=" + options.upstreamRef() + "\n"
            + "upstream.commit=" + options.upstreamCommit() + "\n"
            + "upstream.version=" + report.upstreamVersion + "\n";
    }
}
