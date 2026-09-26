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

import net.deltik.mc.libreprotect.transformer.AuditReport.Severity;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Looks for upstream changes that LibreProtect can't neutralize by rewriting,
 * or that deserve a human look before a release.
 *
 * <ul>
 *   <li><b>FAIL</b>: network access that bypasses {@code Egress} (sockets,
 *       HTTP clients, JNDI, RMI), loading code at run time, native code,
 *       launching processes, replacing JVM-wide network or output state, and
 *       reflection that reaches network APIs. The build fails unless
 *       {@code audit/baseline.json} allows that exact rule at that exact
 *       site.</li>
 *   <li><b>REVIEW</b>: new hosts, DNS lookups, dynamic class loading, new
 *       closed-source extension points, new reads of a plugin's version or
 *       of plugin.yml, signs of fork detection or obfuscation, changes to
 *       upstream's dependencies, build, or license, and changes to how the
 *       extensions work with upstream: the strategies in the capability
 *       report, and the code and documentation of upstream's that they rely
 *       on. Development builds still ship; releases wait for approval.</li>
 * </ul>
 *
 * <p>FAIL rules cover upstream's own code and bundled libraries. The rest only
 * cover upstream's own code, because libraries such as HikariCP reflect and
 * load classes routinely. Libraries exempt from egress rewriting, such as
 * database drivers, are only inventoried.
 */
final class Audit {

    static final String RULE_NETWORK = "network-api";
    static final String RULE_INTERNAL = "jdk-internal-api";
    static final String RULE_DYNAMIC_CODE = "dynamic-code";
    static final String RULE_NATIVE = "native-code";
    static final String RULE_PROCESS = "process";
    static final String RULE_GLOBAL_STATE = "global-state";
    static final String RULE_REFLECTION_NETWORK = "reflection-network";
    static final String RULE_SYSTEM_PROPERTY = "system-property";
    static final String RULE_DNS = "dns-lookup";
    static final String RULE_DYNAMIC_CLASS = "dynamic-class-loading";
    static final String RULE_SELF_INSPECTION = "self-inspection";
    static final String RULE_FORK_DETECTION = "fork-detection";
    static final String RULE_OBFUSCATION = "obfuscation";
    static final String RULE_CUSTOM_BOOTSTRAP = "custom-bootstrap";
    static final String RULE_CAPABILITY = "capability-change";

    private static final Set<String> NETWORK_CLASSES = Set.of(
        "java/net/Socket", "java/net/ServerSocket", "java/net/DatagramSocket", "java/net/MulticastSocket",
        "javax/net/SocketFactory", "javax/net/ServerSocketFactory",
        "javax/net/ssl/SSLSocketFactory", "javax/net/ssl/SSLServerSocketFactory",
        "javax/net/ssl/SSLSocket", "javax/net/ssl/SSLServerSocket",
        "java/nio/channels/SocketChannel", "java/nio/channels/ServerSocketChannel",
        "java/nio/channels/DatagramChannel", "java/nio/channels/AsynchronousSocketChannel",
        "java/nio/channels/AsynchronousServerSocketChannel", "java/nio/channels/spi/SelectorProvider");
    private static final List<String> NETWORK_PACKAGES = List.of(
        "java/net/http/", "jdk/internal/net/", "com/sun/net/httpserver/",
        "javax/naming/", "java/rmi/", "javax/management/remote/");
    private static final List<String> INTERNAL_PACKAGES = List.of("sun/", "jdk/internal/");
    private static final Set<String> DYNAMIC_CODE_CLASSES = Set.of(
        "java/net/URLClassLoader", "javax/tools/ToolProvider", "java/beans/XMLDecoder");
    private static final List<String> DYNAMIC_CODE_PACKAGES = List.of(
        "java/lang/instrument/", "com/sun/tools/attach/", "javax/script/");
    private static final Set<String> DEFINE_CLASS_METHODS = Set.of(
        "defineClass", "defineHiddenClass", "defineHiddenClassWithClassData");
    private static final List<String> NATIVE_PACKAGES = List.of("java/lang/foreign/", "com/sun/jna/");
    private static final Set<String> NATIVE_METHODS = Set.of(
        "java/lang/System.load", "java/lang/System.loadLibrary",
        "java/lang/Runtime.load", "java/lang/Runtime.loadLibrary");
    private static final Set<String> PROCESS_METHODS = Set.of(
        "java/lang/ProcessBuilder.<init>", "java/lang/Runtime.exec");
    private static final Set<String> GLOBAL_STATE_METHODS = Set.of(
        "java/net/URL.setURLStreamHandlerFactory", "java/net/URLConnection.setContentHandlerFactory",
        "java/net/URLConnection.setFileNameMap", "java/net/ProxySelector.setDefault",
        "java/net/Authenticator.setDefault", "java/net/CookieHandler.setDefault", "java/net/ResponseCache.setDefault",
        "javax/net/ssl/HttpsURLConnection.setDefaultSSLSocketFactory",
        "javax/net/ssl/HttpsURLConnection.setDefaultHostnameVerifier", "javax/net/ssl/SSLContext.setDefault",
        "java/security/Security.addProvider", "java/security/Security.insertProviderAt",
        "java/security/Security.setProperty", "java/lang/Thread.setDefaultUncaughtExceptionHandler",
        "java/lang/System.setOut", "java/lang/System.setErr", "java/lang/System.setIn",
        "java/lang/System.setSecurityManager");
    private static final Set<String> SYSTEM_PROPERTY_METHODS = Set.of(
        "java/lang/System.setProperty", "java/lang/System.setProperties", "java/lang/System.clearProperty");
    private static final Set<String> DNS_METHODS = Set.of(
        "java/net/InetAddress.getByName", "java/net/InetAddress.getAllByName", "java/net/InetAddress.getLocalHost",
        "java/net/InetAddress.getHostName", "java/net/InetAddress.getCanonicalHostName",
        "java/net/URL.equals", "java/net/URL.hashCode", "java/net/URL.sameFile");
    private static final Set<String> CLASS_BY_NAME_METHODS = Set.of(
        "java/lang/Class.forName", "java/lang/ClassLoader.loadClass");
    private static final Set<String> REFLECTIVE_LOOKUP_METHODS = Set.of(
        "java/lang/Class.getMethod", "java/lang/Class.getDeclaredMethod", "java/lang/Class.getField",
        "java/lang/Class.getDeclaredField", "java/lang/Class.getConstructor", "java/lang/Class.getDeclaredConstructor",
        "java/lang/invoke/MethodHandles$Lookup.findVirtual", "java/lang/invoke/MethodHandles$Lookup.findStatic",
        "java/lang/invoke/MethodHandles$Lookup.findSpecial", "java/lang/invoke/MethodHandles$Lookup.findConstructor");
    private static final Set<String> SELF_INSPECTION_METHODS = Set.of(
        "java/lang/Class.getProtectionDomain", "java/security/ProtectionDomain.getCodeSource",
        "org/bukkit/plugin/PluginDescriptionFile.getMain");
    /**
     * Reads of a plugin's version, or of names that end in it. CoreProtect
     * compares its own with others only through {@code getPluginVersion()},
     * which reads upstream's version after the transformation; a new read may
     * compare LibreProtect's instead. So may code that reads plugin.yml
     * itself, which {@link #PLUGIN_YML} finds.
     */
    private static final Set<String> VERSION_READ_METHODS = Set.of(
        "org/bukkit/plugin/PluginDescriptionFile.getVersion",
        "org/bukkit/plugin/PluginDescriptionFile.getFullName",
        "io/papermc/paper/plugin/configuration/PluginMeta.getVersion",
        "io/papermc/paper/plugin/configuration/PluginMeta.getDisplayName");
    /** In a string constant, a sign that the method reads plugin.yml, and perhaps the version in it */
    private static final String PLUGIN_YML = "plugin.yml";
    private static final Set<String> STANDARD_BOOTSTRAPS = Set.of(
        "java/lang/invoke/LambdaMetafactory", "java/lang/invoke/StringConcatFactory",
        "java/lang/runtime/ObjectMethods", "java/lang/runtime/SwitchBootstraps", "java/lang/invoke/ConstantBootstraps");
    private static final List<String> NETWORK_CLASS_NAME_PREFIXES = List.of(
        "java.net.", "javax.net.", "sun.", "jdk.internal.", "com.sun.net.", "java.nio.channels.");
    private static final Set<String> EGRESS_METHOD_NAMES = Set.of("openConnection", "openStream", "getContent");

    static final String EXTENSIONS_PREFIX = "net.coreprotect.utility.extensions.";
    private static final List<String> FORK_KEYWORDS = List.of("libreprotect", "deltik");
    private static final Pattern URL_HOST = Pattern.compile("(?i)\\b(?:https?|wss?|ftp)://([a-z0-9.-]+)");
    private static final Pattern ENCODED_BLOB = Pattern.compile("[A-Za-z0-9+/=_-]{200,}");

    private final JarContents jar;
    private final Map<String, Origin> origins;
    private final TransformReport transformReport;
    private final Path upstreamDirectory;
    private final AuditBaseline baseline;
    private final AuditReport report = new AuditReport();
    private final AuditBaseline observed = new AuditBaseline();

    /**
     * @param jar upstream's JAR, before the transformation, so that LibreProtect's own changes don't count as
     *            upstream's
     * @param origins origin of each class entry in the JAR that came from upstream
     * @param transformReport what the transformer did
     * @param upstreamDirectory upstream's source checkout, for the pom and LICENSE
     * @param baseline the reviewed state, or an empty baseline to review everything
     */
    Audit(JarContents jar, Map<String, Origin> origins, TransformReport transformReport, Path upstreamDirectory,
          AuditBaseline baseline) {
        this.jar = jar;
        this.origins = origins;
        this.transformReport = transformReport;
        this.upstreamDirectory = upstreamDirectory;
        this.baseline = baseline;
    }

    AuditReport run() throws Exception {
        for (String extension : transformReport.unrequestedExtensions) {
            review("extension-not-requested", extension,
                "LibreProtect provides this, but upstream no longer loads it, so it will never run. "
                    + "Check upstream's net.coreprotect.utility.Extensions.");
        }

        for (Map.Entry<String, Origin> entry : origins.entrySet()) {
            Origin origin = entry.getValue();
            if (origin == Origin.EXEMPT_LIBRARY) {
                // An exempt library was reviewed as a whole, so inventory it as a whole
                observed.libraryPackages.add(exemptPrefixOf(entry.getKey()));
                continue;
            }
            if (origin == Origin.LIBRARY) {
                observed.libraryPackages.add(packageOf(entry.getKey()));
            }
            ClassNode node = new ClassNode();
            new ClassReader(jar.get(entry.getKey())).accept(node, ClassReader.SKIP_FRAMES);
            auditClass(node, origin == Origin.UPSTREAM);
        }

        observeBuild();
        compareInventories();

        // Carry the reviewed decisions over, so the observed file is a baseline of its own. It accepts only this
        // upstream line's capabilities, so accepting it means adding them to those the baseline accepts
        // for the other line
        observed.comment = baseline.comment;
        observed.allow = baseline.allow;
        observed.egressExemptPrefixes = baseline.egressExemptPrefixes;
        observed.reviewedUpstreams = baseline.reviewedUpstreams;
        report.observed = observed;
        return report;
    }

    private void auditClass(ClassNode node, boolean upstreamAuthored) {
        if (upstreamAuthored) {
            String simpleName = node.name.substring(node.name.lastIndexOf('/') + 1);
            int nested = simpleName.indexOf('$');
            if (nested > 0) {
                simpleName = simpleName.substring(0, nested);
            }
            if (simpleName.length() <= 2 && simpleName.equals(simpleName.toLowerCase(Locale.ROOT))) {
                review(RULE_OBFUSCATION, node.name, "class name '" + simpleName + "' looks obfuscated");
            }
        }

        for (MethodNode method : node.methods) {
            String site = node.name + "#" + method.name + method.desc;
            Set<String> strings = new HashSet<>();
            Set<String> classLiterals = new HashSet<>();
            boolean reflectiveLookup = false;

            for (AbstractInsnNode instruction : method.instructions) {
                if (instruction instanceof MethodInsnNode call) {
                    String member = call.owner + "." + call.name;
                    checkOwner(call.owner, site);
                    checkMember(call, member, site, upstreamAuthored);
                    if (upstreamAuthored && REFLECTIVE_LOOKUP_METHODS.contains(member)) {
                        reflectiveLookup = true;
                    }
                } else if (instruction instanceof FieldInsnNode field) {
                    checkOwner(field.owner, site);
                } else if (instruction instanceof TypeInsnNode type && type.getOpcode() == Opcodes.NEW) {
                    checkOwner(type.desc, site);
                } else if (instruction instanceof LdcInsnNode ldc) {
                    if (ldc.cst instanceof String string) {
                        strings.add(string);
                    } else if (ldc.cst instanceof Type type && type.getSort() == Type.OBJECT) {
                        classLiterals.add(type.getInternalName());
                    } else if (ldc.cst instanceof Handle handle) {
                        checkOwner(handle.getOwner(), site);
                        checkMember(handle, site, upstreamAuthored);
                    }
                } else if (instruction instanceof InvokeDynamicInsnNode indy) {
                    if (upstreamAuthored && !STANDARD_BOOTSTRAPS.contains(indy.bsm.getOwner())) {
                        review(RULE_CUSTOM_BOOTSTRAP, site, "invokedynamic bootstrap " + indy.bsm.getOwner());
                    }
                    for (Object argument : indy.bsmArgs) {
                        if (argument instanceof String string) {
                            strings.add(string);
                        } else if (argument instanceof Handle handle) {
                            checkOwner(handle.getOwner(), site);
                            checkMember(handle, site, upstreamAuthored);
                        }
                    }
                }
            }

            if (upstreamAuthored) {
                if (reflectiveLookup && (classLiterals.stream().anyMatch(Audit::isNetworkClass)
                    || strings.stream().anyMatch(EGRESS_METHOD_NAMES::contains))) {
                    fail(RULE_REFLECTION_NETWORK, site, "reflective lookup of a network class or connection method");
                }
                auditStrings(strings, site);
            }
        }
    }

    private void checkOwner(String owner, String site) {
        if (owner.startsWith("[")) {
            return;
        }
        if (NETWORK_CLASSES.contains(owner) || startsWithAny(owner, NETWORK_PACKAGES)) {
            fail(RULE_NETWORK, site, "uses " + owner + ", which bypasses LibreProtect's Egress gate");
        } else if (startsWithAny(owner, INTERNAL_PACKAGES)) {
            fail(RULE_INTERNAL, site, "uses JDK-internal " + owner);
        } else if (DYNAMIC_CODE_CLASSES.contains(owner) || startsWithAny(owner, DYNAMIC_CODE_PACKAGES)) {
            fail(RULE_DYNAMIC_CODE, site, "uses " + owner + " to load or run code at run time");
        } else if (startsWithAny(owner, NATIVE_PACKAGES)) {
            fail(RULE_NATIVE, site, "uses native-code API " + owner);
        }
    }

    private void checkMember(MethodInsnNode call, String member, String site, boolean upstreamAuthored) {
        if (DEFINE_CLASS_METHODS.contains(call.name)
            && (call.owner.equals("java/lang/ClassLoader") || call.owner.equals("java/lang/invoke/MethodHandles$Lookup")
            || call.owner.equals("java/security/SecureClassLoader") || call.getOpcode() == Opcodes.INVOKESPECIAL
            || call.getOpcode() == Opcodes.INVOKEVIRTUAL)) {
            fail(RULE_DYNAMIC_CODE, site, "defines a class at run time via " + member);
        }
        checkMember(member, site, upstreamAuthored);

        if (upstreamAuthored && CLASS_BY_NAME_METHODS.contains(member)) {
            String name = constantArgument(call);
            if (name == null) {
                review(RULE_DYNAMIC_CLASS, site, member + " with a class name computed at run time");
            } else if (startsWithAny(name, NETWORK_CLASS_NAME_PREFIXES)) {
                fail(RULE_REFLECTION_NETWORK, site, member + "(\"" + name + "\")");
            } else if (name.startsWith(EXTENSIONS_PREFIX)) {
                observed.extensionPoints.add(name);
            }
        }
        if (upstreamAuthored && member.equals("java/net/InetSocketAddress.<init>")
            && call.desc.equals("(Ljava/lang/String;I)V")) {
            review(RULE_DNS, site, "new InetSocketAddress(String, int) resolves the host name");
        }
    }

    private void checkMember(Handle handle, String site, boolean upstreamAuthored) {
        checkMember(handle.getOwner() + "." + handle.getName(), site, upstreamAuthored);
    }

    private void checkMember(String member, String site, boolean upstreamAuthored) {
        if (upstreamAuthored && VERSION_READ_METHODS.contains(member)) {
            observed.versionReads.add(site);
        }
        if (NATIVE_METHODS.contains(member)) {
            fail(RULE_NATIVE, site, "loads native code via " + member);
        } else if (PROCESS_METHODS.contains(member)) {
            fail(RULE_PROCESS, site, "starts a process via " + member);
        } else if (GLOBAL_STATE_METHODS.contains(member)) {
            fail(RULE_GLOBAL_STATE, site, "replaces JVM-wide state via " + member);
        } else if (upstreamAuthored && SYSTEM_PROPERTY_METHODS.contains(member)) {
            review(RULE_SYSTEM_PROPERTY, site, "changes system properties via " + member);
        } else if (upstreamAuthored && DNS_METHODS.contains(member)) {
            review(RULE_DNS, site, member + " can resolve host names");
        } else if (upstreamAuthored && SELF_INSPECTION_METHODS.contains(member)) {
            review(RULE_SELF_INSPECTION, site, "inspects its own code source or plugin description via " + member);
        }
    }

    /**
     * @return the string constant passed as the last argument, if the
     *         instruction before the call loads one
     */
    private static String constantArgument(MethodInsnNode call) {
        if (Type.getArgumentTypes(call.desc).length != 1) {
            // Class.forName(String, boolean, ClassLoader): the name is loaded before the other arguments
            AbstractInsnNode previous = call.getPrevious();
            for (int skipped = 0; previous != null && skipped < 8; previous = previous.getPrevious(), skipped++) {
                if (previous instanceof LdcInsnNode ldc && ldc.cst instanceof String string) {
                    return string;
                }
            }
            return null;
        }
        AbstractInsnNode previous = call.getPrevious();
        while (previous != null && previous.getOpcode() < 0) {
            previous = previous.getPrevious();
        }
        return previous instanceof LdcInsnNode ldc && ldc.cst instanceof String string ? string : null;
    }

    private void auditStrings(Set<String> strings, String site) {
        for (String string : strings) {
            Matcher matcher = URL_HOST.matcher(string);
            while (matcher.find()) {
                observed.hosts.add(matcher.group(1).toLowerCase(Locale.ROOT));
            }
            String lower = string.toLowerCase(Locale.ROOT);
            for (String keyword : FORK_KEYWORDS) {
                if (lower.contains(keyword)) {
                    review(RULE_FORK_DETECTION, site, "string constant mentions '" + keyword + "': " + abbreviate(string));
                }
            }
            if (ENCODED_BLOB.matcher(string).find()) {
                review(RULE_OBFUSCATION, site, "long encoded-looking string constant: " + abbreviate(string));
            }
            if (string.startsWith(EXTENSIONS_PREFIX)) {
                observed.extensionPoints.add(string);
            }
            if (string.contains(PLUGIN_YML)) {
                observed.versionReads.add(site);
            }
        }
    }

    private void observeBuild() throws Exception {
        PomSummary pom = PomSummary.read(upstreamDirectory.resolve("pom.xml"));
        observed.dependencies.addAll(pom.dependencies);
        observed.repositories.addAll(pom.repositories);
        observed.buildPlugins.addAll(pom.buildPlugins);
        observed.profiles.addAll(pom.profiles);
        pom.dependencyVersions.forEach((dependency, version) ->
            report.add(Severity.INFO, "dependency-version", dependency, version));

        PluginYml pluginYml = new PluginYml(new String(jar.get(PluginYml.ENTRY), StandardCharsets.UTF_8));
        if (pluginYml.get("libraries") instanceof List<?> libraries) {
            libraries.forEach(library -> observed.pluginLibraries.add(String.valueOf(library)));
        }

        Path license = upstreamDirectory.resolve("LICENSE");
        if (Files.isRegularFile(license)) {
            observed.licenseSha256 = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(license)));
        }
    }

    private void compareInventories() {
        compare("new-host", "URL host in upstream code", baseline.hosts, observed.hosts);
        compare("new-extension-point", "closed-source extension class loaded by name",
            baseline.extensionPoints, observed.extensionPoints);
        compare("new-library-package", "package shaded into the JAR from a library",
            baseline.libraryPackages, observed.libraryPackages);
        compare("dependency-change", "Maven dependency (groupId:artifactId:scope)",
            baseline.dependencies, observed.dependencies);
        compare("repository-change", "Maven repository", baseline.repositories, observed.repositories);
        compare("build-plugin-change", "Maven build plugin", baseline.buildPlugins, observed.buildPlugins);
        compare("profile-change", "Maven profile", baseline.profiles, observed.profiles);
        compare("plugin-libraries-change", "library that plugin.yml asks the server to download",
            baseline.pluginLibraries, observed.pluginLibraries);
        compare("version-read", "method that reads a plugin's version, a name that ends in it, or plugin.yml itself; "
            + "if CoreProtect compares its own version there, it compares LibreProtect's, unless the transformer has it "
            + "read upstream's as in getPluginVersion()", baseline.versionReads, observed.versionReads);
        compareCapabilities();

        if (observed.licenseSha256 == null) {
            review("license-change", "LICENSE", "upstream no longer has a LICENSE file");
        } else if (!observed.licenseSha256.equals(baseline.licenseSha256)) {
            review("license-change", "LICENSE", "LICENSE changed (SHA-256 " + observed.licenseSha256
                + "); make sure LibreProtect may still be distributed");
        }
    }

    /**
     * The baseline accepts {@code key=value} lines, a key with a value for
     * each upstream line that LibreProtect builds, such as the locked release
     * and upstream's default branch. An observed value that the baseline
     * doesn't accept for its key needs a review: a new key, or a value other
     * than the accepted ones. So does a capability that the report no longer
     * has at all. Other accepted keys that this build doesn't observe, such
     * as the code that only another upstream line has, need nothing. Code,
     * documents, enums and optional members are keyed by the capability and
     * way that use them (see {@link CapabilityReport#observations}), so the
     * code of one line's way is never accepted under another's. Each finding
     * says which capabilities the key belongs to and why they care.
     */
    private void compareCapabilities() {
        Map<String, CapabilityReport.Observation> current = CapabilityReport.observations(transformReport.capabilities);
        current.forEach((key, observation) -> observed.capabilities.add(key + "=" + observation.value()));

        Map<String, List<String>> accepted = new TreeMap<>();
        for (String entry : baseline.capabilities == null ? Set.<String>of() : baseline.capabilities) {
            int equals = entry.indexOf('=');
            accepted.computeIfAbsent(equals < 0 ? entry : entry.substring(0, equals), key -> new ArrayList<>())
                .add(equals < 0 ? "" : entry.substring(equals + 1));
        }

        current.forEach((key, observation) -> {
            List<String> values = accepted.get(key);
            String context = String.join("; ", observation.contexts());
            String value = observation.value();
            if (values == null) {
                reviewCapability(key, value, "new: " + value + ". " + context);
            } else if (!values.contains(value)) {
                reviewCapability(key, value, "changed from " + String.join(" or ", values) + " to " + value + ". "
                    + context);
            }
        });
        accepted.forEach((key, values) -> {
            if (!current.containsKey(key) && key.startsWith(CapabilityReport.CAPABILITY_KEY)) {
                reviewCapability(key, "", "no longer in the capability report; was " + String.join(" or ", values));
            }
        });
    }

    /**
     * An allowance for a capability change names the {@code key=value} it
     * accepts, so that it doesn't accept the key's later values too.
     */
    private void reviewCapability(String key, String value, String detail) {
        add(Severity.REVIEW, RULE_CAPABILITY, key, detail, key + "=" + value);
    }

    private void compare(String rule, String what, Set<String> reviewed, Set<String> current) {
        for (String added : new TreeSet<>(current)) {
            if (!reviewed.contains(added)) {
                review(rule, added, "new " + what);
            }
        }
        for (String removed : reviewed) {
            if (!current.contains(removed)) {
                report.add(Severity.INFO, rule, removed, "no longer present: " + what);
            }
        }
    }

    private void fail(String rule, String site, String detail) {
        add(Severity.FAIL, rule, site, detail);
    }

    private void review(String rule, String site, String detail) {
        add(Severity.REVIEW, rule, site, detail);
    }

    private void add(Severity severity, String rule, String site, String detail) {
        add(severity, rule, site, detail, site);
    }

    /**
     * @param allowedSite what an allowance must name as its site to accept the finding
     */
    private void add(Severity severity, String rule, String site, String detail, String allowedSite) {
        boolean duplicate = report.findings.stream().anyMatch(finding ->
            finding.rule().equals(rule) && finding.site().equals(site) && finding.detail().equals(detail));
        if (duplicate) {
            return;
        }
        for (AuditBaseline.Allowance allowance : baseline.allow) {
            boolean siteMatches = allowance.site.endsWith("*")
                ? allowedSite.startsWith(allowance.site.substring(0, allowance.site.length() - 1))
                : allowedSite.equals(allowance.site);
            if (rule.equals(allowance.rule) && siteMatches) {
                report.add(Severity.INFO, rule, site, detail + " (allowed: " + allowance.reason + ")");
                return;
            }
        }
        report.add(severity, rule, site, detail);
    }

    private static boolean isNetworkClass(String internalName) {
        return NETWORK_CLASSES.contains(internalName) || internalName.equals("java/net/URL")
            || startsWithAny(internalName, NETWORK_PACKAGES);
    }

    private static boolean startsWithAny(String value, List<String> prefixes) {
        for (String prefix : prefixes) {
            if (value.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private String exemptPrefixOf(String entry) {
        String internalName = JarContents.internalName(entry);
        for (String prefix : baseline.egressExemptPrefixes) {
            if (internalName.startsWith(prefix)) {
                return prefix;
            }
        }
        return packageOf(entry);
    }

    private static String packageOf(String entry) {
        String internalName = JarContents.internalName(entry);
        int slash = internalName.lastIndexOf('/');
        return slash < 0 ? "" : internalName.substring(0, slash + 1);
    }

    private static String abbreviate(String value) {
        return value.length() <= 80 ? value : value.substring(0, 77) + "...";
    }
}
