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

import net.deltik.mc.libreprotect.transformer.AuditReport.Resolution;
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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
 *       site. So does any change to upstream's license, since LibreProtect
 *       may no longer be allowed to distribute it, until the baseline accepts
 *       it.</li>
 *   <li><b>REVIEW</b>: new hosts, DNS lookups, dynamic class loading, new
 *       closed-source extension points, new reads of a plugin's version or
 *       of plugin.yml, signs of fork detection or obfuscation, changes to
 *       upstream's dependencies or build, and changes to how the extensions
 *       work with upstream: the strategies in the capability report, and the
 *       code and documentation of upstream's that they rely on. Development
 *       builds still ship; releases wait for approval.</li>
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
    static final String RULE_FINGERPRINT_TRUNCATED = "fingerprint-truncated";
    static final String RULE_LICENSE = "license-change";

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

    /**
     * A file name that may state a license or terms like one: a word such as
     * LICENSE, LICENSING, COPYING, NOTICE, EULA or TERMS at its start or
     * after a separator, as in LICENCE.md, COPYING3, MIT-LICENSE or
     * THIRD_PARTY_NOTICES.md
     */
    private static final Pattern LICENSE_FILE = Pattern.compile(
        "(?i)(?:.*[._\\- ])?(?:(?:un)?licen[cs]|copying|copyright|notice|patent|eula|legal|terms).*");
    /** A directory whose files state licenses, at any depth, such as the LICENSES/ of the REUSE specification */
    private static final Pattern LICENSE_DIRECTORY = Pattern.compile("(?i)licen[cs]es?");
    /** A file at upstream's root that states the license of the whole of upstream */
    private static final Pattern ROOT_LICENSE = Pattern.compile("(?i)(?:(?:un)?licen[cs]e|copying)(?:\\.[a-z0-9]+)?");
    /**
     * The years of a copyright notice, such as 2024, 2019-2026 or
     * 2021, 2024 after "Copyright", "(C)" or the copyright sign. Other
     * years, such as a license's change date, are part of its terms.
     */
    private static final Pattern COPYRIGHT_YEARS = Pattern.compile("(?i)((?:copyright|\\(c\\)|\\x{A9})"
        + "(?:\\s*(?:\\(c\\)|\\x{A9}))?[\\s:]*)(?:19|20)\\d\\d(?:\\s*[-\\x{2013},]\\s*(?:19|20)\\d\\d)*\\b");
    /** A Unicode escape that the Java compiler translates before it reads comments */
    private static final Pattern UNICODE_ESCAPE = Pattern.compile("(?<!\\\\)((?:\\\\\\\\)*)\\\\u+([0-9a-fA-F]{4})");
    static final String LICENSE_FILE_KEY = "file ";
    static final String POM_LICENSES_KEY = "pom licenses";
    static final String HEADER_KEY = "header";
    private static final String LICENSE_REVIEW = "makes sure that LibreProtect may still distribute CoreProtect under "
        + "the GPL, as section 4(c)(ii) of the Artistic License 2.0 allows";

    /**
     * A {@code key=value} of upstream's licensing that this build observed,
     * the site that a finding about it names, and what it is
     */
    private record LicenseObservation(String key, String value, String site, String description) {
        String entry() {
            return key + "=" + value;
        }
    }

    private final JarContents jar;
    private final Map<String, Origin> origins;
    private final TransformReport transformReport;
    private final Path upstreamDirectory;
    private final AuditBaseline baseline;
    private final AuditReport report = new AuditReport();
    private final AuditBaseline.Line observed = new AuditBaseline.Line();
    private final List<LicenseObservation> licenseObservations = new ArrayList<>();

    /**
     * @param jar upstream's JAR, before the transformation, so that LibreProtect's own changes don't count as
     *            upstream's
     * @param origins origin of each class entry in the JAR that came from upstream
     * @param transformReport what the transformer did
     * @param upstreamDirectory upstream's source checkout, for the pom and the licenses
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

        // Which build this is, so that accepting it records what a line's reviewed state is of
        observed.upstream.ref = transformReport.upstreamRef;
        observed.upstream.commit = transformReport.upstreamCommit;
        observed.upstream.jarSha256 = transformReport.upstreamSha256;
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
            report.add(Severity.INFO, "dependency-version", dependency, version, null));

        PluginYml pluginYml = new PluginYml(new String(jar.get(PluginYml.ENTRY), StandardCharsets.UTF_8));
        if (pluginYml.get("libraries") instanceof List<?> libraries) {
            libraries.forEach(library -> observed.pluginLibraries.add(String.valueOf(library)));
        }

        observeLicenses(pom);
    }

    /**
     * Records upstream's licensing: each license-like file in its source
     * tree, the licenses that its pom declares, and each distinct header of
     * a Java file. The whole tree counts, since the source archive of each
     * build ships all of it, except Git's files and the build's output.
     */
    private void observeLicenses(PomSummary pom) throws IOException {
        // Sorted, so that the findings come in the same order on any file system
        Map<String, String> licenseFiles = new TreeMap<>();
        Map<String, TreeSet<String>> headerPaths = new TreeMap<>();
        Map<String, String> headerTexts = new TreeMap<>();
        Path realRoot = upstreamDirectory.toRealPath();
        Files.walkFileTree(upstreamDirectory, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes) {
                String name = String.valueOf(directory.getFileName());
                boolean buildOutput = name.equals("target") && upstreamDirectory.equals(directory.getParent());
                return name.equals(".git") || buildOutput ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                Path relative = upstreamDirectory.relativize(file);
                String path = relative.toString().replace(file.getFileSystem().getSeparator(), "/");
                String name = file.getFileName().toString();
                if (name.endsWith(".java")) {
                    if (attributes.isRegularFile()) {
                        String header = header(new String(Files.readAllBytes(file), StandardCharsets.UTF_8));
                        if (!header.isEmpty()) {
                            String hash = sha256(header.getBytes(StandardCharsets.UTF_8));
                            headerPaths.computeIfAbsent(hash, key -> new TreeSet<>()).add(path);
                            headerTexts.put(hash, header);
                        }
                    }
                } else if (LICENSE_FILE.matcher(name).matches() || inLicenseDirectory(relative)) {
                    if (attributes.isSymbolicLink()) {
                        licenseFiles.put(path, symlink(file, realRoot));
                    } else if (attributes.isRegularFile()) {
                        licenseFiles.put(path, sha256(Files.readAllBytes(file)));
                    }
                }
                return FileVisitResult.CONTINUE;
            }
        });

        licenseFiles.forEach((path, value) -> licenseObservations.add(
            new LicenseObservation(LICENSE_FILE_KEY + path, value, path, "license file")));
        String pomLicenses = pom.licenses.isEmpty() ? "absent" : String.join("; ", pom.licenses);
        licenseObservations.add(new LicenseObservation(POM_LICENSES_KEY, pomLicenses, "pom.xml",
            "licenses that the pom declares"));
        headerPaths.forEach((hash, paths) -> licenseObservations.add(new LicenseObservation(HEADER_KEY, hash,
            paths.getFirst(), "new header in " + paths.size() + " Java file"
            + (paths.size() == 1 ? "" : "s, such as this one") + ", which may state a license: "
            + headerTexts.get(hash))));
        licenseObservations.forEach(observation -> observed.licenses.add(observation.entry()));
    }

    private static boolean inLicenseDirectory(Path relative) {
        for (Path directory = relative.getParent(); directory != null; directory = directory.getParent()) {
            if (LICENSE_DIRECTORY.matcher(directory.getFileName().toString()).matches()) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return where a license-like symbolic link points, and the SHA-256 of
     *         what it points to, if that's a file in upstream's tree, since
     *         the link states that file's license
     */
    private static String symlink(Path link, Path realRoot) throws IOException {
        String value = "symlink to " + Files.readSymbolicLink(link);
        try {
            Path target = link.toRealPath();
            return target.startsWith(realRoot) && Files.isRegularFile(target)
                ? value + ", " + sha256(Files.readAllBytes(target)) : value + ", not a file in upstream's tree";
        } catch (NoSuchFileException e) {
            return value + ", which doesn't exist";
        }
    }

    /**
     * @return the header of a Java source file: its comments before the
     *         package statement and among the package and import statements,
     *         or before the first code if it has neither, without their
     *         comment markers, with whitespace collapsed and the years of
     *         copyright notices replaced by {@code #}, so that they can
     *         change; or an empty string if it has no such comments. The
     *         comments after the last import, which document the class that
     *         follows, aren't part of it.
     */
    static String header(String javaSource) {
        String source = UNICODE_ESCAPE.matcher(javaSource).replaceAll(escape -> Matcher.quoteReplacement(
            escape.group(1) + (char) Integer.parseInt(escape.group(2), 16)));
        StringBuilder header = new StringBuilder();
        StringBuilder pending = new StringBuilder();
        boolean statements = false;
        int position = 0;
        while (true) {
            while (position < source.length()
                && (Character.isWhitespace(source.charAt(position)) || source.charAt(position) == '\uFEFF')) {
                position++;
            }
            if (source.startsWith("//", position)) {
                int end = position + 2;
                while (end < source.length() && source.charAt(end) != '\n' && source.charAt(end) != '\r') {
                    end++;
                }
                pending.append(source, position + 2, end).append('\n');
                position = end;
            } else if (source.startsWith("/*", position)) {
                int end = source.indexOf("*/", position + 2);
                end = end < 0 ? source.length() : end;
                pending.append(source, position + 2, end).append('\n');
                position = Math.min(source.length(), end + 2);
            } else if (startsWithKeyword(source, position, "package") || startsWithKeyword(source, position, "import")) {
                int end = source.indexOf(';', position);
                if (end < 0) {
                    break;
                }
                header.append(pending);
                pending.setLength(0);
                statements = true;
                position = end + 1;
            } else {
                break;
            }
        }
        if (!statements) {
            header.append(pending);
        }
        String withoutMarkers = header.toString().replaceAll("(?m)^[\\s*/]+|[\\s*/]+$", " ");
        return COPYRIGHT_YEARS.matcher(withoutMarkers).replaceAll("$1#").replaceAll("\\s+", " ").trim();
    }

    private static boolean startsWithKeyword(String source, int position, String keyword) {
        int end = position + keyword.length();
        return source.startsWith(keyword, position)
            && (end == source.length() || !Character.isJavaIdentifierPart(source.charAt(end)));
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Every Java platform supports SHA-256", e);
        }
    }

    /**
     * Compares what this build observed with what any of the baseline's
     * lines accepts: a line's reviewed state doesn't depend on which line
     * this build is of.
     */
    private void compareInventories() {
        compare("new-host", "URL host in upstream code", baseline.accepted(line -> line.hosts), observed.hosts);
        compare("new-extension-point", "closed-source extension class loaded by name",
            baseline.accepted(line -> line.extensionPoints), observed.extensionPoints);
        compare("new-library-package", "package shaded into the JAR from a library",
            baseline.accepted(line -> line.libraryPackages), observed.libraryPackages);
        compare("dependency-change", "Maven dependency (groupId:artifactId:scope)",
            baseline.accepted(line -> line.dependencies), observed.dependencies);
        compare("repository-change", "Maven repository", baseline.accepted(line -> line.repositories),
            observed.repositories);
        compare("build-plugin-change", "Maven build plugin", baseline.accepted(line -> line.buildPlugins),
            observed.buildPlugins);
        compare("profile-change", "Maven profile", baseline.accepted(line -> line.profiles), observed.profiles);
        compare("plugin-libraries-change", "library that plugin.yml asks the server to download",
            baseline.accepted(line -> line.pluginLibraries), observed.pluginLibraries);
        compare("version-read", "method that reads a plugin's version, a name that ends in it, or plugin.yml itself; "
            + "if CoreProtect compares its own version there, it compares LibreProtect's, unless the transformer has it "
            + "read upstream's as in getPluginVersion()", baseline.accepted(line -> line.versionReads),
            observed.versionReads);
        compareCapabilities();
        compareLicenses();
    }

    /**
     * @param values the values that the baseline's lines accept for a key, with the lines that accept each
     * @return them for a finding, such as {@code abc (release) or def (development)}
     */
    private static String reviewed(Map<String, List<String>> values) {
        List<String> described = new ArrayList<>();
        values.forEach((value, lines) -> described.add(value + " (" + String.join(", ", lines) + ")"));
        return String.join(" or ", described);
    }

    /**
     * Fails on any {@code key=value} of upstream's licensing that no line of
     * the baseline accepts, and on an upstream without a license file, such
     * as LICENSE or COPYING, at its root. As with capabilities, a key is
     * accepted with the value of any line, and an accepted key that this
     * build doesn't observe needs nothing: another line may have it, and a
     * license file that is gone adds no terms. The root's license is the
     * exception.
     */
    private void compareLicenses() {
        Set<String> accepted = baseline.accepted(line -> line.licenses);
        for (LicenseObservation observation : licenseObservations) {
            if (accepted.contains(observation.entry())) {
                continue;
            }
            Map<String, List<String>> reviewed = baseline.acceptedValues(line -> line.licenses, observation.key());
            String change;
            if (observation.key().equals(HEADER_KEY)) {
                change = observation.description();
            } else if (reviewed.isEmpty()) {
                change = "new " + observation.description() + ": " + observation.value();
            } else {
                change = observation.description() + " changed from " + reviewed(reviewed) + " to "
                    + observation.value();
            }
            add(Severity.FAIL, RULE_LICENSE, observation.site(), change + ". Nothing is built until a maintainer "
                + LICENSE_REVIEW + ", and accepts \"" + observation.entry() + "\" into audit/baseline.json with "
                + "scripts/lp accept --licenses",
                observation.entry(), Resolution.ACCEPT);
        }

        boolean rootLicense = licenseObservations.stream().anyMatch(observation ->
            observation.key().startsWith(LICENSE_FILE_KEY) && ROOT_LICENSE.matcher(observation.site()).matches());
        if (!rootLicense) {
            fail(RULE_LICENSE, "LICENSE", "upstream has no license file, such as LICENSE or COPYING, at its root, "
                + "so its code may no longer be licensed to anyone. Nothing is built until it has one again, or a "
                + "maintainer " + LICENSE_REVIEW + ", and allows this finding in audit/baseline.json");
        }
    }

    /**
     * Each line of the baseline accepts {@code key=value} lines, and a key is
     * accepted with the value of any line, such as the locked release's or
     * that of upstream's default branch. An observed value that no line
     * accepts for its key needs a review: a new key, or a value other than
     * the accepted ones. So does a capability that the report no longer has
     * at all. Other accepted keys that this build doesn't observe, such as
     * the code that only another upstream line has, need nothing. Code,
     * documents, enums and optional members are keyed by the capability and
     * way that use them (see {@link CapabilityReport#observations}), so the
     * code of one line's way is never accepted under another's. Each finding
     * says which lines accept which values, which capabilities the key
     * belongs to, and why they care.
     */
    private void compareCapabilities() {
        Map<String, CapabilityReport.Observation> current = CapabilityReport.observations(transformReport.capabilities);
        current.forEach((key, observation) -> observed.capabilities.add(key + "=" + observation.value()));

        Set<String> accepted = baseline.accepted(line -> line.capabilities);
        current.forEach((key, observation) -> {
            String value = observation.value();
            if (accepted.contains(key + "=" + value)) {
                return;
            }
            Map<String, List<String>> values = baseline.acceptedValues(line -> line.capabilities, key);
            String context = String.join("; ", observation.contexts());
            if (values.isEmpty()) {
                reviewCapability(key, value, "new: " + value + ". " + context);
            } else {
                reviewCapability(key, value, "changed from " + reviewed(values) + " to " + value + ". " + context);
            }
        });
        // Capability IDs have no '=', so the key of a capability's entry ends at its first
        Set<String> gone = new TreeSet<>();
        for (String entry : accepted) {
            String key = entry.contains("=") ? entry.substring(0, entry.indexOf('=')) : entry;
            if (key.startsWith(CapabilityReport.CAPABILITY_KEY) && !current.containsKey(key)) {
                gone.add(key);
            }
        }
        for (String key : gone) {
            // The extensions' own change, which the capability report of every line's build shows
            reviewCapability(key, "", "no longer in the capability report; was "
                + reviewed(baseline.acceptedValues(line -> line.capabilities, key))
                + ". Accepting a build of each of those lines resolves it");
        }

        // A fingerprint that covers only part of what its method runs would miss a change to the rest
        Map<String, Set<String>> truncated = new TreeMap<>();
        for (TransformReport.Capability capability : transformReport.capabilities) {
            for (TransformReport.Reliance reliance : capability.relies()) {
                if (CodeFingerprint.truncated(reliance.fingerprint())) {
                    truncated.computeIfAbsent(reliance.member(), member -> new TreeSet<>()).add(capability.id());
                }
            }
        }
        truncated.forEach((member, ids) -> review(RULE_FINGERPRINT_TRUNCATED, member, "the fingerprint of this "
            + "method, which " + String.join(", ", ids) + " relies on, covers only the first "
            + CodeFingerprint.MAX_METHODS + " methods that it runs, so a change to the others goes unseen. Raise "
            + "CodeFingerprint.MAX_METHODS, or rely on less"));
    }

    /**
     * An allowance for a capability change names the {@code key=value} it
     * accepts, so that it doesn't accept the key's later values too.
     */
    private void reviewCapability(String key, String value, String detail) {
        add(Severity.REVIEW, RULE_CAPABILITY, key, detail, key + "=" + value, Resolution.ACCEPT);
    }

    private void compare(String rule, String what, Set<String> reviewed, Set<String> current) {
        for (String added : new TreeSet<>(current)) {
            if (!reviewed.contains(added)) {
                add(Severity.REVIEW, rule, added, "new " + what, added, Resolution.ACCEPT);
            }
        }
        for (String removed : reviewed) {
            if (!current.contains(removed)) {
                report.add(Severity.INFO, rule, removed, "no longer present: " + what, null);
            }
        }
    }

    private void fail(String rule, String site, String detail) {
        add(Severity.FAIL, rule, site, detail, site, Resolution.ALLOW);
    }

    private void review(String rule, String site, String detail) {
        add(Severity.REVIEW, rule, site, detail, site, Resolution.ALLOW);
    }

    /**
     * @param allowedSite what an allowance must name as its site to accept the finding
     * @param resolution  what resolves the finding if no allowance does
     */
    private void add(Severity severity, String rule, String site, String detail, String allowedSite,
                     Resolution resolution) {
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
                report.add(Severity.INFO, rule, site, detail + " (allowed: " + allowance.reason + ")", null);
                return;
            }
        }
        report.add(severity, rule, site, detail, resolution);
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
