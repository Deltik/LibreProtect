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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The parts of upstream's {@code pom.xml} that decide what code ends up in
 * the JAR or runs during the build: dependencies, repositories, build plugins
 * and profiles. Versions are kept apart, so routine version bumps don't need
 * a review.
 */
final class PomSummary {

    final TreeSet<String> dependencies = new TreeSet<>();
    final TreeMap<String, String> dependencyVersions = new TreeMap<>();
    final TreeSet<String> repositories = new TreeSet<>();
    final TreeSet<String> buildPlugins = new TreeSet<>();
    final TreeSet<String> profiles = new TreeSet<>();

    static PomSummary read(Path pom) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // The pom is untrusted input: no DTDs, no external entities
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        // Report errors only through the exception, not also on stderr
        builder.setErrorHandler(new DefaultHandler());
        Document document = builder.parse(pom.toFile());

        PomSummary summary = new PomSummary();
        Element project = document.getDocumentElement();
        summary.readSection(project, "");
        for (Element profile : children(child(project, "profiles"), "profile")) {
            String id = text(child(profile, "id"));
            summary.profiles.add(id);
            summary.readSection(profile, "profile " + id + ": ");
        }
        return summary;
    }

    private void readSection(Element section, String prefix) {
        for (Element dependency : children(child(section, "dependencies"), "dependency")) {
            String scope = text(child(dependency, "scope"));
            String coordinates = text(child(dependency, "groupId")) + ":" + text(child(dependency, "artifactId"));
            dependencies.add(prefix + coordinates + ":" + (scope.isEmpty() ? "compile" : scope));
            dependencyVersions.put(prefix + coordinates, text(child(dependency, "version")));
        }
        for (String container : List.of("repositories", "pluginRepositories")) {
            for (Element repository : children(child(section, container), null)) {
                repositories.add(prefix + text(child(repository, "url")));
            }
        }
        for (Element plugin : children(child(child(section, "build"), "plugins"), "plugin")) {
            String groupId = text(child(plugin, "groupId"));
            buildPlugins.add(prefix + (groupId.isEmpty() ? "org.apache.maven.plugins" : groupId)
                + ":" + text(child(plugin, "artifactId")));
        }
    }

    private static Element child(Element parent, String name) {
        if (parent == null) {
            return null;
        }
        for (Node node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element element && element.getTagName().equals(name)) {
                return element;
            }
        }
        return null;
    }

    private static List<Element> children(Element parent, String name) {
        List<Element> children = new ArrayList<>();
        if (parent == null) {
            return children;
        }
        for (Node node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element element && (name == null || element.getTagName().equals(name))) {
                children.add(element);
            }
        }
        return children;
    }

    private static String text(Element element) {
        return element == null ? "" : element.getTextContent().trim();
    }
}
