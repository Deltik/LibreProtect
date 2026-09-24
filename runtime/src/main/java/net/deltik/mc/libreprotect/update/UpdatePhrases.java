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

package net.deltik.mc.libreprotect.update;

import net.deltik.mc.libreprotect.PrivacyConstants;

/**
 * Shows the release that LibreProtect found in CoreProtect's update
 * messages, in place of the synthetic version that CoreProtect was told (see
 * {@link UpdateCheck}), and links to the release's page.
 *
 * <p>Called by {@code Branding} for each phrase that CoreProtect renders. The
 * rendered text keeps its wording, so translations work as well. Like
 * {@code Branding}, this uses only the JDK and never throws.
 */
public final class UpdatePhrases {

    /** "Version {0} is now available." in the console, with the version */
    static final String VERSION_NOTICE = "VERSION_NOTICE";
    /** "Latest Version: {0}" in {@code /co status}, with {@code v} and the version */
    static final String LATEST_VERSION = "LATEST_VERSION";
    /** "Notice: {0} is now available." for operators, with {@code CoreProtect CE v} and the version */
    static final String UPDATE_NOTICE = "UPDATE_NOTICE";
    /** "Download: {0}" after either notice, with CoreProtect's download page */
    static final String LINK_DOWNLOAD = "LINK_DOWNLOAD";

    /** What CoreProtect puts before a version: in /co status, and in its notice to operators */
    private static final String[] VERSION_PREFIXES = {
        "v",
        PrivacyConstants.ORIGINAL_NAME + " CE v", PrivacyConstants.ORIGINAL_NAME + " v",
        PrivacyConstants.FORK_NAME + " CE v", PrivacyConstants.FORK_NAME + " v"
    };

    private UpdatePhrases() {
    }

    /**
     * @param phrase   the name of CoreProtect's phrase
     * @param params   the parameters it was rendered with
     * @param rendered CoreProtect's rendering
     * @return the text to use instead, or {@code null} to leave the phrase to
     *         the other branding rules, as when no release was reported
     */
    public static String rewrite(String phrase, String[] params, String rendered) {
        try {
            if (phrase == null || params == null || rendered == null) {
                return null;
            }
            switch (phrase) {
                case VERSION_NOTICE:
                case LATEST_VERSION:
                case UPDATE_NOTICE:
                    return replaceVersion(params, rendered);
                case LINK_DOWNLOAD:
                    return replaceLink(params, rendered);
                default:
                    return null;
            }
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String replaceVersion(String[] params, String rendered) {
        for (String param : params) {
            String replacement = versionParam(param);
            if (replacement != null && rendered.contains(param)) {
                return rendered.replace(param, replacement);
            }
        }
        return null;
    }

    /**
     * @return the parameter with a release in place of the synthetic version
     *         it was reported with, or {@code null} if it doesn't show one
     */
    private static String versionParam(String param) {
        if (param == null) {
            return null;
        }
        UpdateStatus.Known known = UpdateStatus.reported(param);
        if (known != null) {
            return known.version();
        }
        for (String prefix : VERSION_PREFIXES) {
            known = param.startsWith(prefix) ? UpdateStatus.reported(param.substring(prefix.length())) : null;
            if (known != null) {
                return (prefix.equals("v") ? "v" : PrivacyConstants.FORK_NAME + " v") + known.version();
            }
        }
        return null;
    }

    /**
     * Replace CoreProtect's download page with the page of the release
     * reported last, keeping the label, which may be translated. CoreProtect
     * only shows this link with an update notice, which is about a reported
     * release once LibreProtect has reported one.
     */
    private static String replaceLink(String[] params, String rendered) {
        UpdateStatus.Known known = UpdateStatus.lastReported();
        if (known == null) {
            return null;
        }
        for (String param : params) {
            if (param != null && !param.isEmpty() && !isColor(param) && rendered.contains(param)) {
                return rendered.replace(param, known.displayUrl());
            }
        }
        return null;
    }

    /** CoreProtect passes a color code as a parameter to color the text after the phrase's colon */
    private static boolean isColor(String param) {
        return param.length() == 2 && param.charAt(0) == '§';
    }
}
