/*
 * Osprey - a browser extension that protects you from malicious websites.
 * Copyright (C) 2025 Foulest (https://github.com/Foulest)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
"use strict";

let reportedByText;

// Use a global singleton pattern to ensure we don't duplicate resources
window.WarningSingleton = window.WarningSingleton || (() => {

    // Browser API compatibility between Chrome and Firefox
    const browserAPI = typeof browser === 'undefined' ? chrome : browser;

    /**
     * Initialize the popup or refresh if already initialized.
     */
    function initialize() {
        // Extracts the threat code from the current page URL
        const pageUrl = window.document.URL;
        const result = UrlHelpers.extractResult(pageUrl);

        // Sets the reason text based on the result
        if (!result) {
            console.warn("No result found in the URL.");
            return;
        }

        // Cache for DOM elements
        const domElements = Object.fromEntries(
            ["reason", "url", "reportedBy", "reportSite", "allowSite", "homepageButton", "continueButton"]
                .map(id => [id, document.getElementById(id)])
        );

        domElements.reason.innerText = result;

        // Extracts the blocked URL from the current page URL
        const blockedUrl = UrlHelpers.extractBlockedUrl(pageUrl);

        // Encodes the URLs for safe use in other contexts
        const encodedBlockedUrl = encodeURIComponent(blockedUrl);
        const encodedResult = encodeURIComponent(result);

        // Sets the URL text to the current page URL
        domElements.url.innerText = blockedUrl;

        // Gets the origin information
        const origin = UrlHelpers.extractOrigin(pageUrl);
        const originInt = parseInt(origin);
        const systemName = ProtectionResult.ResultOriginNames[originInt];

        // Sets the reported by text
        domElements.reportedBy.innerText = systemName || "Unknown";
        reportedByText = domElements.reportedBy.innerText;

        // Listens for PONG messages to update the reported by count
        browserAPI.runtime.onMessage.addListener(message => {
            if (message.messageType === Messages.MessageType.BLOCKED_COUNTER_PONG && message.count > 0) {
                domElements.reportedBy.innerText = `${reportedByText} (and ${message.count} others)`;

                // Make the innerText hoverable and set the hover text
                const wrappedTitle = wrapSystemNamesText(`Also reported by: ${message.systems.join(', ')}`);
                domElements.reportedBy.title = `${wrappedTitle}`;
            }
        });

        // Sends a PING message to get the count of reported sites
        browserAPI.runtime.sendMessage({
            messageType: Messages.MessageType.BLOCKED_COUNTER_PING
        }).catch(() => {
        });

        /**
         * Gets the report URL lazily when needed.
         *
         * @returns {URL|null} - The report URL.
         */
        function getReportUrl() {
            switch (originInt) {
                case ProtectionResult.ResultOrigin.ADGUARD_SECURITY:
                    return new URL("mailto:support@adguard.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20AdGuard%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResult +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.foulest.net");

                case ProtectionResult.ResultOrigin.ADGUARD_FAMILY:
                    return new URL("mailto:support@adguard.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20AdGuard%20Family%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResult +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.foulest.net");

                case ProtectionResult.ResultOrigin.ALPHAMOUNTAIN:
                    return new URL("https://alphamountain.freshdesk.com/support/tickets/new");

                case ProtectionResult.ResultOrigin.CONTROL_D_SECURITY:
                    return new URL("mailto:help@controld.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20Control%20D%20P1%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResult +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.foulest.net");

                case ProtectionResult.ResultOrigin.CONTROL_D_FAMILY:
                    return new URL("mailto:help@controld.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20Control%20D%20Family%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResult +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.foulest.net");

                case ProtectionResult.ResultOrigin.PRECISIONSEC:
                    return new URL("mailto:info@precisionsec.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20PrecisionSec%20Web%20Protection" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResult +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.foulest.net");

                case ProtectionResult.ResultOrigin.G_DATA:
                    // Old URL: "https://submit.gdatasoftware.com/privacy"
                    // TODO: Needs verification of response from support team.
                    return new URL("mailto:support-us@gdata-software.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20G%20DATA%20Web%20Protection" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResult +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.foulest.net");

                case ProtectionResult.ResultOrigin.CERT_EE:
                    return new URL("mailto:ria@ria.ee?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20CERT-EE%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResult +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.foulest.net");

                case ProtectionResult.ResultOrigin.CLEANBROWSING_SECURITY:
                    return new URL("mailto:support@cleanbrowsing.org?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20CleanBrowsing%20Security%20Filter" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResult +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.foulest.net");

                case ProtectionResult.ResultOrigin.CLEANBROWSING_FAMILY:
                    return new URL("mailto:support@cleanbrowsing.org?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20CleanBrowsing%20Adult%20Filter" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResult +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.foulest.net");

                case ProtectionResult.ResultOrigin.CLOUDFLARE_SECURITY:
                case ProtectionResult.ResultOrigin.CLOUDFLARE_FAMILY:
                    return new URL("https://radar.cloudflare.com/domains/feedback/" + encodedBlockedUrl);

                case ProtectionResult.ResultOrigin.DNS0_SECURITY:
                case ProtectionResult.ResultOrigin.DNS0_FAMILY:
                    return new URL("https://www.dns0.eu/report");

                case ProtectionResult.ResultOrigin.DNS4EU_SECURITY:
                    // TODO: Needs verification of response from support team.
                    return new URL("mailto:contact@dns4.eu?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20DNS4EU%20Protective%20Resolution%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResult +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.foulest.net");

                case ProtectionResult.ResultOrigin.DNS4EU_FAMILY:
                    // TODO: Needs verification of response from support team.
                    return new URL("mailto:contact@dns4.eu?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20DNS4EU%20Protective%20Resolution%20with%20Child%20Protection%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResult +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.foulest.net");

                case ProtectionResult.ResultOrigin.SMARTSCREEN:
                    return new URL("https://feedback.smartscreen.microsoft.com/feedback.aspx?t=16&url=" + blockedUrl);

                case ProtectionResult.ResultOrigin.NORTON:
                    return new URL("https://safeweb.norton.com/report?url=" + encodedBlockedUrl);

                case ProtectionResult.ResultOrigin.QUAD9:
                    // Old URL: "https://quad9.net/support/contact"
                    // TODO: Needs verification of response from support team.
                    return new URL("mailto:support@quad9.net?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20Quad9%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResult +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.foulest.net");

                default:
                    return null;
            }
        }

        /**
         * Sends a message to the background script with the specified message type and additional data.
         *
         * @param messageType - The type of message to send.
         * @param additionalData - Additional data to include in the message.
         * @returns {Promise<void>} - A promise that resolves when the message is sent.
         */
        async function sendMessage(messageType, additionalData = {}) {
            try {
                // Creates the message object and converts URL objects to strings
                const message = {
                    messageType,
                    blockedUrl: blockedUrl instanceof URL ? blockedUrl.toString() : blockedUrl,
                    origin: origin instanceof URL ? origin.toString() : origin,
                    ...additionalData
                };

                // Converts URL objects to strings in additionalData
                for (const key in message) {
                    if (message[key] instanceof URL) {
                        message[key] = message[key].toString();
                    }
                }

                await browserAPI.runtime.sendMessage(message);
            } catch (error) {
                console.error(`Error sending message ${messageType}:`, error);
            }
        }

        // Extracts the blocked URL from the current page URL
        const continueUrl = UrlHelpers.extractContinueUrl(pageUrl);

        // Adds event listener to "Report this website as safe" button
        Settings.get(settings => {
            domElements.reportSite.addEventListener("click", async () => {
                if (!settings.hideReportButton) {
                    await sendMessage(Messages.MessageType.REPORT_SITE, {
                        reportUrl: getReportUrl()
                    });
                }
            });

            // Adds event listener to "Always ignore this website" button
            domElements.allowSite.addEventListener("click", async () => {
                if (!settings.hideContinueButtons) {
                    await sendMessage(Messages.MessageType.ALLOW_SITE, {
                        blockedUrl: blockedUrl,
                        continueUrl: continueUrl
                    });
                }
            });

            // Adds event listener to "Back to safety" button
            domElements.homepageButton.addEventListener("click", async () => {
                await sendMessage(Messages.MessageType.CONTINUE_TO_SAFETY, {
                    blockedUrl: blockedUrl
                });
            });

            // Adds event listener to "Continue anyway" button
            domElements.continueButton.addEventListener("click", async () => {
                if (!settings.hideContinueButtons) {
                    await sendMessage(Messages.MessageType.CONTINUE_TO_SITE, {
                        blockedUrl: blockedUrl,
                        continueUrl: continueUrl
                    });
                }
            });

            // Handles the hide continue buttons policy
            if (!settings.hideContinueButtons) {
                document.getElementById("allowSite").style.display = "";
                document.getElementById("continueButton").style.display = "";
            }

            // Handles the hide report button policy
            if (!settings.hideReportButton) {
                document.getElementById("reportSite").style.display = "";
                document.getElementById("reportBreakpoint").style.display = "";
            }

            // Handles the homepage button visibility
            document.getElementById("homepageButton").style.display = "";
        });
    }

    /**
     * Wraps system names text to fit within a specified maximum line length.
     *
     * @param text - The text to wrap, typically a comma-separated list of system names.
     * @returns {string} - The wrapped text, with each line not exceeding the specified maximum length.
     */
    function wrapSystemNamesText(text) {
        const parts = text.split(', ');
        const lines = [];
        let currentLine = '';

        const isFirefox = typeof browser !== 'undefined';
        let maxLineLength = isFirefox ? 110 : 100;

        for (const part of parts) {
            const nextSegment = currentLine ? `${currentLine}, ${part}` : part;

            if (nextSegment.length <= maxLineLength) {
                currentLine = nextSegment;
            } else {
                if (currentLine) {
                    lines.push(currentLine);
                }

                currentLine = part;
            }
        }

        if (currentLine) {
            lines.push(currentLine);
        }
        return lines.join('\n');
    }

    // Returns the public API
    return {
        initialize
    };
})();

// Initializes when the DOM is ready
document.addEventListener("DOMContentLoaded", () => {
    window.WarningSingleton.initialize();
});
