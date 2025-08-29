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
// noinspection FunctionWithInconsistentReturnsJS
window.WarningSingleton = window.WarningSingleton || (() => {

    // Browser API compatibility between Chrome and Firefox
    const browserAPI = typeof browser === 'undefined' ? chrome : browser;

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

    /**
     * Initialize the popup or refresh if already initialized.
     */
    function initialize() {
        // Extracts the threat code from the current page URL
        const pageUrl = window.document.URL;
        const result = UrlHelpers.extractResult(pageUrl);

        // Checks if the result is valid
        if (!result) {
            console.warn("No result found in the URL.");
            return;
        }

        // Converts the result code to a human-readable string
        const resultText = ProtectionResult.ResultTypeName[result];
        const resultTextEN = ProtectionResult.ResultTypeNameEN[result];

        /**
         * Localizes the page by replacing text content with localized messages.
         */
        function localizePage() {
            // Sets the warning title text
            const warningTitle = document.getElementById('warningTitle');
            if (warningTitle) {
                warningTitle.textContent = LangUtil.WARNING_TITLE;
            }

            // Sets the recommendation text
            const recommendation = document.getElementById('recommendation');
            if (recommendation) {
                recommendation.textContent = LangUtil.RECOMMENDATION;
            }

            // Sets the details text
            const details = document.getElementById('details');
            if (details) {
                details.textContent = LangUtil.DETAILS;
            }

            // Sets the URL label text
            const urlLabel = document.getElementById('urlLabel');
            if (urlLabel) {
                urlLabel.textContent = LangUtil.URL_LABEL;
            }

            // Sets the reported by label text
            const reportedByLabel = document.getElementById('reportedByLabel');
            if (reportedByLabel) {
                reportedByLabel.textContent = LangUtil.REPORTED_BY_LABEL;
            }

            // Sets the reason label text
            const reasonLabel = document.getElementById('reasonLabel');
            if (reasonLabel) {
                reasonLabel.textContent = LangUtil.REASON_LABEL;
            }

            // Sets the report website button text
            const reportWebsite = document.getElementById('reportWebsite');
            if (reportWebsite) {
                reportWebsite.textContent = LangUtil.REPORT_WEBSITE;
            }

            // Sets the allow website button text
            const allowWebsite = document.getElementById('allowWebsite');
            if (allowWebsite) {
                allowWebsite.textContent = LangUtil.ALLOW_WEBSITE;
            }

            // Sets the back button text
            const backButton = document.getElementById('backButton');
            if (backButton) {
                backButton.textContent = LangUtil.BACK_BUTTON;
            }

            // Sets the continue button text
            const continueButton = document.getElementById('continueButton');
            if (continueButton) {
                continueButton.textContent = LangUtil.CONTINUE_BUTTON;
            }

            // Sets the document title text
            document.title = LangUtil.TITLE;

            // Sets the banner text
            const bannerText = document.querySelector('.bannerText');
            if (bannerText) {
                bannerText.textContent = LangUtil.BANNER_TEXT;
            }

            // Sets the alt text for the logo
            const logo = document.getElementById('logo');
            if (logo) {
                logo.alt = LangUtil.LOGO_ALT;
            }
        }

        // Localizes the page content
        localizePage();

        // Cache for DOM elements
        const domElements = Object.fromEntries(
            ["reason", "url", "reportedBy", "reportWebsite", "allowWebsite", "backButton", "continueButton"]
                .map(id => [id, document.getElementById(id)])
        );

        // Sets the reason text to the extracted result
        domElements.reason.innerText = resultText;

        // Extracts the blocked URL from the current page URL
        const blockedUrl = UrlHelpers.extractBlockedUrl(pageUrl);

        // Encodes the URLs for safe use in other contexts
        const encodedBlockedUrl = encodeURIComponent(blockedUrl);
        const encodedResultTextEN = encodeURIComponent(resultTextEN);

        // Sets the URL text to the current page URL
        domElements.url.innerText = blockedUrl;

        // Gets the origin information
        const origin = UrlHelpers.extractOrigin(pageUrl);
        const originInt = parseInt(origin);
        const systemName = ProtectionResult.FullName[originInt];

        // Sets the reported by text
        domElements.reportedBy.innerText = systemName || "Unknown";
        reportedByText = domElements.reportedBy.innerText;

        // Listens for PONG messages to update the reported by count
        browserAPI.runtime.onMessage.addListener(message => {
            if (message.messageType === Messages.BLOCKED_COUNTER_PONG && message.count > 0) {
                let othersText = LangUtil.REPORTED_BY_OTHERS;
                othersText = othersText.replace("___", message.count.toString());

                // Sets the reported by text with the count of other systems
                domElements.reportedBy.innerText = `${reportedByText} ${othersText}`;

                // Make the innerText hoverable and set the hover text
                const alsoReportedBy = LangUtil.REPORTED_BY_ALSO;
                const wrappedTitle = wrapSystemNamesText(`${alsoReportedBy}${message.systems.join(', ')}`);
                domElements.reportedBy.title = `${wrappedTitle}`;
            }
        });

        // Sends a PING message to get the count of reported websites
        // TODO: Send this on refresh of tab as well
        browserAPI.runtime.sendMessage({
            messageType: Messages.BLOCKED_COUNTER_PING
        }).catch(() => {
        });

        /**
         * Gets the report URL lazily when needed.
         *
         * @returns {URL|null} - The report URL.
         */
        function getReportUrl() {
            switch (originInt) {
                case ProtectionResult.Origin.ADGUARD_SECURITY:
                    return new URL("mailto:support@adguard.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20AdGuard%20Public%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.ADGUARD_FAMILY:
                    return new URL("mailto:support@adguard.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20AdGuard%20Family%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.ALPHAMOUNTAIN:
                    return new URL("https://alphamountain.freshdesk.com/support/tickets/new");

                case ProtectionResult.Origin.CONTROL_D_SECURITY:
                    return new URL("mailto:help@controld.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20Control%20D%20Security%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.CONTROL_D_FAMILY:
                    return new URL("mailto:help@controld.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20Control%20D%20Family%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.PRECISIONSEC:
                    return new URL("mailto:info@precisionsec.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20PrecisionSec%20Web%20Protection" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.CERT_EE:
                    return new URL("mailto:ria@ria.ee?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20CERT-EE%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.CLEANBROWSING_SECURITY:
                    return new URL("mailto:support@cleanbrowsing.org?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20CleanBrowsing%20Security%20Filter" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.CLEANBROWSING_FAMILY:
                    return new URL("mailto:support@cleanbrowsing.org?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20CleanBrowsing%20Adult%20Filter" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.CLOUDFLARE_SECURITY:
                case ProtectionResult.Origin.CLOUDFLARE_FAMILY:
                    return new URL("https://radar.cloudflare.com/domains/feedback/" + encodedBlockedUrl);

                case ProtectionResult.Origin.DNS0_SECURITY:
                case ProtectionResult.Origin.DNS0_FAMILY:
                    return new URL("https://www.dns0.eu/report");

                case ProtectionResult.Origin.DNS4EU_SECURITY:
                    return new URL("mailto:viliam.peli@whalebone.io?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20DNS4EU%20Protective%20Resolution%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.DNS4EU_FAMILY:
                    return new URL("mailto:viliam.peli@whalebone.io?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20DNS4EU%20Protective%20Resolution%20with%20Child%20Protection%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.NORTON:
                    return new URL("https://safeweb.norton.com/report?url=" + encodedBlockedUrl);

                case ProtectionResult.Origin.QUAD9:
                    // Old URL: "https://quad9.net/support/contact"
                    // TODO: Needs verification of response from support team.
                    return new URL("mailto:support@quad9.net?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20Quad9%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

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
            domElements.reportWebsite.addEventListener("click", async () => {
                if (!settings.hideReportButton) {
                    await sendMessage(Messages.REPORT_WEBSITE, {
                        reportUrl: getReportUrl()
                    });
                }
            });

            // Adds event listener to "Always ignore this website" button
            domElements.allowWebsite.addEventListener("click", async () => {
                if (!settings.hideContinueButtons) {
                    await sendMessage(Messages.ALLOW_WEBSITE, {
                        blockedUrl: blockedUrl,
                        continueUrl: continueUrl
                    });
                }
            });

            // Adds event listener to "Back to safety" button
            domElements.backButton.addEventListener("click", async () => {
                await sendMessage(Messages.CONTINUE_TO_SAFETY, {
                    blockedUrl: blockedUrl
                });
            });

            // Adds event listener to "Continue anyway" button
            domElements.continueButton.addEventListener("click", async () => {
                if (!settings.hideContinueButtons) {
                    await sendMessage(Messages.CONTINUE_TO_WEBSITE, {
                        blockedUrl: blockedUrl,
                        continueUrl: continueUrl
                    });
                }
            });

            // Handles the hide continue buttons policy
            if (!settings.hideContinueButtons) {
                document.getElementById("allowWebsite").style.display = "";
                document.getElementById("continueButton").style.display = "";
            }

            // Handles the hide report button policy
            if (!settings.hideReportButton) {
                document.getElementById("reportWebsite").style.display = "";
                document.getElementById("reportBreakpoint").style.display = "";
            }

            // Handles the back button visibility
            document.getElementById("backButton").style.display = "";
        });
    }

    return {
        initialize
    };
})();

// Initializes when the DOM is ready
document.addEventListener("DOMContentLoaded", () => {
    window.WarningSingleton.initialize();
});
