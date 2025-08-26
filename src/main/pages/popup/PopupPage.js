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

// Use a global singleton pattern to ensure we don't duplicate resources
window.PopupSingleton = window.PopupSingleton || (() => {

    // Browser API compatibility between Chrome and Firefox
    const browserAPI = typeof browser === 'undefined' ? chrome : browser;

    // Tracks initialization state
    let isInitialized = false;

    // Cache for DOM elements
    const domElements = {};

    // Security systems configuration - only defined once
    const securitySystems = [
        {
            origin: ProtectionResult.Origin.ADGUARD_SECURITY,
            name: "adGuardSecurityEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "adGuardSecurityStatus",
            switchElementId: "adGuardSecuritySwitch",
            messageType: Messages.ADGUARD_SECURITY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.ADGUARD_FAMILY,
            name: "adGuardFamilyEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "adGuardFamilyStatus",
            switchElementId: "adGuardFamilySwitch",
            messageType: Messages.ADGUARD_FAMILY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.ALPHAMOUNTAIN,
            name: "alphaMountainEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "alphaMountainStatus",
            switchElementId: "alphaMountainSwitch",
            messageType: Messages.ALPHAMOUNTAIN_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.CONTROL_D_SECURITY,
            name: "controlDSecurityEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "controlDSecurityStatus",
            switchElementId: "controlDSecuritySwitch",
            messageType: Messages.CONTROL_D_SECURITY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.CONTROL_D_FAMILY,
            name: "controlDFamilyEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "controlDFamilyStatus",
            switchElementId: "controlDFamilySwitch",
            messageType: Messages.CONTROL_D_FAMILY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.PRECISIONSEC,
            name: "precisionSecEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "precisionSecStatus",
            switchElementId: "precisionSecSwitch",
            messageType: Messages.PRECISIONSEC_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.CERT_EE,
            name: "certEEEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "certEEStatus",
            switchElementId: "certEESwitch",
            messageType: Messages.CERT_EE_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.CLEANBROWSING_SECURITY,
            name: "cleanBrowsingSecurityEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "cleanBrowsingSecurityStatus",
            switchElementId: "cleanBrowsingSecuritySwitch",
            messageType: Messages.CLEANBROWSING_SECURITY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.CLEANBROWSING_FAMILY,
            name: "cleanBrowsingFamilyEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "cleanBrowsingFamilyStatus",
            switchElementId: "cleanBrowsingFamilySwitch",
            messageType: Messages.CLEANBROWSING_FAMILY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.CLOUDFLARE_SECURITY,
            name: "cloudflareSecurityEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "cloudflareSecurityStatus",
            switchElementId: "cloudflareSecuritySwitch",
            messageType: Messages.CLOUDFLARE_SECURITY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.CLOUDFLARE_FAMILY,
            name: "cloudflareFamilyEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "cloudflareFamilyStatus",
            switchElementId: "cloudflareFamilySwitch",
            messageType: Messages.CLOUDFLARE_FAMILY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.DNS0_SECURITY,
            name: "dns0SecurityEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "dns0SecurityStatus",
            switchElementId: "dns0SecuritySwitch",
            messageType: Messages.DNS0_SECURITY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.DNS0_FAMILY,
            name: "dns0FamilyEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "dns0FamilyStatus",
            switchElementId: "dns0FamilySwitch",
            messageType: Messages.DNS0_FAMILY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.DNS4EU_SECURITY,
            name: "dns4EUSecurityEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "dns4EUSecurityStatus",
            switchElementId: "dns4EUSecuritySwitch",
            messageType: Messages.DNS4EU_SECURITY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.DNS4EU_FAMILY,
            name: "dns4EUFamilyEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "dns4EUFamilyStatus",
            switchElementId: "dns4EUFamilySwitch",
            messageType: Messages.DNS4EU_FAMILY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.NORTON,
            name: "nortonEnabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "nortonStatus",
            switchElementId: "nortonSwitch",
            messageType: Messages.NORTON_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.QUAD9,
            name: "quad9Enabled",
            title: ProtectionResult.FullName[origin],
            labelElementId: "quad9Status",
            switchElementId: "quad9Switch",
            messageType: Messages.QUAD9_TOGGLED,
        }
    ];

    /**
     * Gets DOM elements for a system, caching them for future use.
     *
     * @param {Object} system - The system object
     * @returns {Object} Object containing the label and switch elements
     */
    function getSystemElements(system) {
        if (!domElements[system.name]) {
            domElements[system.name] = {
                label: document.getElementById(system.labelElementId),
                switchElement: document.getElementById(system.switchElementId)
            };
        }
        return domElements[system.name];
    }

    /**
     * Updates the UI for a specific security system using batched DOM operations.
     *
     * @param {Object} system - The system object being updated.
     * @param {boolean} isOn - Whether the protection is enabled for the system.
     */
    function updateProtectionStatusUI(system, isOn) {
        const updates = [];

        // Gets cached DOM elements or fetches them if not cached
        const elements = getSystemElements(system);

        updates.push(() => {
            if (elements.label) {
                Settings.get(settings => {
                    if (settings.lockProtectionOptions) {
                        elements.label.textContent = isOn ?
                            browserAPI.i18n.getMessage('onLockedText') :
                            browserAPI.i18n.getMessage('offLockedText');
                    } else {
                        elements.label.textContent = isOn ?
                            browserAPI.i18n.getMessage('onText') :
                            browserAPI.i18n.getMessage('offText');
                    }
                });
            }

            if (elements.switchElement) {
                if (isOn) {
                    elements.switchElement.classList.add("on");
                    elements.switchElement.classList.remove("off");
                } else {
                    elements.switchElement.classList.remove("on");
                    elements.switchElement.classList.add("off");
                }
            }
        });

        // Batches the DOM updates for performance
        window.requestAnimationFrame(() => {
            updates.forEach(update => update());
        });
    }

    /**
     * Toggles the state of a security system and updates its UI.
     *
     * @param {Object} system - The system object being toggled.
     */
    function toggleProtection(system) {
        Settings.get(settings => {
            const currentState = settings[system.name];
            const newState = !currentState;

            Settings.set({[system.name]: newState}, () => {
                updateProtectionStatusUI(system, newState);

                browserAPI.runtime.sendMessage({
                    messageType: system.messageType,
                    title: ProtectionResult.FullName[origin],
                    toggleState: newState,
                }).catch(error => {
                    console.error(`Failed to send message for ${system.name}:`, error);
                });
            });
        });
    }

    /**
     * Resets to initial state to prevent memory leaks.
     */
    function reset() {
        // Removes click handlers from all switches
        securitySystems.forEach(system => {
            const elements = domElements[system.name];

            if (elements?.switchElement) {
                elements.switchElement.onclick = null;
            }
        });

        // Keeps the DOM elements cache, but resets initialized status
        isInitialized = false;
    }

    /**
     * Initializes the popup or refresh if already initialized.
     */
    function initialize() {
        // If already initialized, reset first
        if (isInitialized) {
            reset();
        }

        // Marks initialized as true
        isInitialized = true;

        /**
         * Localizes the page by replacing text content with localized messages.
         */
        function localizePage() {
            // Helper function to get localized messages
            const getMessage = (key) => browserAPI.i18n.getMessage(key);

            // Maps element IDs to their corresponding i18n message keys
            const elements = {
                'popupTitle': 'popupTitle',
                'githubLink': 'githubLink',
                'version': 'version',
                'privacyPolicy': 'privacyPolicy'
            };

            // Sets the text content for each element based on its i18n message
            for (const [id, key] of Object.entries(elements)) {
                const element = document.getElementById(id);

                if (element) {
                    element.textContent = getMessage(key);
                }
            }

            // Sets titles and aria-labels for star symbols and partner labels
            document.querySelectorAll('.starSymbol, .partnerLabel').forEach(element => {
                const title = getMessage('officialPartnerTitle');
                element.setAttribute('title', title);
                element.setAttribute('aria-label', title);
            });

            // Sets the document title text
            document.title = getMessage('title');

            // Sets the banner text
            const bannerText = document.querySelector('.bannerText');
            if (bannerText) {
                bannerText.textContent = getMessage('bannerText');
            }

            // Sets the alt text for the Osprey logo
            const logo = document.getElementById('logo');
            if (logo) {
                logo.alt = getMessage('logoAlt');
            }

            // Sets the alt text for the AdGuard logo
            document.querySelectorAll('.adGuardLogo').forEach(element => {
                const title = getMessage('adGuardLogoAlt');
                element.alt = title;
                element.setAttribute('title', title);
                element.setAttribute('aria-label', title);
            });

            // Sets the alt text for the alphaMountain logo
            document.querySelectorAll('.alphaMountainLogo').forEach(element => {
                const title = getMessage('alphaMountainLogoAlt');
                element.alt = title;
                element.setAttribute('title', title);
                element.setAttribute('aria-label', title);
            });

            // Sets the alt text for the Control D logo
            document.querySelectorAll('.controlDLogo').forEach(element => {
                const title = getMessage('controlDLogoAlt');
                element.alt = title;
                element.setAttribute('title', title);
                element.setAttribute('aria-label', title);
            });

            // Sets the alt text for the PrecisionSec logo
            document.querySelectorAll('.precisionSecLogo').forEach(element => {
                const title = getMessage('precisionSecLogoAlt');
                element.alt = title;
                element.setAttribute('title', title);
                element.setAttribute('aria-label', title);
            });

            // Sets the alt text for the CERT-EE logo
            document.querySelectorAll('.certEELogo').forEach(element => {
                const title = getMessage('certEELogoAlt');
                element.alt = title;
                element.setAttribute('title', title);
                element.setAttribute('aria-label', title);
            });

            // Sets the alt text for the CleanBrowsing logo
            document.querySelectorAll('.cleanBrowsingLogo').forEach(element => {
                const title = getMessage('cleanBrowsingLogoAlt');
                element.alt = title;
                element.setAttribute('title', title);
                element.setAttribute('aria-label', title);
            });

            // Sets the alt text for the Cloudflare logo
            document.querySelectorAll('.cloudflareLogo').forEach(element => {
                const title = getMessage('cloudflareLogoAlt');
                element.alt = title;
                element.setAttribute('title', title);
                element.setAttribute('aria-label', title);
            });

            // Sets the alt text for the DNS0.eu logo
            document.querySelectorAll('.dns0Logo').forEach(element => {
                const title = getMessage('dns0LogoAlt');
                element.alt = title;
                element.setAttribute('title', title);
                element.setAttribute('aria-label', title);
            });

            // Sets the alt text for the DNS4EU logo
            document.querySelectorAll('.dns4EULogo').forEach(element => {
                const title = getMessage('dns4EULogoAlt');
                element.alt = title;
                element.setAttribute('title', title);
                element.setAttribute('aria-label', title);
            });

            // Sets the alt text for the Norton logo
            document.querySelectorAll('.nortonLogo').forEach(element => {
                const title = getMessage('nortonLogoAlt');
                element.alt = title;
                element.setAttribute('title', title);
                element.setAttribute('aria-label', title);
            });

            // Sets the alt text for the Quad9 logo
            document.querySelectorAll('.quad9Logo').forEach(element => {
                const title = getMessage('quad9LogoAlt');
                element.alt = title;
                element.setAttribute('title', title);
                element.setAttribute('aria-label', title);
            });
        }

        // Localizes the page content
        localizePage();

        // Sets up switch elements and click handlers
        securitySystems.forEach(system => {
            const elements = getSystemElements(system);

            if (elements.switchElement) {
                elements.switchElement.onclick = () => {
                    Settings.get(settings => {
                        if (settings.lockProtectionOptions) {
                            console.debug("Protections are locked; cannot toggle.");
                        } else {
                            toggleProtection(system);
                        }
                    });
                };
            }
        });

        // Loads and applies settings
        Settings.get(settings => {
            securitySystems.forEach(system => {
                const isEnabled = settings[system.name];
                updateProtectionStatusUI(system, isEnabled);
            });
        });

        const versionElement = document.getElementById("version");

        // Updates the version display
        if (versionElement) {
            const manifest = browserAPI.runtime.getManifest();
            const version = manifest.version;
            versionElement.textContent += version;
        }

        // Get all elements with the class 'page'
        const pages = document.querySelectorAll('.page');
        const prevPage = document.getElementById("prevPage");
        const nextPage = document.getElementById("nextPage");
        const pageIndicator = document.getElementById("pageIndicator");

        let currentPage = 1;
        const totalPages = pages.length;

        // Checks if there are no pages
        if (totalPages === 0) {
            console.error('No pages found. Please ensure there are elements with the class "page".');
            return;
        }

        function updatePageDisplay() {
            // Checks for invalid current page numbers
            if (currentPage < 1 || currentPage > totalPages) {
                currentPage = 1;
            }

            // Toggles the active status
            pages.forEach((page, index) => {
                page.classList.toggle('active', index + 1 === currentPage);
            });

            // Updates the page indicator
            if (pageIndicator) {
                pageIndicator.textContent = `${currentPage}/${totalPages}`;
            }
        }

        prevPage.addEventListener("click", function () {
            currentPage = currentPage === 1 ? totalPages : currentPage - 1;
            updatePageDisplay();
        });

        nextPage.addEventListener("click", function () {
            currentPage = currentPage === totalPages ? 1 : currentPage + 1;
            updatePageDisplay();
        });

        // Initializes the page display
        updatePageDisplay();
    }

    return {
        initialize
    };
})();

// Initializes when the DOM is ready
document.addEventListener("DOMContentLoaded", () => {
    Settings.get(settings => {
        if (settings.hideProtectionOptions) {
            window.close();
        } else {
            window.PopupSingleton.initialize();
        }
    });
});
