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
globalThis.PopupSingleton = globalThis.PopupSingleton || (() => {

    // Browser API compatibility between Chrome and Firefox
    const browserAPI = typeof browser === 'undefined' ? chrome : browser;

    // Tracks initialization state
    let isInitialized = false;

    // Cache for system elements
    const systemElements = {};

    // Cache for DOM elements
    let domElements = {};

    // Security systems configuration - only defined once
    const securitySystems = [
        {
            origin: ProtectionResult.Origin.ADGUARD_SECURITY,
            name: "adGuardSecurityEnabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "adGuardSecurityStatus",
            switchElementId: "adGuardSecuritySwitch",
            messageType: Messages.ADGUARD_SECURITY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.ADGUARD_FAMILY,
            name: "adGuardFamilyEnabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "adGuardFamilyStatus",
            switchElementId: "adGuardFamilySwitch",
            messageType: Messages.ADGUARD_FAMILY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.ALPHAMOUNTAIN,
            name: "alphaMountainEnabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "alphaMountainStatus",
            switchElementId: "alphaMountainSwitch",
            messageType: Messages.ALPHAMOUNTAIN_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.CONTROL_D_SECURITY,
            name: "controlDSecurityEnabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "controlDSecurityStatus",
            switchElementId: "controlDSecuritySwitch",
            messageType: Messages.CONTROL_D_SECURITY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.CONTROL_D_FAMILY,
            name: "controlDFamilyEnabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "controlDFamilyStatus",
            switchElementId: "controlDFamilySwitch",
            messageType: Messages.CONTROL_D_FAMILY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.PRECISIONSEC,
            name: "precisionSecEnabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "precisionSecStatus",
            switchElementId: "precisionSecSwitch",
            messageType: Messages.PRECISIONSEC_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.CERT_EE,
            name: "certEEEnabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "certEEStatus",
            switchElementId: "certEESwitch",
            messageType: Messages.CERT_EE_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.CLEANBROWSING_SECURITY,
            name: "cleanBrowsingSecurityEnabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "cleanBrowsingSecurityStatus",
            switchElementId: "cleanBrowsingSecuritySwitch",
            messageType: Messages.CLEANBROWSING_SECURITY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.CLEANBROWSING_FAMILY,
            name: "cleanBrowsingFamilyEnabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "cleanBrowsingFamilyStatus",
            switchElementId: "cleanBrowsingFamilySwitch",
            messageType: Messages.CLEANBROWSING_FAMILY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.CLOUDFLARE_SECURITY,
            name: "cloudflareSecurityEnabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "cloudflareSecurityStatus",
            switchElementId: "cloudflareSecuritySwitch",
            messageType: Messages.CLOUDFLARE_SECURITY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.CLOUDFLARE_FAMILY,
            name: "cloudflareFamilyEnabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "cloudflareFamilyStatus",
            switchElementId: "cloudflareFamilySwitch",
            messageType: Messages.CLOUDFLARE_FAMILY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.DNS0_SECURITY,
            name: "dns0SecurityEnabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "dns0SecurityStatus",
            switchElementId: "dns0SecuritySwitch",
            messageType: Messages.DNS0_SECURITY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.DNS0_FAMILY,
            name: "dns0FamilyEnabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "dns0FamilyStatus",
            switchElementId: "dns0FamilySwitch",
            messageType: Messages.DNS0_FAMILY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.DNS4EU_SECURITY,
            name: "dns4EUSecurityEnabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "dns4EUSecurityStatus",
            switchElementId: "dns4EUSecuritySwitch",
            messageType: Messages.DNS4EU_SECURITY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.DNS4EU_FAMILY,
            name: "dns4EUFamilyEnabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "dns4EUFamilyStatus",
            switchElementId: "dns4EUFamilySwitch",
            messageType: Messages.DNS4EU_FAMILY_TOGGLED,
        },
        {
            origin: ProtectionResult.Origin.QUAD9,
            name: "quad9Enabled",
            title: ProtectionResult.FullName[this.origin],
            labelElementId: "quad9Status",
            switchElementId: "quad9Switch",
            messageType: Messages.QUAD9_TOGGLED,
        }
    ];

    // Cached manifest data
    const manifest = browserAPI.runtime.getManifest();

    /**
     * Gets DOM elements for a system, caching them for future use.
     *
     * @param {Object} system - The system object
     * @returns {Object} Object containing the label and switch elements
     */
    function getSystemElements(system) {
        if (!systemElements[system.name]) {
            systemElements[system.name] = {
                label: document.getElementById(system.labelElementId),
                switchElement: document.getElementById(system.switchElementId)
            };
        }
        return systemElements[system.name];
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
                        elements.label.textContent = isOn ? LangUtil.ON_LOCKED_TEXT : LangUtil.OFF_LOCKED_TEXT;
                    } else {
                        elements.label.textContent = isOn ? LangUtil.ON_TEXT : LangUtil.OFF_TEXT;
                    }
                });
            } else {
                console.warn(`'label' element not found for ${system.name} in the PopupPage DOM.`);
            }

            if (elements.switchElement) {
                if (isOn) {
                    elements.switchElement.classList.add("on");
                    elements.switchElement.classList.remove("off");
                } else {
                    elements.switchElement.classList.remove("on");
                    elements.switchElement.classList.add("off");
                }
            } else {
                console.warn(`'switchElement' not found for ${system.name} in the PopupPage DOM.`);
            }
        });

        // Batches the DOM updates for performance
        globalThis.requestAnimationFrame(() => {
            for (const update of updates) {
                update();
            }
        });
    }

    /**
     * Toggles the state of a security system and updates its UI.
     *
     * @param {Object} system - The system object being toggled.
     */
    function toggleProtection(system) {
        Settings.get(settings => {
            // Validates name before sending the message
            if (!system.name) {
                console.error(`No name defined for system with origin ${system.origin}; cannot send toggle message.`);
                return;
            }

            const currentState = settings[system.name];
            const newState = !currentState;

            Settings.set({[system.name]: newState}, () => {
                // Validates messageType before sending the message
                if (!system.messageType) {
                    console.error(`No messageType defined for ${system.name}; cannot send toggle message.`);
                    return;
                }

                // Validates origin before sending the message
                if (!system.origin) {
                    console.error(`No origin defined for ${system.name}; cannot send toggle message.`);
                    return;
                }

                updateProtectionStatusUI(system, newState);

                browserAPI.runtime.sendMessage({
                    messageType: system.messageType,
                    title: ProtectionResult.FullName[system.origin],
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
        for (const system of securitySystems) {
            // Validates name before sending the message
            if (!system.name) {
                console.error(`No name defined for system with origin ${system.origin}; cannot remove click handler.`);
                continue;
            }

            const elements = systemElements[system.name];

            if (elements?.switchElement) {
                elements.switchElement.onclick = null;
            }
        }

        // Keeps the DOM elements cache, but resets initialized status
        isInitialized = false;
    }

    /**
     * Initializes the popup or refresh if already initialized.
     */
    function initialize() {
        // Initializes the DOM element cache
        domElements = Object.fromEntries(
            ["popupTitle", "githubLink", "version", "privacyPolicy", "logo", "prevPage", "nextPage", "pageIndicator"]
                .map(id => [id, document.getElementById(id)])
        );

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
            const bannerText = document.querySelector('.bannerText');

            // Sets the document title text
            if (document.title) {
                document.title = LangUtil.TITLE;
            } else {
                console.warn("Document title not found in the PopupPage DOM.");
            }

            // Sets the banner text
            if (bannerText) {
                bannerText.textContent = LangUtil.BANNER_TEXT;
            } else {
                console.warn("'bannerText' element not found in the PopupPage DOM.");
            }

            // Sets titles and aria-labels for star symbols and partner labels
            for (const element of document.querySelectorAll('.starSymbol, .partnerLabel')) {
                element.setAttribute('title', LangUtil.OFFICIAL_PARTNER_TITLE);
                element.setAttribute('aria-label', LangUtil.OFFICIAL_PARTNER_TITLE);
            }

            // Sets the alt text for the AdGuard logo
            for (const element of document.querySelectorAll('.adGuardLogo')) {
                element.alt = LangUtil.ADGUARD_LOGO_ALT;
                element.setAttribute('title', LangUtil.ADGUARD_LOGO_ALT);
                element.setAttribute('aria-label', LangUtil.ADGUARD_LOGO_ALT);
            }

            // Sets the alt text for the alphaMountain logo
            for (const element of document.querySelectorAll('.alphaMountainLogo')) {
                element.alt = LangUtil.ALPHA_MOUNTAIN_LOGO_ALT;
                element.setAttribute('title', LangUtil.ALPHA_MOUNTAIN_LOGO_ALT);
                element.setAttribute('aria-label', LangUtil.ALPHA_MOUNTAIN_LOGO_ALT);
            }

            // Sets the alt text for the Control D logo
            for (const element of document.querySelectorAll('.controlDLogo')) {
                element.alt = LangUtil.CONTROL_D_LOGO_ALT;
                element.setAttribute('title', LangUtil.CONTROL_D_LOGO_ALT);
                element.setAttribute('aria-label', LangUtil.CONTROL_D_LOGO_ALT);
            }

            // Sets the alt text for the PrecisionSec logo
            for (const element of document.querySelectorAll('.precisionSecLogo')) {
                element.alt = LangUtil.PRECISION_SEC_LOGO_ALT;
                element.setAttribute('title', LangUtil.PRECISION_SEC_LOGO_ALT);
                element.setAttribute('aria-label', LangUtil.PRECISION_SEC_LOGO_ALT);
            }

            // Sets the alt text for the CERT-EE logo
            for (const element of document.querySelectorAll('.certEELogo')) {
                element.alt = LangUtil.CERT_EE_LOGO_ALT;
                element.setAttribute('title', LangUtil.CERT_EE_LOGO_ALT);
                element.setAttribute('aria-label', LangUtil.CERT_EE_LOGO_ALT);
            }

            // Sets the alt text for the CleanBrowsing logo
            for (const element of document.querySelectorAll('.cleanBrowsingLogo')) {
                element.alt = LangUtil.CLEAN_BROWSING_LOGO_ALT;
                element.setAttribute('title', LangUtil.CLEAN_BROWSING_LOGO_ALT);
                element.setAttribute('aria-label', LangUtil.CLEAN_BROWSING_LOGO_ALT);
            }

            // Sets the alt text for the Cloudflare logo
            for (const element of document.querySelectorAll('.cloudflareLogo')) {
                element.alt = LangUtil.CLOUDFLARE_LOGO_ALT;
                element.setAttribute('title', LangUtil.CLOUDFLARE_LOGO_ALT);
                element.setAttribute('aria-label', LangUtil.CLOUDFLARE_LOGO_ALT);
            }

            // Sets the alt text for the DNS0.eu logo
            for (const element of document.querySelectorAll('.dns0Logo')) {
                element.alt = LangUtil.DNS0_LOGO_ALT;
                element.setAttribute('title', LangUtil.DNS0_LOGO_ALT);
                element.setAttribute('aria-label', LangUtil.DNS0_LOGO_ALT);
            }

            // Sets the alt text for the DNS4EU logo
            for (const element of document.querySelectorAll('.dns4EULogo')) {
                element.alt = LangUtil.DNS4EU_LOGO_ALT;
                element.setAttribute('title', LangUtil.DNS4EU_LOGO_ALT);
                element.setAttribute('aria-label', LangUtil.DNS4EU_LOGO_ALT);
            }

            // Sets the alt text for the Quad9 logo
            for (const element of document.querySelectorAll('.quad9Logo')) {
                element.alt = LangUtil.QUAD9_LOGO_ALT;
                element.setAttribute('title', LangUtil.QUAD9_LOGO_ALT);
                element.setAttribute('aria-label', LangUtil.QUAD9_LOGO_ALT);
            }

            // Sets the alt text for the Osprey logo
            if (domElements.logo) {
                domElements.logo.alt = LangUtil.LOGO_ALT;
            } else {
                console.warn("'logo' element not found in the PopupPage DOM.");
            }

            // Sets the popup title text
            if (domElements.popupTitle) {
                domElements.popupTitle.textContent = LangUtil.POPUP_TITLE;
            } else {
                console.warn("'popupTitle' element not found in the PopupPage DOM.");
            }

            // Sets the GitHub link text
            if (domElements.githubLink) {
                domElements.githubLink.textContent = LangUtil.GITHUB_LINK;
            } else {
                console.warn("'githubLink' element not found in the PopupPage DOM.");
            }

            // Sets the version text
            if (domElements.version) {
                domElements.version.textContent = LangUtil.VERSION;
            } else {
                console.warn("'version' element not found in the PopupPage DOM.");
            }

            // Sets the Privacy Policy text
            if (domElements.privacyPolicy) {
                domElements.privacyPolicy.textContent = LangUtil.PRIVACY_POLICY;
            } else {
                console.warn("'privacyPolicy' element not found in the PopupPage DOM.");
            }
        }

        // Localizes the page content
        localizePage();

        // Sets up switch elements and click handlers
        for (const system of securitySystems) {
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
            } else {
                console.warn(`'switchElement' not found for ${system.name} in the PopupPage DOM; cannot set click handler.`);
            }
        }

        // Loads and applies settings
        Settings.get(settings => {
            for (const system of securitySystems) {
                // Validates name before sending the message
                if (!system.name) {
                    console.error(`No name defined for system with origin ${system.origin}; cannot apply settings.`);
                    continue;
                }

                const isEnabled = settings[system.name];
                updateProtectionStatusUI(system, isEnabled);
            }
        });

        // Updates the version display
        if (domElements.version) {
            const version = manifest.version;
            domElements.version.textContent += version;
        } else {
            console.warn("'version' element not found in the PopupPage DOM.");
        }

        // Get all elements with the class 'page'
        const pages = document.querySelectorAll('.page');
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

            // Toggles the active status of each page
            for (let i = 0; i < pages.length; i++) {
                if (i + 1 === currentPage) {
                    pages[i].classList.add('active');
                }
            }

            // Updates the page indicator
            if (domElements.pageIndicator) {
                domElements.pageIndicator.textContent = `${currentPage}/${totalPages}`;
            } else {
                console.warn("'pageIndicator' element not found in the PopupPage DOM.");
            }
        }

        if (domElements.prevPage) {
            domElements.prevPage.addEventListener("click", function () {
                currentPage = currentPage === 1 ? totalPages : currentPage - 1;
                updatePageDisplay();
            });
        } else {
            console.warn("'prevPage' element not found in the PopupPage DOM.");
        }

        if (domElements.nextPage) {
            domElements.nextPage.addEventListener("click", function () {
                currentPage = currentPage === totalPages ? 1 : currentPage + 1;
                updatePageDisplay();
            });
        } else {
            console.warn("'nextPage' element not found in the PopupPage DOM.");
        }

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
            globalThis.close();
        } else {
            globalThis.PopupSingleton.initialize();
        }
    });
});
