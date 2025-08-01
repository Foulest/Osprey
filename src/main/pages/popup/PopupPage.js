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

    // Tracks initialization state
    let isInitialized = false;

    // Cache for DOM elements
    const domElements = {};

    // Browser API compatibility between Chrome and Firefox
    const browserAPI = typeof browser === 'undefined' ? chrome : browser;

    // Security systems configuration - only defined once
    const securitySystems = [
        {
            name: "adGuardSecurityEnabled",
            title: "AdGuard Security DNS",
            labelElementId: "adGuardSecurityStatus",
            switchElementId: "adGuardSecuritySwitch",
            messageType: Messages.MessageType.ADGUARD_SECURITY_TOGGLED,
        },
        {
            name: "adGuardFamilyEnabled",
            title: "AdGuard Family DNS",
            labelElementId: "adGuardFamilyStatus",
            switchElementId: "adGuardFamilySwitch",
            messageType: Messages.MessageType.ADGUARD_FAMILY_TOGGLED,
        },
        {
            name: "alphaMountainEnabled",
            title: "alphaMountain Web Protection",
            labelElementId: "alphaMountainStatus",
            switchElementId: "alphaMountainSwitch",
            messageType: Messages.MessageType.ALPHAMOUNTAIN_TOGGLED,
        },
        {
            name: "controlDSecurityEnabled",
            title: "Control D Security DNS",
            labelElementId: "controlDSecurityStatus",
            switchElementId: "controlDSecuritySwitch",
            messageType: Messages.MessageType.CONTROL_D_SECURITY_TOGGLED,
        },
        {
            name: "controlDFamilyEnabled",
            title: "Control D Family DNS",
            labelElementId: "controlDFamilyStatus",
            switchElementId: "controlDFamilySwitch",
            messageType: Messages.MessageType.CONTROL_D_FAMILY_TOGGLED,
        },
        {
            name: "precisionSecEnabled",
            title: "PrecisionSec Web Protection",
            labelElementId: "precisionSecStatus",
            switchElementId: "precisionSecSwitch",
            messageType: Messages.MessageType.PRECISIONSEC_TOGGLED,
        },
        {
            name: "gDataEnabled",
            title: "G DATA Web Protection",
            labelElementId: "gDataStatus",
            switchElementId: "gDataSwitch",
            messageType: Messages.MessageType.G_DATA_TOGGLED,
        },
        {
            name: "smartScreenEnabled",
            title: "Microsoft SmartScreen",
            labelElementId: "smartScreenStatus",
            switchElementId: "smartScreenSwitch",
            messageType: Messages.MessageType.SMARTSCREEN_TOGGLED,
        },
        {
            name: "nortonEnabled",
            title: "Norton Safe Web",
            labelElementId: "nortonStatus",
            switchElementId: "nortonSwitch",
            messageType: Messages.MessageType.NORTON_TOGGLED,
        },
        {
            name: "certEEEnabled",
            title: "CERT-EE Security DNS",
            labelElementId: "certEEStatus",
            switchElementId: "certEESwitch",
            messageType: Messages.MessageType.CERT_EE_TOGGLED,
        },
        {
            name: "cleanBrowsingSecurityEnabled",
            title: "CleanBrowsing Security DNS",
            labelElementId: "cleanBrowsingSecurityStatus",
            switchElementId: "cleanBrowsingSecuritySwitch",
            messageType: Messages.MessageType.CLEANBROWSING_SECURITY_TOGGLED,
        },
        {
            name: "cleanBrowsingFamilyEnabled",
            title: "CleanBrowsing Family DNS",
            labelElementId: "cleanBrowsingFamilyStatus",
            switchElementId: "cleanBrowsingFamilySwitch",
            messageType: Messages.MessageType.CLEANBROWSING_FAMILY_TOGGLED,
        },
        {
            name: "cloudflareSecurityEnabled",
            title: "Cloudflare Security DNS",
            labelElementId: "cloudflareSecurityStatus",
            switchElementId: "cloudflareSecuritySwitch",
            messageType: Messages.MessageType.CLOUDFLARE_SECURITY_TOGGLED,
        },
        {
            name: "cloudflareFamilyEnabled",
            title: "Cloudflare Family DNS",
            labelElementId: "cloudflareFamilyStatus",
            switchElementId: "cloudflareFamilySwitch",
            messageType: Messages.MessageType.CLOUDFLARE_FAMILY_TOGGLED,
        },
        {
            name: "dns0SecurityEnabled",
            title: "DNS0.eu Security DNS",
            labelElementId: "dns0SecurityStatus",
            switchElementId: "dns0SecuritySwitch",
            messageType: Messages.MessageType.DNS0_SECURITY_TOGGLED,
        },
        {
            name: "dns0FamilyEnabled",
            title: "DNS0.eu Family DNS",
            labelElementId: "dns0FamilyStatus",
            switchElementId: "dns0FamilySwitch",
            messageType: Messages.MessageType.DNS0_FAMILY_TOGGLED,
        },
        {
            name: "dns4EUSecurityEnabled",
            title: "DNS4EU Security DNS",
            labelElementId: "dns4EUSecurityStatus",
            switchElementId: "dns4EUSecuritySwitch",
            messageType: Messages.MessageType.DNS4EU_SECURITY_TOGGLED,
        },
        {
            name: "dns4EUFamilyEnabled",
            title: "DNS4EU Family DNS",
            labelElementId: "dns4EUFamilyStatus",
            switchElementId: "dns4EUFamilySwitch",
            messageType: Messages.MessageType.DNS4EU_FAMILY_TOGGLED,
        },
        {
            name: "quad9Enabled",
            title: "Quad9 Security DNS",
            labelElementId: "quad9Status",
            switchElementId: "quad9Switch",
            messageType: Messages.MessageType.QUAD9_TOGGLED,
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
     * Batches updates UI elements for better performance.
     *
     * @param {Array} updates - Array of update operations to perform
     */
    function batchDomUpdates(updates) {
        window.requestAnimationFrame(() => {
            updates.forEach(update => update());
        });
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
                        elements.label.textContent = isOn ? "On (Locked)" : "Off (Locked)";
                    } else {
                        elements.label.textContent = isOn ? "On" : "Off";
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

        batchDomUpdates(updates);
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
                    title: system.title,
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

            if (elements && elements.switchElement) {
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

        const page1 = document.getElementById("page1");
        const page2 = document.getElementById("page2");
        const page3 = document.getElementById("page3");
        const prevPage = document.getElementById("prevPage");
        const nextPage = document.getElementById("nextPage");
        const pageIndicator = document.getElementById("pageIndicator");
        let currentPage = 1;
        const totalPages = 3;

        function updatePageDisplay() {
            // Checks for invalid current page numbers
            if (currentPage < 1 || currentPage > totalPages) {
                currentPage = 1;
            }

            const pages = [page1, page2, page3];

            // Checks for valid HTML page elements
            if (!pages.every(page => page instanceof HTMLElement)) {
                console.error('Missing page elements');
                return;
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

    // Returns the public API
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
