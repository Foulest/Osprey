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

// Manages user preferences and configurations.
const Settings = (function () {

    // Key for storing settings in local storage
    const settingsKey = "Settings";

    let defaultSettings = {
        // Official Partners
        adGuardSecurityEnabled: true,
        adGuardFamilyEnabled: false,
        alphaMountainEnabled: true,
        controlDSecurityEnabled: true,
        controlDFamilyEnabled: false,
        precisionSecEnabled: true,

        // Non-Partnered Providers
        gDataEnabled: true,
        certEEEnabled: true,
        ciraSecurityEnabled: false,
        ciraFamilyEnabled: false,
        cleanBrowsingSecurityEnabled: true,
        cleanBrowsingFamilyEnabled: false,
        cleanBrowsingAdultEnabled: false,
        cloudflareSecurityEnabled: true,
        cloudflareFamilyEnabled: false,
        dns0SecurityEnabled: false,
        dns0KidsEnabled: false,
        dns4EUSecurityEnabled: true,
        dns4EUFamilyEnabled: false,
        smartScreenEnabled: true,
        nortonEnabled: false,
        openDNSSecurityEnabled: true,
        openDNSFamilyShieldEnabled: false,
        quad9Enabled: true,
        switchCHEnabled: false,

        // General Settings
        contextMenuEnabled: true,
        notificationsEnabled: false,
        ignoreFrameNavigation: true,
        hideContinueButtons: false,
        hideReportButton: false,
        lockProtectionOptions: false,
        hideProtectionOptions: false,
        cacheExpirationSeconds: 86400,
    };

    /**
     * Compares two objects and updates the target object with values from the source object if they differ.
     *
     * @param {Object} target - The target object to update.
     * @param {Object} source - The source object to compare with.
     * @returns {boolean} - Returns true if any values were updated, false otherwise.
     */
    function updateIfChanged(target, source) {
        // Checks if the target is valid
        if (!target || typeof target !== 'object') {
            throw new Error('Target must be an object');
        }

        // Checks if the source is valid
        if (!source || typeof source !== 'object') {
            return false;
        }

        let hasChanges = false;

        try {
            // Iterates through the source object properties
            // If the values differ, update the target and mark changes
            for (const key in source) {
                if (Object.prototype.hasOwnProperty.call(source, key)) {
                    if (source[key] !== target[key]) {
                        target[key] = source[key];
                        hasChanges = true;
                    }
                }
            }
        } catch (error) {
            console.error('Error updating settings:', error);
            throw error;
        }

        // Returns whether any changes were made
        return hasChanges;
    }

    return {
        /**
         * Retrieves settings from local storage and merges them with default settings.
         *
         * @param {Function} callback - The function to call with the retrieved settings.
         */
        get: function (callback) {
            Storage.getFromLocalStore(settingsKey, function (storedSettings) {
                // Clones the default settings object
                let mergedSettings = JSON.parse(JSON.stringify(defaultSettings));

                // Merges any stored settings into the cloned default settings
                updateIfChanged(mergedSettings, storedSettings);

                // Invokes the callback with the merged settings
                callback && callback(mergedSettings);
            });
        },

        /**
         * Saves settings to local storage, merging them with any previously stored settings.
         *
         * @param {Object} newSettings - The new settings to save.
         * @param {Function} [callback] - Optional callback to call after settings are saved.
         */
        set: function (newSettings, callback) {
            Storage.getFromLocalStore(settingsKey, function (storedSettings) {
                // Clones the default settings object
                let mergedSettings = JSON.parse(JSON.stringify(defaultSettings));

                // Merges stored settings and new settings into the cloned default settings
                storedSettings && updateIfChanged(mergedSettings, storedSettings);
                updateIfChanged(mergedSettings, newSettings);

                // Saves the merged settings back to local storage
                Storage.setToLocalStore(settingsKey, mergedSettings, callback);
            });
        },

        /**
         * Restore the default settings.
         *
         * @param callback - Callback function that will be called after restoring the settings.
         */
        restoreDefaultSettings: function (callback) {
            // Saves the default settings back to local storage
            Storage.getFromLocalStore(settingsKey, function () {
                Storage.setToLocalStore(settingsKey, defaultSettings, callback);
            });
        }
    };
})();
