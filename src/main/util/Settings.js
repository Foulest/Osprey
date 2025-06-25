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
        nortonEnabled: true,
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
    const updateIfChanged = function (target, source) {
        let hasChanges = false;

        if (source) {
            // Iterate through the source object properties
            for (let key in source) {
                // If the values differ, update the target and mark changes
                if (source[key] !== target[key]) {
                    target[key] = source[key];
                    hasChanges = true;
                }
            }
        }
        return hasChanges; // Return whether any changes were made
    };

    return {
        /**
         * Retrieves settings from local storage and merges them with default settings.
         *
         * @param {Function} callback - The function to call with the retrieved settings.
         */
        get: function (callback) {
            Storage.getFromLocalStore(settingsKey, function (storedSettings) {
                // Clone the default settings object
                let mergedSettings = JSON.parse(JSON.stringify(defaultSettings));

                // Merge any stored settings into the cloned default settings
                updateIfChanged(mergedSettings, storedSettings);

                // Invoke the callback with the merged settings
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
                // Clone the default settings object
                let mergedSettings = JSON.parse(JSON.stringify(defaultSettings));

                // Merge stored settings and new settings into the cloned default settings
                storedSettings && updateIfChanged(mergedSettings, storedSettings);
                updateIfChanged(mergedSettings, newSettings);

                // Save the merged settings back to local storage
                Storage.setToLocalStore(settingsKey, mergedSettings, callback);
            });
        },

        /**
         * Restore the default settings.
         *
         * @param callback - Callback function that will be called after restoring the settings.
         */
        restoreDefaultSettings: function (callback) {
            Storage.getFromLocalStore(settingsKey, function () {
                // Save the default settings back to local storage
                Storage.setToLocalStore(settingsKey, defaultSettings, callback);
            });
        }
    };
})();
