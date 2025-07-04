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

// Storage utility for interacting with the browser's local storage.
const Storage = {

    /**
     * Checks if the storage API is available in the browser.
     *
     * @returns {boolean}
     */
    isAvailable() {
        const browserAPI = typeof browser === 'undefined' ? chrome : browser;
        return !!(browserAPI && browserAPI.storage && browserAPI.storage.local && browserAPI.storage.session);
    },

    /**
     * Retrieves data from the browser's local storage.
     *
     * @param {string} key - The key to retrieve from local storage.
     * @param {Function} callback - The function to call with the retrieved value.
     */
    getFromLocalStore(key, callback) {
        // Checks if the storage API is available
        if (!this.isAvailable()) {
            console.error('Storage API not available');
            callback(null);
            return;
        }

        // Browser API compatibility between Chrome and Firefox
        const browserAPI = typeof browser === 'undefined' ? chrome : browser;

        browserAPI.storage.local.get(key, function (result) {
            // Handles errors in the storage process
            if (browserAPI.runtime.lastError) {
                console.error('Storage error:', browserAPI.runtime.lastError);
                callback(null);
                return;
            }

            // Extracts the value associated with the key.
            let value = result && result[key];

            // Calls the callback function with the retrieved value.
            callback(value);
        });
    },

    /**
     * Saves data to the browser's local storage.
     *
     * @param {string} key - The key to save to local storage.
     * @param {any} value - The value to store.
     * @param {Function} [callback] - Optional callback to call after saving.
     */
    setToLocalStore(key, value, callback) {
        // Checks if the storage API is available
        if (!this.isAvailable()) {
            console.error('Storage API not available');
            callback(null);
            return;
        }

        // Checks if the key is a string
        if (typeof key !== 'string') {
            throw new Error('Key must be a string');
        }

        // Browser API compatibility between Chrome and Firefox
        const browserAPI = typeof browser === 'undefined' ? chrome : browser;

        // The final callback variable
        const finalCallback = typeof callback === 'function' ? callback : () => {
        };

        // Creates an object to hold the key-value pair
        let data = {};
        data[key] = value;

        browserAPI.storage.local.set(data, function () {
            // Handles errors in the storage process
            if (browserAPI.runtime.lastError) {
                console.error('Storage error:', browserAPI.runtime.lastError);
            }

            // Completes the callback
            finalCallback();
        });
    },

    /**
     * Retrieves data from the browser's session storage.
     *
     * @param {string} key - The key to retrieve from session storage.
     * @param {Function} callback - The function to call with the retrieved value.
     */
    getFromSessionStore(key, callback) {
        // Checks if the storage API is available
        if (!this.isAvailable()) {
            console.error('Storage API not available');
            callback(null);
            return;
        }

        // Browser API compatibility between Chrome and Firefox
        const browserAPI = typeof browser === 'undefined' ? chrome : browser;

        browserAPI.storage.session.get(key, function (result) {
            // Handles errors in the storage process
            if (browserAPI.runtime.lastError) {
                console.error('Storage error:', browserAPI.runtime.lastError);
                callback(null);
                return;
            }

            // Extracts the value associated with the key.
            let value = result && result[key];

            // Calls the callback function with the retrieved value.
            callback(value);
        });
    },

    /**
     * Saves data to the browser's session storage.
     *
     * @param {string} key - The key to save to session storage.
     * @param {any} value - The value to store.
     * @param {Function} [callback] - Optional callback to call after saving.
     */
    setToSessionStore(key, value, callback) {
        // Checks if the storage API is available
        if (!this.isAvailable()) {
            console.error('Storage API not available');
            callback(null);
            return;
        }

        // Checks if the key is a string
        if (typeof key !== 'string') {
            throw new Error('Key must be a string');
        }

        // Browser API compatibility between Chrome and Firefox
        const browserAPI = typeof browser === 'undefined' ? chrome : browser;

        // The final callback variable
        const finalCallback = typeof callback === 'function' ? callback : () => {
        };

        // Creates an object to hold the key-value pair
        let data = {};
        data[key] = value;

        browserAPI.storage.session.set(data, function () {
            // Handles errors in the storage process
            if (browserAPI.runtime.lastError) {
                console.error('Storage error:', browserAPI.runtime.lastError);
            }

            // Completes the callback
            finalCallback();
        });
    }
};
