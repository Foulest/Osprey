"use strict";

// Storage utility for interacting with the browser's local storage.
const Storage = {

    /**
     * Retrieves data from the browser's local storage.
     *
     * @param {string} key - The key to retrieve from local storage.
     * @param {Function} callback - The function to call with the retrieved value.
     */
    getFromLocalStore: function (key, callback) {
        // Browser API compatibility between Chrome and Firefox
        const browserAPI = typeof browser === 'undefined' ? chrome : browser;

        /**
         * Internal function to handle the retrieval process from local storage.
         *
         * @param {object} storage - The storage object (browserAPI.storage.local).
         * @param {string} key - The key to retrieve from the storage.
         * @param {Function} callback - The function to call with the retrieved value.
         */
        (function (storage, key, callback) {
            // Get the data from local storage.
            storage.get(key, function (result) {
                // Extract the value associated with the key.
                let value = result && result[key];

                // Call the callback function with the retrieved value.
                callback(value);
            });
        })(browserAPI.storage.local, key, callback);
    },

    /**
     * Saves data to the browser's local storage.
     *
     * @param {string} key - The key to save to local storage.
     * @param {any} value - The value to store.
     * @param {Function} [callback] - Optional callback to call after saving.
     */
    setToLocalStore: function (key, value, callback) {
        // Browser API compatibility between Chrome and Firefox
        const browserAPI = typeof browser === 'undefined' ? chrome : browser;

        /**
         * Internal function to handle the saving process to local storage.
         *
         * @param {object} storage - The storage object (browserAPI.storage.local).
         * @param {string} key - The key to save the value under.
         * @param {any} value - The value to store.
         * @param {Function} [callback] - Optional callback to call after saving.
         */
        (function (storage, key, value, callback) {
            // Create an object to hold the key-value pair.
            let data = {};
            data[key] = value;

            // Save the data to local storage.
            storage.set(data, callback);
        })(browserAPI.storage.local, key, value, callback);
    },

    /**
     * Retrieves data from the browser's session storage.
     *
     * @param {string} key - The key to retrieve from session storage.
     * @param {Function} callback - The function to call with the retrieved value.
     */
    getFromSessionStore: function (key, callback) {
        // Browser API compatibility between Chrome and Firefox
        const browserAPI = typeof browser === 'undefined' ? chrome : browser;

        /**
         * Internal function to handle the retrieval process from session storage.
         *
         * @param {object} storage - The storage object (browserAPI.storage.session).
         * @param {string} key - The key to retrieve from the storage.
         * @param {Function} callback - The function to call with the retrieved value.
         */
        (function (storage, key, callback) {
            // Get the data from session storage.
            storage.get(key, function (result) {
                // Extract the value associated with the key.
                let value = result && result[key];

                // Call the callback function with the retrieved value.
                callback(value);
            });
        })(browserAPI.storage.session, key, callback);
    },

    /**
     * Saves data to the browser's session storage.
     *
     * @param {string} key - The key to save to session storage.
     * @param {any} value - The value to store.
     * @param {Function} [callback] - Optional callback to call after saving.
     */
    setToSessionStore: function (key, value, callback) {
        // Browser API compatibility between Chrome and Firefox
        const browserAPI = typeof browser === 'undefined' ? chrome : browser;

        /**
         * Internal function to handle the saving process to session storage.
         *
         * @param {object} storage - The storage object (browserAPI.storage.session).
         * @param {string} key - The key to save the value under.
         * @param {any} value - The value to store.
         * @param {Function} [callback] - Optional callback to call after saving.
         */
        (function (storage, key, value, callback) {
            // Create an object to hold the key-value pair.
            let data = {};
            data[key] = value;

            // Save the data to session storage.
            storage.set(data, callback);
        })(browserAPI.storage.session, key, value, callback);
    }
};
