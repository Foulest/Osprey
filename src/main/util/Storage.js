"use strict";

// Storage utility for interacting with Chrome's local storage.
const Storage = {

    /**
     * Retrieves data from Chrome's local storage.
     * @param {string} key - The key to retrieve from local storage.
     * @param {Function} callback - The function to call with the retrieved value.
     */
    getFromLocalStore: function (key, callback) {
        /**
         * Internal function to handle the retrieval process from local storage.
         * @param {object} storage - The storage object (chrome.storage.local).
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
        })(chrome.storage.local, key, callback);
    },

    /**
     * Saves data to Chrome's local storage.
     * @param {string} key - The key to save to local storage.
     * @param {any} value - The value to store.
     * @param {Function} [callback] - Optional callback to call after saving.
     */
    setToLocalStore: function (key, value, callback) {
        /**
         * Internal function to handle the saving process to local storage.
         * @param {object} storage - The storage object (chrome.storage.local).
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
        })(chrome.storage.local, key, value, callback);
    }
};
