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

// Object containing helper functions for working with URLs.
const UrlHelpers = {

    /**
     * Extracts the blocked URL (the site being reported as malicious) from the query parameters of a URL.
     *
     * @param {string} url - The URL containing the blocked site information.
     * @returns {string|null} - The blocked URL, or null if not found.
     */
    extractBlockedUrl: url => {
        try {
            return new URL(url).searchParams.get("url");
        } catch (error) {
            console.warn(`Invalid URL format: ${error.message}`);
            return null;
        }
    },

    /**
     * Extracts the continue URL from the query parameters of a URL.
     *
     * @param {string} url - The URL containing the continue URL parameter.
     * @returns {string|null} - The continue URL, or null if not found.
     */
    extractContinueUrl: url => {
        try {
            return new URL(url).searchParams.get("curl");
        } catch (error) {
            console.warn(`Invalid URL format: ${error.message}`);
            return null;
        }
    },

    /**
     * Extracts the origin of the protection result from the query parameters of a URL.
     *
     * @param url - The URL containing the origin information
     * @returns {string} - The origin of the protection result
     */
    extractOrigin: url => {
        try {
            return new URL(url).searchParams.get("or");
        } catch (error) {
            console.warn(`Invalid URL format: ${error.message}`);
            return "0";
        }
    },

    /**
     * Extracts the result (e.g., phishing, malware) from the query parameters of a URL.
     *
     * @param {string} url - The URL containing the result.
     * @returns {string|null} - The result from the URL, or null if not found.
     */
    extractResult: url => {
        try {
            return new URL(url).searchParams.get("rs");
        } catch (error) {
            console.warn(`Invalid URL format: ${error.message}`);
            return null;
        }
    },

    /**
     * Constructs the URL for the browser's block page, which shows a warning when a site is blocked.
     *
     * @param {object} protectionResult - The result object containing details about the threat.
     * @param {object} continueURL - The URL to continue to if the user clicks a continue button.
     * @returns {string} - The full URL for the block page.
     */
    getBlockPageUrl: (protectionResult, continueURL) => {
        // Checks if the protection result is valid
        if (!protectionResult || typeof protectionResult !== 'object') {
            throw new Error('Invalid protection result');
        }

        // Checks if the protection result's properties are valid
        if (!protectionResult.url || !protectionResult.origin || !protectionResult.result) {
            throw new Error('Missing required protection result properties');
        }

        // Browser API compatibility between Chrome and Firefox
        const browserAPI = typeof browser === 'undefined' ? chrome : browser;

        // Base URL for the block page
        const blockPageBaseUrl = browserAPI.runtime.getURL("pages/warning/WarningPage.html");

        try {
            // Constructs a new URL object for the block page
            const blockPageUrl = new URL(blockPageBaseUrl);

            // Sets the search parameters for the block page URL
            blockPageUrl.search = new URLSearchParams([
                ["url", protectionResult.url],       // The URL of the blocked site
                ["curl", continueURL || ''],         // The continue URL
                ["or", protectionResult.origin],     // The origin of the protection result
                ["rs", protectionResult.result]      // The result string (e.g. Malicious)
            ]).toString();

            // Returns the constructed block page URL as a string
            return blockPageUrl.toString();
        } catch (error) {
            throw new Error(`Failed to construct block page URL: ${error.message}`);
        }
    },

    /**
     * Normalizes a hostname by removing "www." if it exists.
     *
     * @param {string} hostname - The hostname to normalize.
     * @returns {string} - The normalized hostname.
     */
    normalizeHostname: hostname => {
        // Ensures the hostname is a string before proceeding
        if (typeof hostname !== 'string') {
            return '';
        }

        hostname = hostname.trim().toLowerCase();

        // Checks if the hostname is invalid
        if (!hostname) {
            return '';
        }

        // Removes multiple possible www. prefixes
        while (hostname.startsWith('www.')) {
            hostname = hostname.substring(4);
        }

        // Removes trailing dots from the hostname
        hostname = hostname.replace(/\.+$/, '');
        return hostname;
    }
};
