"use strict";

// Object containing helper functions for working with URLs.
const UrlHelpers = {

    /**
     * Extracts the blocked URL (the site being reported as malicious) from the query parameters of a URL.
     *
     * @param {string} url - The URL containing the blocked site information.
     * @returns {string|null} - The blocked URL, or null if not found.
     */
    extractBlockedUrl: url => new URL(url).searchParams.get("url"),

    /**
     * Extracts the origin of the protection result from the query parameters of a URL.
     *
     * @param url - The URL containing the origin information
     * @returns {string} - The origin of the protection result
     */
    extractOrigin: url => new URL(url).searchParams.get("or"),

    /**
     * Extracts the result (e.g., phishing, malware) from the query parameters of a URL.
     *
     * @param {string} url - The URL containing the result.
     * @returns {string|null} - The result from the URL, or null if not found.
     */
    extractResult: url => new URL(url).searchParams.get("rs"),

    /**
     * Constructs the URL for the browser's block page, which shows a warning when a site is blocked.
     *
     * @param {object} protectionResult - The result object containing details about the threat.
     * @returns {string} - The full URL for the block page.
     */
    getBlockPageUrl: (protectionResult) => {
        // Browser API compatibility between Chrome and Firefox
        const browserAPI = typeof browser === 'undefined' ? chrome : browser;

        // Base URL for the block page
        const blockPageBaseUrl = browserAPI.runtime.getURL("pages/warning/WarningPage.html");

        // Determine the result from the protection result object
        const result = protectionResult.result;

        // Construct a new URL object for the block page
        let blockPageUrl = new URL(blockPageBaseUrl);

        // Set the search parameters for the block page URL
        blockPageUrl.search = new URLSearchParams([
            ["url", protectionResult.url],       // The URL of the blocked site
            ["or", protectionResult.origin],     // The origin of the protection result
            ["rs", result]                       // The result string (e.g. Malicious)
        ]).toString();

        // Return the constructed block page URL as a string
        return blockPageUrl.toString();
    },

    /**
     * Normalizes a hostname by removing "www." if it exists.
     *
     * @param {string} hostname - The hostname to normalize.
     * @returns {string} - The normalized hostname.
     */
    normalizeHostname: hostname => {
        // Ensure the hostname is a string before proceeding
        if (typeof hostname !== 'string') {
            return '';
        }

        // Remove "www." prefix if it exists in the hostname
        if (hostname.toLowerCase().startsWith("www.")) {
            hostname = hostname.substring(4);
        }
        return hostname;
    }
};
