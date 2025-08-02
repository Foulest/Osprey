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

// Main object for managing browser protection functionality
const BrowserProtection = (() => {

    // Map to store AbortControllers for each tab
    let tabAbortControllers = new Map();

    // API keys for various protection services
    let alphaMountainKey;
    let precisionSecKey;
    let gDataKey;
    let smartScreenKey;

    /**
     * Initializes the API keys for various protection services.
     *
     * The key values aren't meant to be secretive, but this might stop secret sniffing bots.
     */
    function initializeKeys() {
        alphaMountainKey = atob("YTRhNDVkYzMtNjFmMC00OGIzLTlmMjUtNjQxMzgxYjgwNWQ3");
        precisionSecKey = atob("MGI1Yjc2MjgtMzgyYi0xMWYwLWE1OWMtYjNiNTIyN2IxMDc2");
        gDataKey = atob("MS4xNC4wIDI1LjUuMTcuMzM1IDEyOS4wLjAuMA==");
        smartScreenKey = atob("MzgxZGRkMWUtZTYwMC00MmRlLTk0ZWQtOGMzNGJmNzNmMTZk");
    }

    /**
     * Closes all open connections for a specific tab.
     *
     * @param {number} tabId - The ID of the tab for which to close connections.
     * @param {string} reason - The reason for closing the connections.
     */
    function closeOpenConnections(tabId, reason) {
        if (tabAbortControllers.has(tabId)) {
            tabAbortControllers.get(tabId).abort(reason); // Abort all pending requests for the tab
            tabAbortControllers.set(tabId, new AbortController()); // Create a new controller for future requests
        }
    }

    /**
     * Cleans up controllers for tabs that no longer exist.
     */
    function cleanupTabControllers() {
        // Browser API compatibility between Chrome and Firefox
        const browserAPI = typeof browser === 'undefined' ? chrome : browser;

        // Remove controllers for tabs that no longer exist
        browserAPI.tabs.query({}, tabs => {
            const activeTabIds = new Set(tabs.map(tab => tab.id));

            for (const tabId of tabAbortControllers.keys()) {
                if (!activeTabIds.has(tabId)) {
                    tabAbortControllers.delete(tabId);
                    console.debug(`Removed controller for tab ID: ${tabId}`);
                }
            }
        });
    }

    return {
        initializeKeys,

        /**
         * Abandons all pending requests for a specific tab.
         *
         * @param {number} tabId - The ID of the tab for which to abandon requests.
         * @param {string} reason - The reason for abandoning the requests.
         */
        abandonPendingRequests: function (tabId, reason) {
            closeOpenConnections(tabId, reason);
        },

        /**
         * Checks if a URL is malicious or trusted.
         *
         * @param {number} tabId - The ID of the tab that initiated the request.
         * @param {string} url - The URL to check.
         * @param {function} callback - The callback function to handle the result.
         */
        checkIfUrlIsMalicious: function (tabId, url, callback) {
            // Return early if any of the parameters are missing
            if (!tabId || !url || !callback) {
                return;
            }

            // Capture the current time for response measurement
            const startTime = (new Date()).getTime();

            // Parse the URL to extract the hostname and pathname
            const urlObject = new URL(url);
            const urlHostname = urlObject.hostname;
            const urlPathname = urlObject.pathname;

            // The non-filtering URL used for DNS lookups
            const nonFilteringURL = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(urlHostname)}`;

            // Ensure there is an AbortController for the tab
            if (!tabAbortControllers.has(tabId)) {
                tabAbortControllers.set(tabId, new AbortController());
            }

            // Get the signal from the current AbortController
            const signal = tabAbortControllers.get(tabId).signal;

            /**
             * Checks the URL with AdGuard's Security DNS API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithAdGuardSecurity(settings) {
                // Checks if the provider is enabled
                if (!settings.adGuardSecurityEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "adGuardSecurity")) {
                    console.debug(`[AdGuard Security] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.ADGUARD_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "adGuardSecurity")) {
                    console.debug(`[AdGuard Security] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "adGuardSecurity"), ProtectionResult.ResultOrigin.ADGUARD_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "adGuardSecurity")) {
                    console.debug(`[AdGuard Security] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.ADGUARD_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "adGuardSecurity", tabId);

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://dns.adguard-dns.com/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Returns early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[AdGuard Security] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.ADGUARD_SECURITY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0 &&
                        nonFilteringData.Answer &&
                        nonFilteringData.Answer.length > 0) {

                        // AdGuard's way of blocking the domain.
                        if (filteringDataString.includes("0,0,1,0,1,192,12,0,1,0,1,0,0,14,16,0,4,94,140,14,3")) {
                            console.debug(`[AdGuard Security] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "adGuardSecurity", ProtectionResult.ResultType.MALICIOUS);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.ADGUARD_SECURITY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[AdGuard Security] Added URL to allowed cache: ${url}`);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "adGuardSecurity");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.ADGUARD_SECURITY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[AdGuard Security] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.ADGUARD_SECURITY), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with AdGuard's Family DNS API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithAdGuardFamily(settings) {
                // Checks if the provider is enabled
                if (!settings.adGuardFamilyEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "adGuardFamily")) {
                    console.debug(`[AdGuard Family] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.ADGUARD_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "adGuardFamily")) {
                    console.debug(`[AdGuard Family] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "adGuardFamily"), ProtectionResult.ResultOrigin.ADGUARD_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "adGuardFamily")) {
                    console.debug(`[AdGuard Family] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.ADGUARD_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "adGuardFamily", tabId);

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://family.adguard-dns.com/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Returns early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[AdGuard Family] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.ADGUARD_FAMILY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0 &&
                        nonFilteringData.Answer &&
                        nonFilteringData.Answer.length > 0) {

                        // AdGuard's way of blocking the domain.
                        if (filteringDataString.includes("0,0,1,0,1,192,12,0,1,0,1,0,0,14,16,0,4,94,140,14,3")) {
                            console.debug(`[AdGuard Family] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "adGuardFamily", ProtectionResult.ResultType.ADULT_CONTENT);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ADULT_CONTENT, ProtectionResult.ResultOrigin.ADGUARD_FAMILY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[AdGuard Family] Added URL to allowed cache: ${url}`);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "adGuardFamily");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.ADGUARD_FAMILY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[AdGuard Family] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.ADGUARD_FAMILY), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with alphaMountain's API.
             */
            async function checkUrlWithAlphaMountain(settings) {
                // Checks if the provider is enabled
                if (!settings.alphaMountainEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "alphaMountain")) {
                    console.debug(`[alphaMountain] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.ALPHAMOUNTAIN), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "alphaMountain")) {
                    console.debug(`[alphaMountain] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "alphaMountain"), ProtectionResult.ResultOrigin.ALPHAMOUNTAIN), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "alphaMountain")) {
                    console.debug(`[alphaMountain] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.ALPHAMOUNTAIN), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "alphaMountain", tabId);

                const apiUrl = `https://api.alphamountain.ai/filter/uri`;
                const payload = {
                    uri: url,
                    license: alphaMountainKey,
                    type: "user.main",
                    version: 1
                };

                try {
                    const response = await fetch(apiUrl, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                        },
                        body: JSON.stringify(payload),
                        signal
                    });

                    // Return early if the response is not OK
                    if (!response.ok) {
                        console.warn(`[alphaMountain] Returned early: ${response.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.ALPHAMOUNTAIN), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.json();

                    // Get the categories from the response
                    const categories = data.category?.categories;

                    // Check if the categories array is empty
                    if (!categories || !Array.isArray(categories) || categories.length === 0) {
                        console.info(`[alphaMountain] No categories found for URL: ${url}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.ALPHAMOUNTAIN), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Untrusted Categories
                    const untrustedCategories = [
                        11, // Child Sexual Abuse Material (CSAM)
                        15, // Drugs/Controlled Substances
                        55, // Potentially Unwanted Applications (PUA)
                        72, // Suspicious
                    ];

                    // Malicious Categories
                    const maliciousCategories = [
                        39, // Malicious
                    ];

                    // Phishing Categories
                    const phishingCategories = [
                        51, // Phishing
                    ];

                    // Check if the URL falls into any of the untrusted categories
                    if (categories.some(category => untrustedCategories.includes(category))) {
                        console.debug(`[alphaMountain] Added URL to blocked cache: ${url}`);
                        BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "alphaMountain", ProtectionResult.ResultType.UNTRUSTED);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.UNTRUSTED, ProtectionResult.ResultOrigin.ALPHAMOUNTAIN), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Check if the URL falls into any of the malicious categories
                    if (categories.some(category => maliciousCategories.includes(category))) {
                        console.debug(`[alphaMountain] Added URL to blocked cache: ${url}`);
                        BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "alphaMountain", ProtectionResult.ResultType.MALICIOUS);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.ALPHAMOUNTAIN), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Check if the URL falls into any of the phishing categories
                    if (categories.some(category => phishingCategories.includes(category))) {
                        console.debug(`[alphaMountain] Added URL to blocked cache: ${url}`);
                        BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "alphaMountain", ProtectionResult.ResultType.PHISHING);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.PHISHING, ProtectionResult.ResultOrigin.ALPHAMOUNTAIN), (new Date()).getTime() - startTime);
                        return;
                    }

                    // If the URL does not fall into any of the categories, it is considered safe
                    console.debug(`[alphaMountain] Added URL to allowed cache: ${url}`);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "alphaMountain");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.ALPHAMOUNTAIN), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[alphaMountain] Failed to check URL: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.ALPHAMOUNTAIN), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with Control D's Security DNS API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithControlDSecurity(settings) {
                // Checks if the provider is enabled
                if (!settings.controlDSecurityEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "controlDSecurity")) {
                    console.debug(`[Control D Security] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CONTROL_D_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "controlDSecurity")) {
                    console.debug(`[Control D Security] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "controlDSecurity"), ProtectionResult.ResultOrigin.CONTROL_D_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "controlDSecurity")) {
                    console.debug(`[Control D Security] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CONTROL_D_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "controlDSecurity", tabId);

                const filteringURL = `https://freedns.controld.com/no-malware-typo?name=${encodeURIComponent(urlHostname)}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Returns early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[Control D Security] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CONTROL_D_SECURITY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0 &&
                        nonFilteringData.Answer &&
                        nonFilteringData.Answer.length > 0) {

                        // ControlD's way of blocking the domain.
                        if (filteringDataString.endsWith("0,4,0,0,0,0")) {
                            console.debug(`[Control D Security] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "controlDSecurity", ProtectionResult.ResultType.MALICIOUS);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CONTROL_D_SECURITY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[Control D Security] Added URL to allowed cache: ${url}`);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "controlDSecurity");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CONTROL_D_SECURITY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Control D Security] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CONTROL_D_SECURITY), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with Control D's Family DNS API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithControlDFamily(settings) {
                // Checks if the provider is enabled
                if (!settings.controlDFamilyEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "controlDFamily")) {
                    console.debug(`[Control D Family] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CONTROL_D_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "controlDFamily")) {
                    console.debug(`[Control D Family] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "controlDFamily"), ProtectionResult.ResultOrigin.CONTROL_D_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "controlDFamily")) {
                    console.debug(`[Control D Family] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CONTROL_D_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "controlDFamily", tabId);

                const filteringURL = `https://freedns.controld.com/no-drugs-porn-gambling-malware-typo?name=${encodeURIComponent(urlHostname)}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Returns early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[Control D Family] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CONTROL_D_FAMILY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0 &&
                        nonFilteringData.Answer &&
                        nonFilteringData.Answer.length > 0) {

                        // ControlD's way of blocking the domain.
                        if (filteringDataString.endsWith("0,4,0,0,0,0")) {
                            console.debug(`[Control D Family] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "controlDFamily", ProtectionResult.ResultType.MALICIOUS);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CONTROL_D_FAMILY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[Control D Family] Added URL to allowed cache: ${url}`);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "controlDFamily");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CONTROL_D_FAMILY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Control D Family] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CONTROL_D_FAMILY), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with PrecisionSec's API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithPrecisionSec(settings) {
                // Checks if the provider is enabled
                if (!settings.precisionSecEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "precisionSec")) {
                    console.debug(`[PrecisionSec] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.PRECISIONSEC), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "precisionSec")) {
                    console.debug(`[PrecisionSec] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "precisionSec"), ProtectionResult.ResultOrigin.PRECISIONSEC), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "precisionSec")) {
                    console.debug(`[PrecisionSec] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.PRECISIONSEC), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "precisionSec", tabId);

                const apiUrl = `https://api.precisionsec.com/check_url/${encodeURIComponent(url)}`;

                try {
                    const response = await fetch(apiUrl, {
                        method: "GET",
                        headers: {
                            "Content-Type": "application/json",
                            "API-Key": precisionSecKey,
                        },
                        signal
                    });

                    // Return early if the response is not OK
                    if (!response.ok) {
                        console.warn(`[PrecisionSec] Returned early: ${response.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.PRECISIONSEC), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.json();
                    const {result} = data;

                    // Malicious
                    if (result === "Malicious") {
                        console.debug(`[PrecisionSec] Added URL to blocked cache: ${url}`);
                        BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "precisionSec", ProtectionResult.ResultType.MALICIOUS);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.PRECISIONSEC), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Safe/Trusted
                    if (result === "No result") {
                        console.debug(`[PrecisionSec] Added URL to allowed cache: ${url}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "precisionSec");
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.PRECISIONSEC), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Unexpected result
                    console.warn(`[PrecisionSec] Returned an unexpected result for URL ${url}: ${data}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.PRECISIONSEC), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[PrecisionSec] Failed to check URL: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.PRECISIONSEC), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with G DATA's API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithGDATA(settings) {
                // Checks if the provider is enabled
                if (!settings.gDataEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "gData")) {
                    console.debug(`[G DATA] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "gData")) {
                    console.debug(`[G DATA] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "gData"), ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "gData")) {
                    console.debug(`[G DATA] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "gData", tabId);

                // Adds a small delay to prevent overwhelming the API
                // Ignored if all official partners are disabled
                if (settings.adGuardSecurityEnabled || settings.adGuardFamilyEnabled ||
                    settings.alphaMountainEnabled || settings.controlDSecurityEnabled ||
                    settings.controlDFamilyEnabled || settings.precisionSecEnabled) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }

                const apiUrl = "https://dlarray-bp-europ-secsrv069.gdatasecurity.de/url/v3";

                const payload = {
                    "REVOKEID": 0,
                    "CLIENT": "EXED",
                    "CLV": gDataKey,
                    "URLS": [url]
                };

                try {
                    const response = await fetch(apiUrl, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json"
                        },
                        body: JSON.stringify(payload),
                        signal
                    });

                    // Return early if the response is not OK
                    if (!response.ok) {
                        console.warn(`[G DATA] Returned early: ${response.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.text();

                    // Phishing
                    if (data.includes("\"PHISHING\"")) {
                        console.debug(`[G DATA] Added URL to blocked cache: ${url}`);
                        BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "gData", ProtectionResult.ResultType.PHISHING);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.PHISHING, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Malicious
                    if (data.includes("\"MALWARE\"")) {
                        console.debug(`[G DATA] Added URL to blocked cache: ${url}`);
                        BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "gData", ProtectionResult.ResultType.MALICIOUS);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Safe/Allowed
                    if (data.includes("\"TRUSTED\"") ||
                        data.includes("\"WHITELIST\"") ||
                        data.includes("\"URLS\":[{}]}")) {
                        console.debug(`[G DATA] Added URL to allowed cache: ${url}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "gData");
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Unexpected result
                    console.warn(`[G DATA] Returned an unexpected result for URL ${url}: ${data}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[G DATA] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.G_DATA), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with SmartScreen's API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithSmartScreen(settings) {
                // Checks if the provider is enabled
                if (!settings.smartScreenEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "smartScreen")) {
                    console.debug(`[SmartScreen] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "smartScreen")) {
                    console.debug(`[SmartScreen] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "smartScreen"), ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "smartScreen")) {
                    console.debug(`[SmartScreen] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "smartScreen", tabId);

                // Adds a small delay to prevent overwhelming the API
                // Ignored if all official partners are disabled
                if (settings.adGuardSecurityEnabled || settings.adGuardFamilyEnabled ||
                    settings.alphaMountainEnabled || settings.controlDSecurityEnabled ||
                    settings.controlDFamilyEnabled || settings.precisionSecEnabled) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }

                // Prepare request data
                const requestData = JSON.stringify({
                    destination: {
                        uri: UrlHelpers.normalizeHostname(urlHostname + urlPathname)
                    }
                });

                // Generate the hash and authorization header
                const {hash, key} = SmartScreenUtil.hash(requestData);
                const authHeader = `SmartScreenHash ${btoa(JSON.stringify({
                    authId: smartScreenKey,
                    hash,
                    key
                }))}`;

                try {
                    const response = await fetch("https://bf.smartscreen.microsoft.com/api/browser/Navigate/1", {
                        method: "POST",
                        credentials: "omit",
                        headers: {
                            "Content-Type": "application/json; charset=utf-8",
                            Authorization: authHeader
                        },
                        body: requestData,
                        signal
                    });

                    // Return early if the response is not OK
                    if (!response.ok) {
                        console.warn(`[SmartScreen] Returned early: ${response.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.json();
                    const {responseCategory} = data;

                    switch (responseCategory) {
                        case "TechScam":
                        case "Phishing":
                            console.debug(`[SmartScreen] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "smartScreen", ProtectionResult.ResultType.PHISHING);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.PHISHING, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                            break;

                        case "Exploit":
                        case "Malicious":
                            console.debug(`[SmartScreen] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "smartScreen", ProtectionResult.ResultType.MALICIOUS);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                            break;

                        case "Untrusted":
                            console.debug(`[SmartScreen] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "smartScreen", ProtectionResult.ResultType.UNTRUSTED);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.UNTRUSTED, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                            break;

                        case "Allowed":
                            console.debug(`[SmartScreen] Added URL to allowed cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "smartScreen");
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                            break;

                        default:
                            console.warn(`[SmartScreen] Returned an unexpected result for URL ${url}: ${JSON.stringify(data)}`);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                            break;
                    }
                } catch (error) {
                    console.debug(`[SmartScreen] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.SMARTSCREEN), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with Norton's API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithNorton(settings) {
                // Checks if the provider is enabled
                if (!settings.nortonEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "norton")) {
                    console.debug(`[Norton] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "norton")) {
                    console.debug(`[Norton] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "norton"), ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "norton")) {
                    console.debug(`[Norton] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "norton", tabId);

                // Adds a small delay to prevent overwhelming the API
                // Ignored if all official partners are disabled
                if (settings.adGuardSecurityEnabled || settings.adGuardFamilyEnabled ||
                    settings.alphaMountainEnabled || settings.controlDSecurityEnabled ||
                    settings.controlDFamilyEnabled || settings.precisionSecEnabled) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }

                const apiUrl = `https://ratings-wrs.norton.com/brief?url=${encodeURIComponent(url)}`;

                try {
                    const response = await fetch(apiUrl, {
                        method: "GET",
                        signal
                    });

                    // Return early if the response is not OK
                    if (!response.ok) {
                        console.warn(`[Norton] Returned early: ${response.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                        return;
                    }

                    const data = await response.text();

                    // Malicious
                    if (data.includes('r="b"')) {
                        console.debug(`[Norton] Added URL to blocked cache: ${url}`);
                        BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "norton", ProtectionResult.ResultType.MALICIOUS);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Safe/Trusted
                    if (data.includes('r="g"') ||
                        data.includes('r="r"') ||
                        data.includes('r="w"') ||
                        data.includes('r="u"')) {
                        console.debug(`[Norton] Added URL to allowed cache: ${url}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "norton");
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                        return;
                    }

                    // Unexpected result
                    console.warn(`[Norton] Returned an unexpected result for URL ${url}: ${data}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Norton] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.NORTON), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with CERT-EE's DNS API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithCERTEE(settings) {
                // Checks if the provider is enabled
                if (!settings.certEEEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "certEE")) {
                    console.debug(`[CERT-EE] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CERT_EE), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "certEE")) {
                    console.debug(`[CERT-EE] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "certEE"), ProtectionResult.ResultOrigin.CERT_EE), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "certEE")) {
                    console.debug(`[CERT-EE] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CERT_EE), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "certEE", tabId);

                // Adds a small delay to prevent overwhelming the API
                // Ignored if all official partners are disabled
                if (settings.adGuardSecurityEnabled || settings.adGuardFamilyEnabled ||
                    settings.alphaMountainEnabled || settings.controlDSecurityEnabled ||
                    settings.controlDFamilyEnabled || settings.precisionSecEnabled) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://dns.cert.ee/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Returns early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[CERT-EE] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CERT_EE), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0 &&
                        nonFilteringData.Answer &&
                        nonFilteringData.Answer.length > 0) {

                        // CERT-EE's way of blocking the domain.
                        if (filteringDataString.endsWith("180,0,0,9,58,128")) {
                            console.debug(`[CERT-EE] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "certEE", ProtectionResult.ResultType.MALICIOUS);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CERT_EE), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[CERT-EE] Added URL to allowed cache: ${url}`);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "certEE");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CERT_EE), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[CERT-EE] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CERT_EE), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with CleanBrowsing's Security DNS API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithCleanBrowsingSecurity(settings) {
                // Checks if the provider is enabled
                if (!settings.cleanBrowsingSecurityEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "cleanBrowsingSecurity")) {
                    console.debug(`[CleanBrowsing Security] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CLEANBROWSING_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "cleanBrowsingSecurity")) {
                    console.debug(`[CleanBrowsing Security] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "cleanBrowsingSecurity"), ProtectionResult.ResultOrigin.CLEANBROWSING_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "cleanBrowsingSecurity")) {
                    console.debug(`[CleanBrowsing Security] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CLEANBROWSING_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "cleanBrowsingSecurity", tabId);

                // Adds a small delay to prevent overwhelming the API
                // Ignored if all official partners are disabled
                if (settings.adGuardSecurityEnabled || settings.adGuardFamilyEnabled ||
                    settings.alphaMountainEnabled || settings.controlDSecurityEnabled ||
                    settings.controlDFamilyEnabled || settings.precisionSecEnabled) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://doh.cleanbrowsing.org/doh/security-filter/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Returns early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[CleanBrowsing Security] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLEANBROWSING_SECURITY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0 &&
                        nonFilteringData.Answer &&
                        nonFilteringData.Answer.length > 0) {

                        // CleanBrowsing's way of blocking the domain.
                        if (filteringData[3] === 131) {
                            console.debug(`[CleanBrowsing Security] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "cleanBrowsingSecurity", ProtectionResult.ResultType.MALICIOUS);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CLEANBROWSING_SECURITY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[CleanBrowsing Security] Added URL to allowed cache: ${url}`);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "cleanBrowsingSecurity");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CLEANBROWSING_SECURITY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[CleanBrowsing Security] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLEANBROWSING_SECURITY), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with CleanBrowsing's Family DNS API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithCleanBrowsingFamily(settings) {
                // Checks if the provider is enabled
                if (!settings.cleanBrowsingFamilyEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "cleanBrowsingFamily")) {
                    console.debug(`[CleanBrowsing Family] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CLEANBROWSING_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "cleanBrowsingFamily")) {
                    console.debug(`[CleanBrowsing Family] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "cleanBrowsingFamily"), ProtectionResult.ResultOrigin.CLEANBROWSING_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "cleanBrowsingFamily")) {
                    console.debug(`[CleanBrowsing Family] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CLEANBROWSING_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "cleanBrowsingFamily", tabId);

                // Adds a small delay to prevent overwhelming the API
                // Ignored if all official partners are disabled
                if (settings.adGuardSecurityEnabled || settings.adGuardFamilyEnabled ||
                    settings.alphaMountainEnabled || settings.controlDSecurityEnabled ||
                    settings.controlDFamilyEnabled || settings.precisionSecEnabled) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://doh.cleanbrowsing.org/doh/adult-filter/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Returns early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[CleanBrowsing Family] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLEANBROWSING_FAMILY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0 &&
                        nonFilteringData.Answer &&
                        nonFilteringData.Answer.length > 0) {

                        // CleanBrowsing's way of blocking the domain.
                        if (filteringData[3] === 131) {
                            console.debug(`[CleanBrowsing Family] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "cleanBrowsingFamily", ProtectionResult.ResultType.ADULT_CONTENT);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ADULT_CONTENT, ProtectionResult.ResultOrigin.CLEANBROWSING_FAMILY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[CleanBrowsing Family] Added URL to allowed cache: ${url}`);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "cleanBrowsingFamily");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CLEANBROWSING_FAMILY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[CleanBrowsing Family] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLEANBROWSING_FAMILY), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with Cloudflare's Security DNS APIs.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithCloudflareSecurity(settings) {
                // Checks if the provider is enabled
                if (!settings.cloudflareSecurityEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "cloudflareSecurity")) {
                    console.debug(`[Cloudflare Security] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CLOUDFLARE_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "cloudflareSecurity")) {
                    console.debug(`[Cloudflare Security] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "cloudflareSecurity"), ProtectionResult.ResultOrigin.CLOUDFLARE_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "cloudflareSecurity")) {
                    console.debug(`[Cloudflare Security] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CLOUDFLARE_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "cloudflareSecurity", tabId);

                // Adds a small delay to prevent overwhelming the API
                // Ignored if all official partners are disabled
                if (settings.adGuardSecurityEnabled || settings.adGuardFamilyEnabled ||
                    settings.alphaMountainEnabled || settings.controlDSecurityEnabled ||
                    settings.controlDFamilyEnabled || settings.precisionSecEnabled) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }

                const filteringURL = `https://security.cloudflare-dns.com/dns-query?name=${encodeURIComponent(urlHostname)}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Returns early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[Cloudflare Security] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLOUDFLARE_SECURITY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = await filteringResponse.json();
                    const filteringDataString = JSON.stringify(filteringData);
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0 &&
                        nonFilteringData.Answer &&
                        nonFilteringData.Answer.length > 0) {

                        // Cloudflare's way of blocking the domain.
                        if (filteringDataString.includes("EDE(16): Censored") ||
                            filteringDataString.includes("\"TTL\":60,\"data\":\"0.0.0.0\"")) {
                            console.debug(`[Cloudflare Security] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "cloudflareSecurity", ProtectionResult.ResultType.MALICIOUS);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.CLOUDFLARE_SECURITY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[Cloudflare Security] Added URL to allowed cache: ${url}`);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "cloudflareSecurity");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CLOUDFLARE_SECURITY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Cloudflare Security] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLOUDFLARE_SECURITY), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with Cloudflare's Family DNS APIs.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithCloudflareFamily(settings) {
                // Checks if the provider is enabled
                if (!settings.cloudflareFamilyEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "cloudflareFamily")) {
                    console.debug(`[Cloudflare Family] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.CLOUDFLARE_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "cloudflareFamily")) {
                    console.debug(`[Cloudflare Family] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "cloudflareFamily"), ProtectionResult.ResultOrigin.CLOUDFLARE_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "cloudflareFamily")) {
                    console.debug(`[Cloudflare Family] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.CLOUDFLARE_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "cloudflareFamily", tabId);

                // Adds a small delay to prevent overwhelming the API
                // Ignored if all official partners are disabled
                if (settings.adGuardSecurityEnabled || settings.adGuardFamilyEnabled ||
                    settings.alphaMountainEnabled || settings.controlDSecurityEnabled ||
                    settings.controlDFamilyEnabled || settings.precisionSecEnabled) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }

                const filteringURL = `https://family.cloudflare-dns.com/dns-query?name=${encodeURIComponent(urlHostname)}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Returns early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[Cloudflare Family] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLOUDFLARE_FAMILY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = await filteringResponse.json();
                    const filteringDataString = JSON.stringify(filteringData);
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0 &&
                        nonFilteringData.Answer &&
                        nonFilteringData.Answer.length > 0) {

                        // Cloudflare's way of blocking the domain.
                        if (filteringDataString.includes("EDE(16): Censored") ||
                            filteringDataString.includes("\"TTL\":60,\"data\":\"0.0.0.0\"")) {
                            console.debug(`[Cloudflare Family] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "cloudflareFamily", ProtectionResult.ResultType.ADULT_CONTENT);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ADULT_CONTENT, ProtectionResult.ResultOrigin.CLOUDFLARE_FAMILY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[Cloudflare Family] Added URL to allowed cache: ${url}`);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "cloudflareFamily");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.CLOUDFLARE_FAMILY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Cloudflare Family] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.CLOUDFLARE_FAMILY), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with DNS0's Security DNS API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithDNS0Security(settings) {
                // Checks if the provider is enabled
                if (!settings.dns0SecurityEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "dns0Security")) {
                    console.debug(`[DNS0.eu Security] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.DNS0_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "dns0Security")) {
                    console.debug(`[DNS0.eu Security] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "dns0Security"), ProtectionResult.ResultOrigin.DNS0_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "dns0Security")) {
                    console.debug(`[DNS0.eu Security] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.DNS0_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "dns0Security", tabId);

                // Adds a small delay to prevent overwhelming the API
                // Ignored if all official partners are disabled
                if (settings.adGuardSecurityEnabled || settings.adGuardFamilyEnabled ||
                    settings.alphaMountainEnabled || settings.controlDSecurityEnabled ||
                    settings.controlDFamilyEnabled || settings.precisionSecEnabled) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }

                const filteringURL = `https://dns0.eu/dns-query?name=${encodeURIComponent(urlHostname)}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Returns early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[DNS0.eu Security] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.DNS0_SECURITY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = await filteringResponse.json();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0 &&
                        nonFilteringData.Answer &&
                        nonFilteringData.Answer.length > 0) {

                        // DNS0's way of blocking the domain.
                        if (filteringData.Status === 3) {
                            console.debug(`[DNS0.eu Security] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "dns0Security", ProtectionResult.ResultType.MALICIOUS);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.DNS0_SECURITY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[DNS0.eu Security] Added URL to allowed cache: ${url}`);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "dns0Security");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.DNS0_SECURITY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[DNS0.eu Security] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.DNS0_SECURITY), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with DNS0's Family DNS API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithDNS0Family(settings) {
                // Checks if the provider is enabled
                if (!settings.dns0FamilyEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "dns0Family")) {
                    console.debug(`[DNS0.eu Family] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.DNS0_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "dns0Family")) {
                    console.debug(`[DNS0.eu Family] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "dns0Family"), ProtectionResult.ResultOrigin.DNS0_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "dns0Family")) {
                    console.debug(`[DNS0.eu Family] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.DNS0_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "dns0Family", tabId);

                // Adds a small delay to prevent overwhelming the API
                // Ignored if all official partners are disabled
                if (settings.adGuardSecurityEnabled || settings.adGuardFamilyEnabled ||
                    settings.alphaMountainEnabled || settings.controlDSecurityEnabled ||
                    settings.controlDFamilyEnabled || settings.precisionSecEnabled) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }

                const filteringURL = `https://kids.dns0.eu/dns-query?name=${encodeURIComponent(urlHostname)}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Returns early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[DNS0.eu Family] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.DNS0_FAMILY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = await filteringResponse.json();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0 &&
                        nonFilteringData.Answer &&
                        nonFilteringData.Answer.length > 0) {

                        // DNS0's way of blocking the domain.
                        if (filteringData.Status === 3) {
                            console.debug(`[DNS0.eu Family] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "dns0Family", ProtectionResult.ResultType.ADULT_CONTENT);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ADULT_CONTENT, ProtectionResult.ResultOrigin.DNS0_FAMILY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[DNS0.eu Family] Added URL to allowed cache: ${url}`);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "dns0Family");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.DNS0_FAMILY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[DNS0.eu Family] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.DNS0_FAMILY), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with DNS4EU's Security DNS API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithDNS4EUSecurity(settings) {
                // Checks if the provider is enabled
                if (!settings.dns4EUSecurityEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "dns4EUSecurity")) {
                    console.debug(`[DNS4EU Security] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.DNS4EU_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "dns4EUSecurity")) {
                    console.debug(`[DNS4EU Security] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "dns4EUSecurity"), ProtectionResult.ResultOrigin.DNS4EU_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "dns4EUSecurity")) {
                    console.debug(`[DNS4EU Security] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.DNS4EU_SECURITY), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "dns4EUSecurity", tabId);

                // Adds a small delay to prevent overwhelming the API
                // Ignored if all official partners are disabled
                if (settings.adGuardSecurityEnabled || settings.adGuardFamilyEnabled ||
                    settings.alphaMountainEnabled || settings.controlDSecurityEnabled ||
                    settings.controlDFamilyEnabled || settings.precisionSecEnabled) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://protective.joindns4.eu/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Returns early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[DNS4EU Security] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.DNS4EU_SECURITY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0 &&
                        nonFilteringData.Answer &&
                        nonFilteringData.Answer.length > 0) {

                        // DNS4EU's way of blocking the domain.
                        if (filteringDataString.endsWith("0,1,0,0,0,1,0,4,51,15,69,11")) {
                            console.debug(`[DNS4EU Security] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "dns4EUSecurity", ProtectionResult.ResultType.MALICIOUS);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.DNS4EU_SECURITY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[DNS4EU Security] Added URL to allowed cache: ${url}`);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "dns4EUSecurity");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.DNS4EU_SECURITY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[DNS4EU Security] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.DNS4EU_SECURITY), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with DNS4EU's Family DNS API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithDNS4EUFamily(settings) {
                // Checks if the provider is enabled
                if (!settings.dns4EUFamilyEnabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "dns4EUFamily")) {
                    console.debug(`[DNS4EU Family] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.DNS4EU_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "dns4EUFamily")) {
                    console.debug(`[DNS4EU Family] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "dns4EUFamily"), ProtectionResult.ResultOrigin.DNS4EU_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "dns4EUFamily")) {
                    console.debug(`[DNS4EU Family] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.DNS4EU_FAMILY), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "dns4EUFamily", tabId);

                // Adds a small delay to prevent overwhelming the API
                // Ignored if all official partners are disabled
                if (settings.adGuardSecurityEnabled || settings.adGuardFamilyEnabled ||
                    settings.alphaMountainEnabled || settings.controlDSecurityEnabled ||
                    settings.controlDFamilyEnabled || settings.precisionSecEnabled) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://child.joindns4.eu/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Returns early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[DNS4EU Family] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.DNS4EU_FAMILY), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const filteringDataString = Array.from(filteringData).toString();
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0 &&
                        nonFilteringData.Answer &&
                        nonFilteringData.Answer.length > 0) {

                        // DNS4EU's way of blocking the domain.
                        if (filteringDataString.endsWith("0,1,0,0,0,1,0,4,51,15,69,11")) {
                            console.debug(`[DNS4EU Family] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "dns4EUFamily", ProtectionResult.ResultType.ADULT_CONTENT);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.ADULT_CONTENT, ProtectionResult.ResultOrigin.DNS4EU_FAMILY), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[DNS4EU Family] Added URL to allowed cache: ${url}`);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "dns4EUFamily");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.DNS4EU_FAMILY), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[DNS4EU Family] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.DNS4EU_FAMILY), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Checks the URL with Quad9's DNS API.
             *
             * @param {Object} settings - The settings object containing user preferences.
             */
            async function checkUrlWithQuad9(settings) {
                // Checks if the provider is enabled
                if (!settings.quad9Enabled) {
                    return;
                }

                // Checks if the URL is in the allowed cache
                if (isUrlInAllowedCache(urlObject, urlHostname, "quad9")) {
                    console.debug(`[Quad9] URL is already allowed: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.KNOWN_SAFE, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the blocked cache
                if (isUrlInBlockedCache(urlObject, urlHostname, "quad9")) {
                    console.debug(`[Quad9] URL is already blocked: ${url}`);
                    callback(new ProtectionResult(url, BrowserProtection.cacheManager.getBlockedResultType(url, "quad9"), ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                    return;
                }

                // Checks if the URL is in the processing cache
                if (isUrlInProcessingCache(urlObject, urlHostname, "quad9")) {
                    console.debug(`[Quad9] URL is already processing: ${url}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.WAITING, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                    return;
                }

                // Adds the URL to the processing cache to prevent duplicate requests
                BrowserProtection.cacheManager.addUrlToProcessingCache(urlObject, "quad9", tabId);

                // Adds a small delay to prevent overwhelming the API
                // Ignored if all official partners are disabled
                if (settings.adGuardSecurityEnabled || settings.adGuardFamilyEnabled ||
                    settings.alphaMountainEnabled || settings.controlDSecurityEnabled ||
                    settings.controlDFamilyEnabled || settings.precisionSecEnabled) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }

                const encodedQuery = encodeDnsQuery(encodeURIComponent(urlHostname));
                const filteringURL = `https://dns.quad9.net/dns-query?dns=${encodedQuery}`;

                try {
                    const filteringResponse = await fetch(filteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-message"
                        },
                        signal
                    });

                    const nonFilteringResponse = await fetch(nonFilteringURL, {
                        method: "GET",
                        headers: {
                            "Accept": "application/dns-json"
                        },
                        signal
                    });

                    // Returns early if one or more of the responses is not OK
                    if (!filteringResponse.ok || !nonFilteringResponse.ok) {
                        console.warn(`[Quad9] Returned early: ${filteringResponse.status}`);
                        callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                        return;
                    }

                    const filteringData = new Uint8Array(await filteringResponse.arrayBuffer());
                    const nonFilteringData = await nonFilteringResponse.json();

                    // If the non-filtering domain returns NOERROR...
                    if (nonFilteringData.Status === 0 &&
                        nonFilteringData.Answer &&
                        nonFilteringData.Answer.length > 0) {

                        // Quad9's way of blocking the domain.
                        if (filteringData[3] === 3) {
                            console.debug(`[Quad9] Added URL to blocked cache: ${url}`);
                            BrowserProtection.cacheManager.addUrlToBlockedCache(urlObject, "quad9", ProtectionResult.ResultType.MALICIOUS);
                            callback(new ProtectionResult(url, ProtectionResult.ResultType.MALICIOUS, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                            return;
                        }
                    }

                    // Otherwise, the domain is either invalid or not blocked.
                    console.debug(`[Quad9] Added URL to allowed cache: ${url}`);
                    BrowserProtection.cacheManager.addUrlToAllowedCache(urlObject, "quad9");
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.ALLOWED, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                } catch (error) {
                    console.debug(`[Quad9] Failed to check URL ${url}: ${error}`);
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.QUAD9), (new Date()).getTime() - startTime);
                }
            }

            /**
             * Encodes a DNS query for the given domain and type.
             *
             * @param {string} domain - The domain to encode.
             * @param {number} type - The type of DNS record (default is 1 for A record).
             * @return {string} - The base64url encoded DNS query.
             */
            function encodeDnsQuery(domain, type = 1) {
                // Creates DNS query components
                const header = new Uint8Array([
                    0x00, 0x00, // ID (0)
                    0x01, 0x00, // Flags: standard query
                    0x00, 0x01, // QDCOUNT: 1 question
                    0x00, 0x00, // ANCOUNT: 0 answers
                    0x00, 0x00, // NSCOUNT: 0 authority records
                    0x00, 0x00  // ARCOUNT: 0 additional records
                ]);

                // Encodes domain parts
                const domainParts = domain.split('.');
                let domainBuffer = [];

                for (const part of domainParts) {
                    domainBuffer.push(part.length);

                    for (let i = 0; i < part.length; i++) {
                        domainBuffer.push(part.charCodeAt(i));
                    }
                }

                // Adds terminating zero
                domainBuffer.push(0);

                // Adds QTYPE and QCLASS
                domainBuffer.push(0x00, type); // QTYPE (1 = A record)
                domainBuffer.push(0x00, 0x01); // QCLASS (1 = IN)

                // Combines the header and domain parts
                const dnsPacket = new Uint8Array([...header, ...domainBuffer]);

                // Encodes and returns the results
                return btoa(String.fromCharCode(...dnsPacket))
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=+$/, '');
            }

            /**
             * Checks if the URL is in the allowed caches.
             *
             * @param urlObject - The URL object.
             * @param hostname - The hostname of the URL.
             * @param provider - The provider to check the allowed cache against.
             * @returns {boolean} - True if the URL is in the allowed cache, false otherwise.
             */
            function isUrlInAllowedCache(urlObject, hostname, provider) {
                return BrowserProtection.cacheManager.isUrlInAllowedCache(urlObject, provider) ||
                    BrowserProtection.cacheManager.isStringInAllowedCache(`${hostname} (allowed)`, provider);
            }

            /**
             * Checks if the URL is in the blocked caches.
             *
             * @param urlObject - The URL object.
             * @param hostname - The hostname of the URL.
             * @param provider - The provider to check the blocked cache against.
             * @returns {boolean} - True if the URL is in the blocked cache, false otherwise.
             */
            function isUrlInBlockedCache(urlObject, hostname, provider) {
                return BrowserProtection.cacheManager.isUrlInBlockedCache(urlObject, provider);
            }

            /**
             * Checks if the URL is in the processing caches.
             *
             * @param urlObject - The URL object.
             * @param hostname - The hostname of the URL.
             * @param provider - The provider to check the processing cache against.
             * @returns {boolean} - True if the URL is in the processing cache, false otherwise.
             */
            function isUrlInProcessingCache(urlObject, hostname, provider) {
                return BrowserProtection.cacheManager.isUrlInProcessingCache(urlObject, provider);
            }

            // Call all the check functions asynchronously
            Settings.get(settings => {
                // Official Partners
                checkUrlWithAdGuardSecurity(settings);
                checkUrlWithAdGuardFamily(settings);
                checkUrlWithAlphaMountain(settings);
                checkUrlWithControlDSecurity(settings);
                checkUrlWithControlDFamily(settings);
                checkUrlWithPrecisionSec(settings);

                // Non-Partnered Providers
                checkUrlWithGDATA(settings);
                checkUrlWithSmartScreen(settings);
                checkUrlWithNorton(settings);
                checkUrlWithCERTEE(settings);
                checkUrlWithCleanBrowsingSecurity(settings);
                checkUrlWithCleanBrowsingFamily(settings);
                checkUrlWithCloudflareSecurity(settings);
                checkUrlWithCloudflareFamily(settings);
                checkUrlWithDNS0Security(settings);
                checkUrlWithDNS0Family(settings);
                checkUrlWithDNS4EUSecurity(settings);
                checkUrlWithDNS4EUFamily(settings);
                checkUrlWithQuad9(settings);
            });

            // Cleans up controllers for tabs that no longer exist
            cleanupTabControllers();
        }
    };
})();

// Initializes the cache manager
BrowserProtection.cacheManager = new CacheManager();
