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

// Manages the cache for the allowed protection providers.
class CacheManager {
    constructor(allowedKey = 'allowedCache',
                blockedKey = 'blockedCache',
                processingKey = 'processingCache',
                debounceDelay = 5000) {
        Settings.get(settings => {
            this.expirationTime = settings.cacheExpirationSeconds;
            this.allowedKey = allowedKey;
            this.blockedKey = blockedKey;
            this.processingKey = processingKey;
            this.debounceDelay = debounceDelay;
            this.timeoutId = null;

            const providers = [
                // Official Partners
                "adGuardSecurity", "adGuardFamily",
                "alphaMountain",
                "controlDSecurity", "controlDFamily",
                "precisionSec",

                // Non-Partnered Providers
                "certEE",
                "ciraSecurity", "ciraFamily",
                "cleanBrowsingSecurity", "cleanBrowsingFamily", "cleanBrowsingAdult",
                "cloudflareSecurity", "cloudflareFamily",
                "dns0Security", "dns0Kids",
                "dns4EUSecurity", "dns4EUFamily",
                "gData",
                "smartScreen",
                "norton",
                "openDNSSecurity", "openDNSFamilyShield",
                "quad9",
                "switchCH"
            ];

            this.allowedCaches = {};
            this.blockedCaches = {};
            this.processingCaches = {};

            // Initialize caches for each provider
            providers.forEach(name => {
                this.allowedCaches[name] = new Map();
                this.blockedCaches[name] = new Map();
                this.processingCaches[name] = new Map();
            });

            // Load allowed caches (without tabId) from local storage
            Storage.getFromLocalStore(this.allowedKey, storedAllowed => {
                if (!storedAllowed) {
                    return;
                }

                Object.keys(this.allowedCaches).forEach(name => {
                    if (storedAllowed[name]) {
                        this.allowedCaches[name] = new Map(Object.entries(storedAllowed[name]));
                    }
                });
            });

            // Load blocked caches (without tabId) from local storage
            Storage.getFromLocalStore(this.blockedKey, storedBlocked => {
                if (!storedBlocked) {
                    return;
                }

                Object.keys(this.blockedCaches).forEach(name => {
                    if (storedBlocked[name]) {
                        this.blockedCaches[name] = new Map(
                            Object.entries(storedBlocked[name]).map(([url, entry]) => [
                                url,
                                {exp: entry.exp, resultType: entry.resultType}
                            ])
                        );
                    }
                });
            });

            // Load processing caches (with tabId) from session storage
            Storage.getFromSessionStore(this.processingKey, storedProcessing => {
                if (!storedProcessing) {
                    return;
                }

                Object.keys(this.processingCaches).forEach(name => {
                    if (storedProcessing[name]) {
                        this.processingCaches[name] = new Map(Object.entries(storedProcessing[name]));
                    }
                });
            });
        });
    }

    /**
     * Update the caches that use localStorage (allowed and blocked caches).
     *
     * @param debounced - If true, updates will be debounced to avoid frequent writes.
     */
    updateLocalStorage(debounced) {
        // Checks if the allowed caches are valid
        if (!this.allowedCaches || typeof this.allowedCaches !== 'object') {
            console.warn('allowedCache is not defined or not an object');
            return;
        }

        // Checks if the blocked caches are valid
        if (!this.blockedCaches || typeof this.blockedCaches !== 'object') {
            console.warn('blockedCache is not defined or not an object');
            return;
        }

        const write = () => {
            const allowedOut = {};
            const blockedOut = {};

            Object.keys(this.allowedCaches).forEach(name => {
                allowedOut[name] = Object.fromEntries(this.allowedCaches[name]);
            });

            Object.keys(this.blockedCaches).forEach(name => {
                blockedOut[name] = Object.fromEntries(
                    Array.from(this.blockedCaches[name], ([url, entry]) => [
                        url,
                        {exp: entry.exp, resultType: entry.resultType}
                    ])
                );
            });

            Storage.setToLocalStore(this.allowedKey, allowedOut);
            Storage.setToLocalStore(this.blockedKey, blockedOut);
        };

        if (debounced) {
            if (!this.timeoutId) {
                this.timeoutId = setTimeout(() => {
                    this.timeoutId = null;
                    write();
                }, this.debounceDelay);
            }
        } else {
            write();
        }
    }

    /**
     * Update the caches that use sessionStorage (processing caches).
     *
     * @param debounced - If true, updates will be debounced to avoid frequent writes.
     */
    updateSessionStorage(debounced) {
        // Checks if the processing cache is valid
        if (!this.processingCaches || typeof this.processingCaches !== 'object') {
            console.warn('processingCache is not defined or not an object');
            return;
        }

        const write = () => {
            const out = {};

            Object.keys(this.processingCaches).forEach(name => {
                out[name] = Object.fromEntries(this.processingCaches[name]);
            });

            Storage.setToSessionStore(this.processingKey, out);
        };

        if (debounced) {
            if (!this.timeoutId) {
                this.timeoutId = setTimeout(() => {
                    this.timeoutId = null;
                    write();
                }, this.debounceDelay);
            }
        } else {
            write();
        }
    }

    /**
     * Clears all allowed caches.
     */
    clearAllowedCache() {
        // Returns if the allowed cache is not defined.
        if (!this.allowedCaches || typeof this.allowedCaches !== 'object') {
            console.warn('allowedCache is not defined or not an object');
            return;
        }

        Object.values(this.allowedCaches).forEach(m => m.clear());
        this.updateLocalStorage(false);
    }

    /**
     * Clears all blocked caches.
     */
    clearBlockedCache() {
        // Returns if the blocked cache is not defined.
        if (!this.blockedCaches || typeof this.blockedCaches !== 'object') {
            console.warn('blockedCache is not defined or not an object');
            return;
        }

        Object.values(this.blockedCaches).forEach(m => m.clear());
        this.updateLocalStorage(false);
    }

    /**
     * Clears all processing caches.
     */
    clearProcessingCache() {
        // Checks if the processing cache is valid
        if (!this.processingCaches || typeof this.processingCaches !== 'object') {
            console.warn('processingCache is not defined or not an object');
            return;
        }

        Object.values(this.processingCaches).forEach(m => m.clear());
        this.updateSessionStorage(false);
    }

    /**
     * Cleans up expired entries from all caches.
     *
     * @returns {number} - The number of expired entries removed from all caches.
     */
    cleanExpiredEntries() {
        const now = Date.now();
        let removed = 0;

        const cleanGroup = (group, onDirty) => {
            Object.values(group).forEach(map => {
                for (const [key, value] of map.entries()) {
                    const expTime = value && typeof value === 'object' && 'exp' in value ? value.exp : value;

                    // Removes expired keys from the map
                    // Ignores keys with expiration time of 0 (indicating no expiration)
                    if (expTime !== 0 && expTime < now) {
                        map.delete(key);
                        removed++;
                    }
                }
            });

            // Sets the dirty flag if keys were removed
            if (removed > 0) {
                onDirty(true);
            }
        };

        cleanGroup(this.allowedCaches, () => this.updateLocalStorage(true));
        cleanGroup(this.blockedCaches, () => this.updateLocalStorage(true));
        cleanGroup(this.processingCaches, () => this.updateSessionStorage(true));
        return removed;
    }

    /**
     * Normalizes a URL by removing the trailing slash and normalizing the hostname.
     *
     * @param url {string|URL} - The URL to normalize, can be a string or a URL object.
     * @returns {string|string} - The normalized URL as a string.
     */
    normalizeUrl(url) {
        const u = typeof url === "string" ? new URL(url) : url;
        let norm = UrlHelpers.normalizeHostname(u.hostname + u.pathname);
        return norm.endsWith("/") ? norm.slice(0, -1) : norm;
    }

    /**
     * Checks if a URL is in the allowed cache for a specific provider.
     *
     * @param url {string|URL} - The URL to check, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec", "smartScreen").
     * @returns {boolean} - Returns true if the URL is in the allowed cache and not expired, false otherwise.
     */
    isUrlInAllowedCache(url, name) {
        // Returns if the allowed cache is not defined.
        if (!this.allowedCaches || typeof this.allowedCaches !== 'object') {
            console.warn('allowedCache is not defined or not an object');
            return false;
        }

        try {
            const key = this.normalizeUrl(url);
            const map = this.allowedCaches[name];

            if (!map) {
                return false;
            }

            if (map.has(key)) {
                const exp = map.get(key);

                if (exp > Date.now()) {
                    return true;
                }

                map.delete(key);
                this.updateLocalStorage(true);
            }
        } catch (error) {
            console.error(error);
        }
        return false;
    }

    /**
     * Checks if a string is in the allowed cache for a specific provider.
     *
     * @param str {string} - The string to check.
     * @param name {string} - The name of the provider (e.g., "precisionSec", "smartScreen").
     * @returns {boolean} - Returns true if the string is in the allowed cache and not expired, false otherwise.
     */
    isStringInAllowedCache(str, name) {
        // Returns if the allowed cache is not defined.
        if (!this.allowedCaches || typeof this.allowedCaches !== 'object') {
            console.warn('allowedCache is not defined or not an object');
            return false;
        }

        try {
            const map = this.allowedCaches[name];

            if (!map) {
                return false;
            }

            if (map.has(str)) {
                return true;
            }
        } catch (error) {
            console.error(error);
        }
        return false;
    }

    /**
     * Add a URL to the allowed cache for a specific provider.
     *
     * @param url {string|URL} - The URL to add, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec", "smartScreen").
     */
    addUrlToAllowedCache(url, name) {
        // Returns if the allowed cache is not defined.
        if (!this.allowedCaches || typeof this.allowedCaches !== 'object') {
            console.warn('allowedCache is not defined or not an object');
            return;
        }

        try {
            const key = this.normalizeUrl(url);
            const expTime = Date.now() + this.expirationTime * 1000;

            if (this.cleanExpiredEntries() === 0) {
                this.updateLocalStorage(true);
            }

            if (name === "all") {
                Object.values(this.allowedCaches).forEach(m => m.set(key, expTime));
            } else if (this.allowedCaches[name]) {
                this.allowedCaches[name].set(key, expTime);
            } else {
                console.warn(`Cache "${name}" not found`);
            }
        } catch (error) {
            console.error(error);
        }
    }

    /**
     * Add a string key to the allowed cache for a specific provider.
     *
     * @param str {string} - The string to add.
     * @param name {string} - The name of the provider (e.g., "precisionSec", "smartScreen").
     */
    addStringToAllowedCache(str, name) {
        // Returns if the allowed cache is not defined.
        if (!this.allowedCaches || typeof this.allowedCaches !== 'object') {
            console.warn('allowedCache is not defined or not an object');
            return;
        }

        try {
            const expTime = 0;

            if (this.cleanExpiredEntries() === 0) {
                this.updateLocalStorage(true);
            }

            if (name === "all") {
                Object.values(this.allowedCaches).forEach(m => m.set(str, expTime));
            } else if (this.allowedCaches[name]) {
                this.allowedCaches[name].set(str, expTime);
            } else {
                console.warn(`Cache "${name}" not found`);
            }
        } catch (error) {
            console.error(error);
        }
    }

    /**
     * Checks if a URL is in the blocked cache for a specific provider.
     *
     * @param url {string|URL} - The URL to check, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec", "smartScreen").
     * @returns {boolean} - Returns true if the URL is in the allowed cache and not expired, false otherwise.
     */
    isUrlInBlockedCache(url, name) {
        // Returns if the blocked cache is not defined.
        if (!this.blockedCaches || typeof this.blockedCaches !== 'object') {
            console.warn('blockedCache is not defined or not an object');
            return false;
        }

        try {
            const key = this.normalizeUrl(url);
            const map = this.blockedCaches[name];

            if (!map || !map.has(key)) {
                return false;
            }

            const entry = map.get(key);

            if (entry.exp > Date.now()) {
                return true;
            }

            map.delete(key);
            this.updateLocalStorage(false);
        } catch (error) {
            console.error(error);
        }
        return false;
    }

    /**
     * Add a URL to the blocked cache for a specific provider.
     *
     * @param url {string|URL} - The URL to add, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec", "smartScreen").
     * @param resultType {string} - The resultType of the URL (e.g., "malicious", "phishing").
     */
    addUrlToBlockedCache(url, name, resultType) {
        // Returns if the blocked cache is not defined.
        if (!this.blockedCaches || typeof this.blockedCaches !== 'object') {
            console.warn('blockedCache is not defined or not an object');
            return;
        }

        try {
            const key = this.normalizeUrl(url);
            const expTime = Date.now() + this.expirationTime * 1000;

            if (this.cleanExpiredEntries() === 0) {
                this.updateLocalStorage(false);
            }

            const cache = this.blockedCaches[name];

            if (name === "all") {
                Object.values(this.blockedCaches).forEach(m =>
                    m.set(key, {exp: expTime, resultType: resultType})
                );
            } else if (cache) {
                cache.set(key, {exp: expTime, resultType: resultType});
            } else {
                console.warn(`Cache "${name}" not found`);
            }
        } catch (error) {
            console.error(error);
        }
    }

    /**
     * Get the result type of a blocked URL from the cache for a specific provider.
     *
     * @param url {string|URL} - The URL to check, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec", "smartScreen").
     * @returns {*|null} - Returns the result type (e.g., "Malicious", "Phishing") if found and not expired, null otherwise.
     */
    getBlockedResultType(url, name) {
        // Returns if the blocked cache is not defined.
        if (!this.blockedCaches || typeof this.blockedCaches !== 'object') {
            console.warn('blockedCache is not defined or not an object');
            return;
        }

        try {
            const key = this.normalizeUrl(url);
            const cache = this.blockedCaches[name];

            if (!cache || !cache.has(key)) {
                return null;
            }

            const entry = cache.get(key);

            if (entry.exp > Date.now()) {
                return entry.resultType;
            } else {
                cache.delete(key);
                this.updateLocalStorage(false);
            }
        } catch (e) {
            console.error(e);
        }
        return null;
    }

    /**
     * Remove a URL from the blocked cache for a specific provider.
     *
     * @param url {string|URL} - The URL to remove, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec", "smartScreen").
     */
    removeUrlFromBlockedCache(url, name) {
        // Returns if the blocked cache is not defined.
        if (!this.blockedCaches || typeof this.blockedCaches !== 'object') {
            console.warn('blockedCache is not defined or not an object');
            return;
        }

        try {
            const key = this.normalizeUrl(url);

            if (name === "all") {
                Object.values(this.blockedCaches).forEach(m => m.delete(key));
            } else if (this.blockedCaches[name]) {
                this.blockedCaches[name].delete(key);
            } else {
                console.warn(`Cache "${name}" not found`);
            }

            this.updateLocalStorage(false);
        } catch (e) {
            console.error(e);
        }
    }

    /**
     * Checks if a URL is in the processing cache for a specific provider.
     *
     * @param url {string|URL} - The URL to check, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec", "smartScreen").
     * @returns {boolean} - Returns true if the URL is in the processing cache and not expired, false otherwise.
     */
    isUrlInProcessingCache(url, name) {
        // Checks if the processing cache is valid
        if (!this.processingCaches || typeof this.processingCaches !== 'object') {
            console.warn('processingCaches is not defined or not an object');
            return false;
        }

        try {
            const key = this.normalizeUrl(url);
            const map = this.processingCaches[name];

            if (!map) {
                return false;
            }

            if (map.has(key)) {
                const entry = map.get(key);

                if (entry.exp > Date.now()) {
                    return true;
                }

                map.delete(key);
                this.updateSessionStorage(true);
            }
        } catch (e) {
            console.error(e);
        }
        return false;
    }

    /**
     * Add a URL to the processing cache, associating it with a specific tabId.
     *
     * @param {string|URL} url - The URL to add, can be a string or a URL object.
     * @param {string} name - The name of the provider (e.g., "precisionSec", "smartScreen").
     * @param {number} tabId - The ID of the tab associated with this URL.
     */
    addUrlToProcessingCache(url, name, tabId) {
        // Checks if the processing cache is valid
        if (!this.processingCaches || typeof this.processingCaches !== 'object') {
            console.warn('processingCaches is not defined or not an object');
            return;
        }

        try {
            const key = this.normalizeUrl(url);
            const expTime = Date.now() + this.expirationTime * 1000;

            if (this.cleanExpiredEntries() === 0) {
                this.updateSessionStorage(true);
            }

            const entry = {exp: expTime, tabId: tabId};

            if (name === "all") {
                Object.values(this.processingCaches).forEach(m => m.set(key, entry));
            } else if (this.processingCaches[name]) {
                this.processingCaches[name].set(key, entry);
            } else {
                console.warn(`Processing cache "${name}" not found`);
            }
        } catch (e) {
            console.error(e);
        }
    }

    /**
     * Remove a URL from the processing cache for a specific provider.
     *
     * @param url {string|URL} - The URL to remove, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec", "smartScreen").
     */
    removeUrlFromProcessingCache(url, name) {
        // Checks if the processing cache is valid
        if (!this.processingCaches || typeof this.processingCaches !== 'object') {
            console.warn('processingCaches is not defined or not an object');
            return;
        }

        try {
            const key = this.normalizeUrl(url);

            if (name === "all") {
                Object.values(this.processingCaches).forEach(m => m.delete(key));
            } else if (this.processingCaches[name]) {
                this.processingCaches[name].delete(key);
            } else {
                console.warn(`Processing cache "${name}" not found`);
            }

            this.updateSessionStorage(true);
        } catch (e) {
            console.error(e);
        }
    }

    /**
     * Retrieve all normalized-URL keys (or string keys) in the processing cache for a given provider
     * that are associated with the specified tabId and not yet expired.
     *
     * @param {string} name - The name of the provider (e.g., "precisionSec", "smartScreen").
     * @param {number} tabId - The ID of the tab to filter by.
     * @returns {string[]} - An array of keys (normalized URLs or strings) that match the criteria.
     */
    getKeysByTabId(name, tabId) {
        // Checks if the processing cache is valid
        if (!this.processingCaches || typeof this.processingCaches !== 'object') {
            console.warn('processingCaches is not defined or not an object');
            return null;
        }

        const results = [];
        const map = this.processingCaches[name];

        // Checks if the map is valid
        if (!map) {
            return results;
        }

        const now = Date.now();

        // Removes expired keys from the map
        for (const [key, entry] of map.entries()) {
            if (entry.tabId === tabId) {
                if (entry.exp > now) {
                    results.push(key);
                } else {
                    map.delete(key);
                }
            }
        }

        this.updateSessionStorage(true);
        return results;
    }

    /**
     * Remove all entries in the processing cache for all keys associated with a specific tabId.
     *
     * @param tabId - The ID of the tab whose entries should be removed.
     */
    removeKeysByTabId(tabId) {
        // Checks if the processing cache is valid
        if (!this.processingCaches || typeof this.processingCaches !== 'object') {
            console.warn('processingCaches is not defined or not an object');
            return;
        }

        let removedCount = 0;

        Object.keys(this.processingCaches).forEach(name => {
            const map = this.processingCaches[name];

            // Checks if the cache is valid
            if (!map) {
                return;
            }

            for (const [key, entry] of map.entries()) {
                if (entry.tabId === tabId) {
                    removedCount++;
                    map.delete(key);
                }
            }
        });

        // Persist the changes to session storage
        if (removedCount > 0) {
            console.debug(`Removed ${removedCount} entries from processing cache for tab ID ${tabId}`);
            this.updateSessionStorage(false);
        }
    }
}
