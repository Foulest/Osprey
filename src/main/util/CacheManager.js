"use strict";

// Manages the cache for the allowed protection providers.
// Updated to attach a tab ID (int) to each entry in the processing queue.
class CacheManager {
    constructor(allowedKey = 'allowedCache', processingKey = 'processingCache', debounceDelay = 5000) {
        Settings.get(settings => {
            this.expirationTime = settings.cacheExpirationSeconds;
            this.allowedKey = allowedKey;
            this.processingKey = processingKey;
            this.debounceDelay = debounceDelay;
            this.timeoutId = null;

            const providers = [
                "precisionSec", "smartScreen", "symantec", "emsisoft", "bitdefender",
                "norton", "gData", "cloudflare", "quad9", "dns0", "cleanBrowsing",
                "cira", "adGuard", "switchCH", "certEE", "controlD",
            ];

            this.allowedCaches = {};
            this.processingCaches = {};

            providers.forEach(name => {
                this.allowedCaches[name] = new Map();
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
     * Update the allowed caches in localStorage.
     *
     * @param debounced - If true, updates will be debounced to avoid frequent writes.
     */
    updateLocalStorage(debounced) {
        const write = () => {
            const out = {};

            Object.keys(this.allowedCaches).forEach(name => {
                out[name] = Object.fromEntries(this.allowedCaches[name]);
            });

            Storage.setToLocalStore(this.allowedKey, out);
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
     * Update the processing caches in sessionStorage.
     *
     * @param debounced - If true, updates will be debounced to avoid frequent writes.
     */
    updateSessionStorage(debounced) {
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
        Object.values(this.allowedCaches).forEach(m => m.clear());
        this.updateLocalStorage(false);
    }

    /**
     * Clears all processing caches.
     */
    clearProcessingCache() {
        Object.values(this.processingCaches).forEach(m => m.clear());
        this.updateSessionStorage(false);
    }

    /**
     * Cleans up expired entries from both allowed and processing caches.
     *
     * @returns {number} - The number of expired entries removed from both caches.
     */
    cleanExpiredEntries() {
        const now = Date.now();
        let removed = 0;

        const cleanGroup = (group, onDirty) => {
            Object.values(group).forEach(map => {
                for (const [key, value] of map.entries()) {
                    const expTime = (typeof value === 'number') ? value : value.exp;

                    if (expTime < now) {
                        map.delete(key);
                        removed++;
                    }
                }
            });

            if (removed > 0) {
                onDirty(true);
            }
        };

        cleanGroup(this.allowedCaches, () => this.updateLocalStorage(true));
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
        } catch (e) {
            console.error(e);
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
        try {
            const map = this.allowedCaches[name];

            if (!map) {
                return false;
            }

            if (map.has(str)) {
                const exp = map.get(str);

                if (exp > Date.now()) {
                    return true;
                }

                map.delete(str);
                this.updateLocalStorage(true);
            }
        } catch (e) {
            console.error(e);
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
        } catch (e) {
            console.error(e);
        }
    }

    /**
     * Add a string key to the allowed cache for a specific provider.
     *
     * @param str {string} - The string to add.
     * @param name {string} - The name of the provider (e.g., "precisionSec", "smartScreen").
     */
    addStringToAllowedCache(str, name) {
        try {
            const expTime = Date.now() + this.expirationTime * 1000;

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
        } catch (e) {
            console.error(e);
        }
    }

    /**
     * Remove a URL from the allowed cache for a specific provider.
     *
     * @param url {string|URL} - The URL to remove, can be a string or a URL object.
     * @param name {string} - The name of the provider (e.g., "precisionSec", "smartScreen").
     */
    removeUrlFromAllowedCache(url, name) {
        try {
            const key = this.normalizeUrl(url);

            if (name === "all") {
                Object.values(this.allowedCaches).forEach(m => m.delete(key));
            } else if (this.allowedCaches[name]) {
                this.allowedCaches[name].delete(key);
            } else {
                console.warn(`Cache "${name}" not found`);
            }

            this.updateLocalStorage(true);
        } catch (e) {
            console.error(e);
        }
    }

    /**
     * Remove a string key from the allowed cache for a specific provider.
     *
     * @param str {string} - The string to remove.
     * @param name {string} - The name of the provider (e.g., "precisionSec", "smartScreen").
     */
    removeStringFromAllowedCache(str, name) {
        try {
            if (name === "all") {
                Object.values(this.allowedCaches).forEach(m => m.delete(str));
            } else if (this.allowedCaches[name]) {
                this.allowedCaches[name].delete(str);
            } else {
                console.warn(`Cache "${name}" not found`);
            }

            this.updateLocalStorage(true);
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
     * Checks if a string is in the processing cache for a specific provider.
     *
     * @param str {string} - The string to check.
     * @param name {string} - The name of the provider (e.g., "precisionSec", "smartScreen").
     * @returns {boolean} - Returns true if the string is in the processing cache and not expired, false otherwise.
     */
    isStringInProcessingCache(str, name) {
        try {
            const map = this.processingCaches[name];

            if (!map) {
                return false;
            }

            if (map.has(str)) {
                const entry = map.get(str);

                if (entry.exp > Date.now()) {
                    return true;
                }

                map.delete(str);
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
     * Add a string key to the processing cache, associating it with a specific tabId.
     *
     * @param {string} str - The string to add.
     * @param {string} name - The name of the provider (e.g., "precisionSec", "smartScreen").
     * @param {number} tabId - The ID of the tab associated with this string.
     */
    addStringToProcessingCache(str, name, tabId) {
        try {
            const expTime = Date.now() + this.expirationTime * 1000;

            if (this.cleanExpiredEntries() === 0) {
                this.updateSessionStorage(true);
            }

            const entry = {exp: expTime, tabId: tabId};

            if (name === "all") {
                Object.values(this.processingCaches).forEach(m => m.set(str, entry));
            } else if (this.processingCaches[name]) {
                this.processingCaches[name].set(str, entry);
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
     * Remove a string key from the processing cache for a specific provider.
     *
     * @param str {string} - The string to remove.
     * @param name {string} - The name of the provider (e.g., "precisionSec", "smartScreen").
     */
    removeStringFromProcessingCache(str, name) {
        try {
            if (name === "all") {
                Object.values(this.processingCaches).forEach(m => m.delete(str));
            } else if (this.processingCaches[name]) {
                this.processingCaches[name].delete(str);
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
        const results = [];
        const map = this.processingCaches[name];

        if (!map) {
            return results;
        }

        const now = Date.now();

        for (const [key, entry] of map.entries()) {
            if (entry.tabId === tabId) {
                if (entry.exp > now) {
                    results.push(key);
                } else {
                    // expired: remove it
                    map.delete(key);
                }
            }
        }

        // If any expired entries were removed, persist the change
        this.updateSessionStorage(true);
        return results;
    }

    /**
     * Remove all entries in the processing cache for all keys associated with a specific tabId.
     *
     * @param tabId - The ID of the tab whose entries should be removed.
     */
    removeKeysByTabId(tabId) {
        let removedCount = 0;

        Object.keys(this.processingCaches).forEach(name => {
            const map = this.processingCaches[name];

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
