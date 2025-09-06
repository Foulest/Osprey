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
const UrlHelpers = (() => {

    // Browser API compatibility between Chrome and Firefox
    const browserAPI = typeof browser === 'undefined' ? chrome : browser;

    // Base URL for the block page
    const blockPageBaseUrl = browserAPI.runtime.getURL("pages/warning/WarningPage.html");

    /**
     * Extracts the blocked URL (the website being reported as malicious) from the query parameters of a URL.
     *
     * @param {string} url - The URL containing the blocked website information.
     * @returns {string|null} - The blocked URL, or null if not found.
     */
    function extractBlockedUrl(url) {
        try {
            return new URL(url).searchParams.get("url");
        } catch (error) {
            console.warn(`Invalid URL format: ${error.message}`);
            return null;
        }
    }

    /**
     * Extracts the continue URL from the query parameters of a URL.
     *
     * @param {string} url - The URL containing the continue URL parameter.
     * @returns {string|null} - The continue URL, or null if not found.
     */
    function extractContinueUrl(url) {
        try {
            return new URL(url).searchParams.get("curl");
        } catch (error) {
            console.warn(`Invalid URL format: ${error.message}`);
            return null;
        }
    }

    /**
     * Extracts the origin of the protection result from the query parameters of a URL.
     *
     * @param url - The URL containing the origin information
     * @returns {string} - The origin of the protection result
     */
    function extractOrigin(url) {
        try {
            return new URL(url).searchParams.get("or");
        } catch (error) {
            console.warn(`Invalid URL format: ${error.message}`);
            return "0";
        }
    }

    /**
     * Extracts the result (e.g., phishing, malware) from the query parameters of a URL.
     *
     * @param {string} url - The URL containing the result.
     * @returns {string|null} - The result from the URL, or null if not found.
     */
    function extractResult(url) {
        try {
            return new URL(url).searchParams.get("rs");
        } catch (error) {
            console.warn(`Invalid URL format: ${error.message}`);
            return "0";
        }
    }

    /**
     * Constructs the URL for the browser's block page, which shows a warning when a website is blocked.
     *
     * @param {object} protectionResult - The result object containing details about the threat.
     * @param {object} continueURL - The URL to continue to if the user clicks a continue button.
     * @returns {string} - The full URL for the block page.
     */
    function getBlockPageUrl(protectionResult, continueURL) {
        // Checks if the protection result is valid
        if (!protectionResult || typeof protectionResult !== 'object') {
            throw new Error('Invalid protection result');
        }

        // Checks if the protection result's properties are valid
        if (!protectionResult.url || !protectionResult.origin || !protectionResult.resultType) {
            throw new Error('Missing required protection result properties');
        }

        try {
            // Constructs a new URL object for the block page
            const blockPageUrl = new URL(blockPageBaseUrl);

            // Sets the search parameters for the block page URL
            blockPageUrl.search = new URLSearchParams([
                ["url", protectionResult.url],       // The URL of the blocked website
                ["curl", continueURL || ''],         // The continue URL
                ["or", protectionResult.origin],     // The origin of the protection result
                ["rs", protectionResult.resultType]  // The result type
            ]).toString();

            // Returns the constructed block page URL as a string
            return blockPageUrl.toString();
        } catch (error) {
            throw new Error(`Failed to construct block page URL: ${error.message}`);
        }
    }

    /**
     * Checks if a hostname is locally hosted.
     *
     * @param hostname - The hostname to check.
     * @returns {boolean|boolean} - If a hostname is locally hosted.
     */
    function isLocalHostname(hostname) {
        return hostname === "localhost" ||
            hostname.endsWith(".localhost") ||
            hostname.endsWith(".local");
    }

    /**
     * Checks if a hostname/IP address is locally hosted.
     *
     * @param hostname - The hostname to check.
     * @returns {boolean} - If a hostname is locally hosted.
     */
    function isInternalAddress(hostname) {
        if (isLocalHostname(hostname)) {
            return true;
        }

        // Check for IPv6 addresses
        if (hostname.includes(':')) {
            const h = hostname.toLowerCase();

            // ::1 is loopback, fc00::/7 is unique local, fe80::/10 is link-local
            return h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80:');
        }

        const ip = normalizeIP(hostname); // IPv4 dotted‑decimal only
        return ip ? isPrivateIP(ip) : false;
    }

    /**
     * Checks if an IP address is private/locally hosted.
     *
     * @param ip - The IP address to check.
     * @returns {boolean|boolean|boolean} - If the IP address is private/locally hosted.
     */
    function isPrivateIP(ip) {
        return ip.startsWith("127.") ||
            ip.startsWith("10.") ||
            /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
            ip.startsWith("192.168.") ||
            ip.startsWith("0.0.0.0");
    }

    /**
     * Normalizes an IP address.
     *
     * @param {string} hostname - The IP/hostname to check.
     * @returns {null|string} - The normalized IP address.
     */
    function normalizeIP(hostname) {
        // Accept only dotted‑decimal IPv4 (no octal/hex/decimal-int shorthands)
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
            return null;
        }

        const nums = hostname.split('.').map(n => Number(n));

        if (nums.some(n => n < 0 || n > 255)) {
            return null;
        }
        return nums.join('.');
    }

    /**
     * Normalizes a URL by removing the trailing slash and normalizing the hostname.
     *
     * @param url {string|URL} - The URL to normalize, can be a string or a URL object.
     * @returns {string|string} - The normalized URL as a string.
     */
    function normalizeUrl(url) {
        const u = typeof url === "string" ? new URL(url) : url;

        // Removes trailing dots from the hostname
        const host = u.hostname.toLowerCase().replace(/\.$/, '');

        // Removes trailing slashes from the pathname
        const path = u.pathname.replace(/\/+$/, '');
        return host + path;
    }

    /**
     * Encodes a DNS query for the given domain and type.
     *
     * @param {string} domain - The domain to encode.
     * @param {number} type - The type of DNS record (default is 1 for A record).
     * @return {string} - The base64url encoded DNS query.
     */
    function encodeDNSQuery(domain, type = 1) {
        if (typeof domain !== 'string') {
            throw new Error('domain must be a string');
        }

        // Strip trailing dot; DNS wire format carries labels explicitly
        domain = domain.trim().replace(/\.$/, '');

        const header = new Uint8Array([
            0x00, 0x00, // ID
            0x01, 0x00, // flags: standard query, recursion desired
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00  // ARCOUNT
        ]);

        const qname = [];

        for (const label of domain.split('.')) {
            const bytes = new TextEncoder().encode(label);

            if (bytes.length === 0 || bytes.length > 63) {
                throw new Error(`Invalid label length in domain ${domain}: ${bytes.length}`);
            }

            qname.push(bytes.length, ...bytes);
        }

        qname.push(0x00); // end of QNAME

        const qtype = new Uint8Array([type >>> 8 & 0xff, type & 0xff]);
        const qclass = new Uint8Array([0x00, 0x01]); // IN
        const packet = new Uint8Array(header.length + qname.length + qtype.length + qclass.length);

        packet.set(header, 0);
        packet.set(qname, header.length);
        packet.set(qtype, header.length + qname.length);
        packet.set(qclass, header.length + qname.length + qtype.length);

        let bin = '';

        for (const byte of packet) {
            bin += String.fromCharCode(byte);
        }
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    return {
        extractBlockedUrl,
        extractContinueUrl,
        extractOrigin,
        extractResult,
        normalizeUrl,
        getBlockPageUrl,
        isInternalAddress,
        encodeDNSQuery
    };
})();
