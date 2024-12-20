"use strict";

const EmsisoftUtil = function () {

    /**
     * Creates an array of domains from a hostname.
     *
     * @param {string} hostname - The hostname.
     * @returns {string[]} The array of domains.
     */
    const createHostnameArray = function (hostname) {
        return hostname.split('.').map((_, i, arr) => arr.slice(i).join('.'));
    };

    /**
     * Creates a string of hashes from an array of domains.
     *
     * @param {string[]} arr - The array of domains.
     * @returns {string} The string of hashes.
     */
    const getStringOfHashes = function (arr) {
        return arr.map(createHash).join(',');
    };

    /**
     * Creates a hash from a domain.
     * (Used by Emsisoft API)
     *
     * @param {string} domain - The domain to hash.
     * @returns {string} The hashed domain.
     */
    const createHash = function (domain) {
        return MD5("Kd3fIjAq" + domain.toLowerCase(), null, false).toUpperCase();
    };

    /**
     * Finds the subdomain by hash.
     *
     * @param {string} hostname - The hostname to search.
     * @param {string} hash - The hash to find.
     * @returns {string} The subdomain or an empty string if not found.
     */
    const findSubdomainByHash = function (hostname, hash) {
        return EmsisoftUtil.createHostnameArray(hostname).find(domain => EmsisoftUtil.createHash(domain) === hash) || "";
    };

    /**
     * Creates a new RegExp object.
     *
     * @param {string} value - The regex pattern
     * @param {boolean} [convertFromPCRE=false] - Whether to convert from PCRE
     * @param {string} [flags=''] - The regex flags
     * @returns {RegExp|null} The RegExp object or null if invalid
     */
    const newRegExp = function (value, convertFromPCRE = false, flags = '') {
        try {
            // Handle PCRE conversion if required
            if (convertFromPCRE) {
                const match = /^\(\?([gmiu]+)\)/.exec(value);

                if (match) {
                    match[1].split('').forEach(itm => {
                        if (!flags.includes(itm)) {
                            flags += itm;
                        }
                    });

                    value = value.replace(/^\(\?([gmiu]+)\)/, '');
                }
            }

            // Attempt to create a RegExp with the provided flags
            return new RegExp(value, flags);
        } catch {
            try {
                // Retry by toggling the 'u' flag
                return new RegExp(value, flags.includes('u') ? flags.replace('u', '') : flags + 'u');
            } catch {
                console.warn(`Invalid regex: "${value}"`);
                return null;
            }
        }
    };

    return {
        createHostnameArray: createHostnameArray,
        getStringOfHashes: getStringOfHashes,
        createHash: createHash,
        findSubdomainByHash: findSubdomainByHash,
        newRegExp: newRegExp
    };
}();
