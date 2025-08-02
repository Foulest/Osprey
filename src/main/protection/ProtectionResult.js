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

class ProtectionResult {

    /**
     * Constructor function for creating a browser protection result object.
     *
     * @param {string} urlChecked - The URL that was checked.
     * @param {string} resultType - The result type of the protection check (e.g., "allowed", "malicious").
     * @param {number} resultOrigin - The origin of the result (e.g., from endpoint or known top site).
     */
    constructor(urlChecked, resultType, resultOrigin) {
        this.url = urlChecked;
        this.result = resultType;
        this.origin = resultOrigin;
    }
}

ProtectionResult.ResultType = {
    KNOWN_SAFE: "Known Safe",
    FAILED: "Failed",
    WAITING: "Waiting",
    ALLOWED: "Allowed",
    MALICIOUS: "Malicious",
    PHISHING: "Phishing",
    UNTRUSTED: "Untrusted",
    ADULT_CONTENT: "Adult Content",
};

ProtectionResult.ResultOrigin = {
    UNKNOWN: 0,

    // Official Partners
    ADGUARD_SECURITY: 1,
    ADGUARD_FAMILY: 2,
    ALPHAMOUNTAIN: 3,
    CONTROL_D_SECURITY: 4,
    CONTROL_D_FAMILY: 5,
    PRECISIONSEC: 6,

    // Non-Partnered Providers
    G_DATA: 7,
    CERT_EE: 8,
    CLEANBROWSING_SECURITY: 9,
    CLEANBROWSING_FAMILY: 10,
    CLOUDFLARE_SECURITY: 11,
    CLOUDFLARE_FAMILY: 12,
    DNS0_SECURITY: 13,
    DNS0_FAMILY: 14,
    DNS4EU_SECURITY: 15,
    DNS4EU_FAMILY: 16,
    SMARTSCREEN: 17,
    NORTON: 18,
    QUAD9: 19,
};

ProtectionResult.ResultOriginNames = {
    0: "Unknown",

    // Official Partners
    1: "AdGuard Security DNS",
    2: "AdGuard Family DNS",
    3: "alphaMountain Web Protection",
    4: "Control D Security DNS",
    5: "Control D Family DNS",
    6: "PrecisionSec Web Protection",

    // Non-Partnered Providers
    7: "G DATA Web Protection",
    8: "CERT-EE Security DNS",
    9: "CleanBrowsing Security DNS",
    10: "CleanBrowsing Family DNS",
    11: "Cloudflare Security DNS",
    12: "Cloudflare Family DNS",
    13: "DNS0.eu Security DNS",
    14: "DNS0.eu Family DNS",
    15: "DNS4EU Security DNS",
    16: "DNS4EU Family DNS",
    17: "Microsoft SmartScreen",
    18: "Norton Safe Web",
    19: "Quad9 Security DNS",
};

ProtectionResult.ShortOriginNames = {
    0: "Unknown",

    // Official Partners
    1: "AdGuard Security",
    2: "AdGuard Family",
    3: "alphaMountain",
    4: "Control D Security",
    5: "Control D Family",
    6: "PrecisionSec",

    // Non-Partnered Providers
    7: "G DATA",
    8: "CERT-EE",
    9: "CleanBrowsing Security",
    10: "CleanBrowsing Family",
    11: "Cloudflare Security",
    12: "Cloudflare Family",
    13: "DNS0.eu Security",
    14: "DNS0.eu Family",
    15: "DNS4EU Security",
    16: "DNS4EU Family",
    17: "SmartScreen",
    18: "Norton",
    19: "Quad9",
};

ProtectionResult.CacheOriginNames = {
    0: "unknown",

    // Official Partners
    1: "adGuardSecurity",
    2: "adGuardFamily",
    3: "alphaMountain",
    4: "controlDSecurity",
    5: "controlDFamily",
    6: "precisionSec",

    // Non-Partnered Providers
    7: "gData",
    8: "certEE",
    9: "cleanBrowsingSecurity",
    10: "cleanBrowsingFamily",
    11: "cloudflareSecurity",
    12: "cloudflareFamily",
    13: "dns0Security",
    14: "dns0Family",
    15: "dns4EUSecurity",
    16: "dns4EUFamily",
    17: "smartScreen",
    18: "norton",
    19: "quad9",
};
