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
     * @param {number} resultOrigin - The origin of the result (e.g., from endpoint or known top website).
     */
    constructor(urlChecked, resultType, resultOrigin) {
        this.url = urlChecked;
        this.resultType = resultType;
        this.origin = resultOrigin;
    }
}

ProtectionResult.ResultType = {
    KNOWN_SAFE: 0,
    FAILED: 1,
    WAITING: 2,
    ALLOWED: 3,
    MALICIOUS: 4,
    PHISHING: 5,
    UNTRUSTED: 6,
    ADULT_CONTENT: 7,
};

ProtectionResult.ResultTypeName = {
    0: LangUtil.KNOWN_SAFE,
    1: LangUtil.FAILED,
    2: LangUtil.WAITING,
    3: LangUtil.ALLOWED,
    4: LangUtil.MALICIOUS,
    5: LangUtil.PHISHING,
    6: LangUtil.UNTRUSTED,
    7: LangUtil.ADULT_CONTENT
};

ProtectionResult.ResultTypeNameEN = {
    0: "Known Safe",
    1: "Failed",
    2: "Waiting",
    3: "Allowed",
    4: "Malicious",
    5: "Phishing",
    6: "Untrusted",
    7: "Adult Content",
};

ProtectionResult.Origin = {
    UNKNOWN: 0,

    // Official Partners
    ADGUARD_SECURITY: 1,
    ADGUARD_FAMILY: 2,
    ALPHAMOUNTAIN: 3,
    CONTROL_D_SECURITY: 4,
    CONTROL_D_FAMILY: 5,
    PRECISIONSEC: 6,

    // Non-Partnered Providers
    CERT_EE: 7,
    CLEANBROWSING_SECURITY: 8,
    CLEANBROWSING_FAMILY: 9,
    CLOUDFLARE_SECURITY: 10,
    CLOUDFLARE_FAMILY: 11,
    DNS0_SECURITY: 12,
    DNS0_FAMILY: 13,
    DNS4EU_SECURITY: 14,
    DNS4EU_FAMILY: 15,
    QUAD9: 16,
};

ProtectionResult.FullName = {
    0: "Unknown",

    // Official Partners
    1: "AdGuard Security DNS",
    2: "AdGuard Family DNS",
    3: "alphaMountain Web Protection",
    4: "Control D Security DNS",
    5: "Control D Family DNS",
    6: "PrecisionSec Web Protection",

    // Non-Partnered Providers
    7: "CERT-EE Security DNS",
    8: "CleanBrowsing Security DNS",
    9: "CleanBrowsing Family DNS",
    10: "Cloudflare Security DNS",
    11: "Cloudflare Family DNS",
    12: "DNS0.eu Security DNS",
    13: "DNS0.eu Family DNS",
    14: "DNS4EU Security DNS",
    15: "DNS4EU Family DNS",
    16: "Quad9 Security DNS",
};

ProtectionResult.ShortName = {
    0: "Unknown",

    // Official Partners
    1: "AdGuard Security",
    2: "AdGuard Family",
    3: "alphaMountain",
    4: "Control D Security",
    5: "Control D Family",
    6: "PrecisionSec",

    // Non-Partnered Providers
    7: "CERT-EE",
    8: "CleanBrowsing Security",
    9: "CleanBrowsing Family",
    10: "Cloudflare Security",
    11: "Cloudflare Family",
    12: "DNS0.eu Security",
    13: "DNS0.eu Family",
    14: "DNS4EU Security",
    15: "DNS4EU Family",
    16: "Quad9",
};

ProtectionResult.CacheName = {
    0: "unknown",

    // Official Partners
    1: "adGuardSecurity",
    2: "adGuardFamily",
    3: "alphaMountain",
    4: "controlDSecurity",
    5: "controlDFamily",
    6: "precisionSec",

    // Non-Partnered Providers
    7: "certEE",
    8: "cleanBrowsingSecurity",
    9: "cleanBrowsingFamily",
    10: "cloudflareSecurity",
    11: "cloudflareFamily",
    12: "dns0Security",
    13: "dns0Family",
    14: "dns4EUSecurity",
    15: "dns4EUFamily",
    16: "quad9",
};
