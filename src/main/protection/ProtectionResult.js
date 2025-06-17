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
    CONTROL_D_SECURITY: 3,
    CONTROL_D_FAMILY: 4,
    PRECISIONSEC: 5,

    // Non-Partnered Providers
    G_DATA: 6,
    CERT_EE: 7,
    CIRA_SECURITY: 8,
    CIRA_FAMILY: 9,
    CLEANBROWSING_SECURITY: 10,
    CLEANBROWSING_FAMILY: 11,
    CLEANBROWSING_ADULT: 12,
    CLOUDFLARE_SECURITY: 13,
    CLOUDFLARE_FAMILY: 14,
    DNS0_SECURITY: 15,
    DNS0_KIDS: 16,
    DNS4EU_SECURITY: 17,
    DNS4EU_FAMILY: 18,
    SMARTSCREEN: 19,
    NORTON: 20,
    OPENDNS_SECURITY: 21,
    OPENDNS_FAMILY_SHIELD: 22,
    QUAD9: 23,
    SWITCH_CH: 24,
};

ProtectionResult.ResultOriginNames = {
    0: "Unknown",

    // Official Partners
    1: "AdGuard Security DNS",
    2: "AdGuard Family DNS",
    3: "Control D Security DNS",
    4: "Control D Family DNS",
    5: "PrecisionSec Web Protection",

    // Non-Partnered Providers
    6: "G DATA WebProtection",
    7: "CERT-EE Security DNS",
    8: "CIRA Security DNS",
    9: "CIRA Family DNS",
    10: "CleanBrowsing Security DNS",
    11: "CleanBrowsing Family DNS",
    12: "CleanBrowsing Adult DNS",
    13: "Cloudflare Security DNS",
    14: "Cloudflare Family DNS",
    15: "DNS0.eu Security DNS",
    16: "DNS0.eu Kids DNS",
    17: "DNS4EU Security DNS",
    18: "DNS4EU Family DNS",
    19: "Microsoft SmartScreen",
    20: "Norton Safe Web",
    21: "OpenDNS Security DNS",
    22: "OpenDNS Family Shield DNS",
    23: "Quad9 Security DNS",
    24: "Switch.ch Security DNS"
};

ProtectionResult.ShortOriginNames = {
    0: "Unknown",

    // Official Partners
    1: "AdGuard Security",
    2: "AdGuard Family",
    3: "Control D Security",
    4: "Control D Family",
    5: "PrecisionSec",

    // Non-Partnered Providers
    6: "G DATA",
    7: "CERT-EE",
    8: "CIRA Security",
    9: "CIRA Family",
    10: "CleanBrowsing Security",
    11: "CleanBrowsing Family",
    12: "CleanBrowsing Adult",
    13: "Cloudflare Security",
    14: "Cloudflare Family",
    15: "DNS0.eu Security",
    16: "DNS0.eu Kids",
    17: "DNS4EU Security",
    18: "DNS4EU Family",
    19: "SmartScreen",
    20: "Norton",
    21: "OpenDNS Security",
    22: "OpenDNS Family Shield",
    23: "Quad9",
    24: "Switch.ch"
};

ProtectionResult.CacheOriginNames = {
    0: "unknown",

    // Official Partners
    1: "adGuardSecurity",
    2: "adGuardFamily",
    3: "controlDSecurity",
    4: "controlDFamily",
    5: "precisionSec",

    // Non-Partnered Providers
    6: "gData",
    7: "certEE",
    8: "ciraSecurity",
    9: "ciraFamily",
    10: "cleanBrowsingSecurity",
    11: "cleanBrowsingFamily",
    12: "cleanBrowsingAdult",
    13: "cloudflareSecurity",
    14: "cloudflareFamily",
    15: "dns0Security",
    16: "dns0Kids",
    17: "dns4EUSecurity",
    18: "dns4EUFamily",
    19: "smartScreen",
    20: "norton",
    21: "openDNSSecurity",
    22: "openDNSFamilyShield",
    23: "quad9",
    24: "switchCH"
};
