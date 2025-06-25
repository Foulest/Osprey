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
    CIRA_SECURITY: 9,
    CIRA_FAMILY: 10,
    CLEANBROWSING_SECURITY: 11,
    CLEANBROWSING_FAMILY: 12,
    CLEANBROWSING_ADULT: 13,
    CLOUDFLARE_SECURITY: 14,
    CLOUDFLARE_FAMILY: 15,
    DNS0_SECURITY: 16,
    DNS0_KIDS: 17,
    DNS4EU_SECURITY: 18,
    DNS4EU_FAMILY: 19,
    SMARTSCREEN: 20,
    NORTON: 21,
    OPENDNS_SECURITY: 22,
    OPENDNS_FAMILY_SHIELD: 23,
    QUAD9: 24,
    SWITCH_CH: 25,
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
    9: "CIRA Security DNS",
    10: "CIRA Family DNS",
    11: "CleanBrowsing Security DNS",
    12: "CleanBrowsing Family DNS",
    13: "CleanBrowsing Adult DNS",
    14: "Cloudflare Security DNS",
    15: "Cloudflare Family DNS",
    16: "DNS0.eu Security DNS",
    17: "DNS0.eu Kids DNS",
    18: "DNS4EU Security DNS",
    19: "DNS4EU Family DNS",
    20: "Microsoft SmartScreen",
    21: "Norton Safe Web",
    22: "OpenDNS Security DNS",
    23: "OpenDNS Family Shield DNS",
    24: "Quad9 Security DNS",
    25: "Switch.ch Security DNS"
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
    9: "CIRA Security",
    10: "CIRA Family",
    11: "CleanBrowsing Security",
    12: "CleanBrowsing Family",
    13: "CleanBrowsing Adult",
    14: "Cloudflare Security",
    15: "Cloudflare Family",
    16: "DNS0.eu Security",
    17: "DNS0.eu Kids",
    18: "DNS4EU Security",
    19: "DNS4EU Family",
    20: "SmartScreen",
    21: "Norton",
    22: "OpenDNS Security",
    23: "OpenDNS Family Shield",
    24: "Quad9",
    25: "Switch.ch"
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
    9: "ciraSecurity",
    10: "ciraFamily",
    11: "cleanBrowsingSecurity",
    12: "cleanBrowsingFamily",
    13: "cleanBrowsingAdult",
    14: "cloudflareSecurity",
    15: "cloudflareFamily",
    16: "dns0Security",
    17: "dns0Kids",
    18: "dns4EUSecurity",
    19: "dns4EUFamily",
    20: "smartScreen",
    21: "norton",
    22: "openDNSSecurity",
    23: "openDNSFamilyShield",
    24: "quad9",
    25: "switchCH"
};
