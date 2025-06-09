"use strict";

class ProtectionResult {
    /**
     * Constructor function for creating a browser protection result object.
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
    PHISHING: "Phishing",
    MALICIOUS: "Malicious",
    FRAUD: "Fraud",
    PUA: "Potentially Unwanted Applications",
    CRYPTOJACKING: "Cryptojacking",
    MALVERTISING: "Malvertising",
    COMPROMISED: "Compromised",
    UNTRUSTED: "Untrusted",
    RESTRICTED: "Restricted",
};

ProtectionResult.ResultOrigin = {
    UNKNOWN: 0,

    // Page 1
    ADGUARD_SECURITY: 1,
    ADGUARD_FAMILY: 2,
    CONTROL_D_SECURITY: 3,
    CONTROL_D_FAMILY: 4,
    PRECISIONSEC: 5,
    BITDEFENDER: 6,
    G_DATA: 7,

    // Page 2
    SMARTSCREEN: 8,
    NORTON: 9,
    CERT_EE: 10,
    CIRA_SECURITY: 11,
    CIRA_FAMILY: 12,
    CLEANBROWSING_SECURITY: 13,
    CLEANBROWSING_FAMILY: 14,

    // Page 3
    CLEANBROWSING_ADULT: 15,
    CLOUDFLARE_SECURITY: 16,
    CLOUDFLARE_FAMILY: 17,
    DNS0_SECURITY: 18,
    DNS0_KIDS: 19,
    DNS4EU_SECURITY: 20,
    DNS4EU_FAMILY: 21,

    // Page 4
    OPENDNS_SECURITY: 22,
    OPENDNS_FAMILY_SHIELD: 23,
    QUAD9: 24,
    SWITCH_CH: 25,
};

ProtectionResult.ResultOriginNames = {
    0: "Unknown",

    // Page 1
    1: "AdGuard Security DNS",
    2: "AdGuard Family DNS",
    3: "Control D Security DNS",
    4: "Control D Family DNS",
    5: "PrecisionSec Web Protection",
    6: "Bitdefender TrafficLight",
    7: "G DATA WebProtection",

    // Page 2
    8: "Microsoft SmartScreen",
    9: "Norton SafeWeb",
    10: "CERT-EE Security DNS",
    11: "CIRA Security DNS",
    12: "CIRA Family DNS",
    13: "CleanBrowsing Security DNS",
    14: "CleanBrowsing Family DNS",

    // Page 3
    15: "CleanBrowsing Adult DNS",
    16: "Cloudflare Security DNS",
    17: "Cloudflare Family DNS",
    18: "DNS0.eu Security DNS",
    19: "DNS0.eu Kids DNS",
    20: "DNS4EU Security DNS",
    21: "DNS4EU Family DNS",

    // Page 4
    22: "OpenDNS Security DNS",
    23: "OpenDNS Family Shield DNS",
    24: "Quad9 Security DNS",
    25: "Switch.ch Security DNS"
};

ProtectionResult.ShortOriginNames = {
    0: "Unknown",

    // Page 1
    1: "AdGuard Security",
    2: "AdGuard Family",
    3: "Control D Security",
    4: "Control D Family",
    5: "PrecisionSec",
    6: "Bitdefender",
    7: "G DATA",

    // Page 2
    8: "SmartScreen",
    9: "Norton",
    10: "CERT-EE",
    11: "CIRA Security",
    12: "CIRA Family",
    13: "CleanBrowsing Security",
    14: "CleanBrowsing Family",

    // Page 3
    15: "CleanBrowsing Adult",
    16: "Cloudflare Security",
    17: "Cloudflare Family",
    18: "DNS0.eu Security",
    19: "DNS0.eu Kids",
    20: "DNS4EU Security",
    21: "DNS4EU Family",

    // Page 4
    22: "OpenDNS Security",
    23: "OpenDNS Family Shield",
    24: "Quad9",
    25: "Switch.ch"
};

ProtectionResult.CacheOriginNames = {
    0: "unknown",

    // Page 1
    1: "adGuardSecurity",
    2: "adGuardFamily",
    3: "controlDSecurity",
    4: "controlDFamily",
    5: "precisionSec",
    6: "bitdefender",
    7: "gData",

    // Page 2
    8: "smartScreen",
    9: "norton",
    10: "certEE",
    11: "ciraSecurity",
    12: "ciraFamily",
    13: "cleanBrowsingSecurity",
    14: "cleanBrowsingFamily",

    // Page 3
    15: "cleanBrowsingAdult",
    16: "cloudflareSecurity",
    17: "cloudflareFamily",
    18: "dns0Security",
    19: "dns0Kids",
    20: "dns4EUSecurity",
    21: "dns4EUFamily",

    // Page 4
    22: "openDNSSecurity",
    23: "openDNSFamilyShield",
    24: "quad9",
    25: "switchCH"
};
