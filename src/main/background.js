(() => {
    "use strict";

    // Browser API compatibility between Chrome and Firefox
    const isFirefox = typeof browser !== 'undefined';
    const browserAPI = isFirefox ? browser : chrome;
    const contextMenuAPI = isFirefox ? browserAPI.menus : browserAPI.contextMenus;
    let supportsManagedPolicies = true;

    const resultCounts = new Map();
    const resultSystemNames = new Map();

    // Import necessary scripts for functionality
    try {
        // This will work in Chrome service workers but throw in Firefox
        importScripts(
            // Util
            "util/Settings.js",
            "util/UrlHelpers.js",
            "util/CacheManager.js",
            "util/Storage.js",
            "util/MessageType.js",

            // Other
            "util/other/SmartScreenUtil.js",

            // Protection
            "protection/ProtectionResult.js",
            "protection/BrowserProtection.js"
        );
    } catch (error) {
        // In Firefox, importScripts is not available, but scripts are loaded via background.html
        console.debug("Running in Firefox or another environment without importScripts");
        console.debug("Error: " + error);
    }

    // List of valid protocols (e.g., HTTP, HTTPS).
    const validProtocols = ['http:', 'https:'];

    // Function to handle navigation checks.
    const handleNavigation = navigationDetails => {
        Settings.get(settings => {
            // Retrieve settings to check if protection is enabled.
            if (!settings.adGuardSecurityEnabled
                && !settings.adGuardFamilyEnabled
                && !settings.certEEEnabled
                && !settings.ciraFamilyEnabled
                && !settings.ciraSecurityEnabled
                && !settings.cleanBrowsingAdultEnabled
                && !settings.cleanBrowsingFamilyEnabled
                && !settings.cleanBrowsingSecurityEnabled
                && !settings.cloudflareFamilyEnabled
                && !settings.cloudflareSecurityEnabled
                && !settings.controlDFamilyEnabled
                && !settings.controlDSecurityEnabled
                && !settings.dns0KidsEnabled
                && !settings.dns0SecurityEnabled
                && !settings.dns4EUFamilyEnabled
                && !settings.dns4EUSecurityEnabled
                && !settings.gDataEnabled
                && !settings.nortonEnabled
                && !settings.openDNSFamilyShieldEnabled
                && !settings.openDNSSecurityEnabled
                && !settings.precisionSecEnabled
                && !settings.quad9Enabled
                && !settings.smartScreenEnabled
                && !settings.switchCHEnabled
            ) {
                console.debug("Protection is disabled; bailing out early.");
                return;
            }

            let {tabId, frameId, url: currentUrl} = navigationDetails;

            // Check if the frame ID is not the main frame.
            if (settings.ignoreFrameNavigation && frameId !== 0) {
                console.debug(`Ignoring frame navigation: ${currentUrl} #${frameId}; bailing out.`);
                return;
            }

            // Check if the URL is missing or incomplete.
            if (!currentUrl || !currentUrl.includes('://')) {
                console.debug(`Incomplete or missing URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Remove trailing slashes from the URL.
            currentUrl = currentUrl.replace(/\/+$/, '');

            // Remove www. from the start of the URL.
            currentUrl = currentUrl.replace(/https?:\/\/www\./, 'https://');

            // Remove query parameters, fragments (#) and & tags from the URL.
            currentUrl = currentUrl.replace(/[?#&].*$/, '');

            // Sanitize and encode the URL to handle spaces and special characters.
            try {
                currentUrl = encodeURI(currentUrl);
            } catch (error) {
                console.warn(`Failed to encode URL: ${currentUrl}; bailing out: ` + error);
                return;
            }

            // Parse the URL object.
            let urlObject;
            try {
                urlObject = new URL(currentUrl);
            } catch (error) {
                console.warn(`Invalid URL format: ${currentUrl}; bailing out: ` + error);
                return;
            }

            const protocol = urlObject.protocol;
            let hostname = urlObject.hostname;

            // Check for incomplete URLs missing the scheme.
            if (!protocol || currentUrl.startsWith('//')) {
                console.warn(`URL is missing a scheme: ${currentUrl}; bailing out.`);
                return;
            }

            // Check for valid protocols.
            if (!validProtocols.includes(protocol)) {
                console.debug(`Invalid protocol: ${protocol}; bailing out.`);
                return;
            }

            // Check for missing hostname.
            if (!hostname) {
                console.warn(`Missing hostname in URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Exclude internal network addresses, loopback, or reserved domains.
            if (['localhost', '127.0.0.1'].includes(hostname)
                || hostname.endsWith('.local')
                || /^192\.168\.\d{1,3}\.\d{1,3}$/.test(hostname)
                || /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)
                || /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
                console.warn(`Local/internal network URL detected: ${currentUrl}; bailing out.`);
                return;
            }

            // Cancels all pending requests for the main frame navigation.
            if (frameId === 0) {
                BrowserProtection.abandonPendingRequests(tabId, "Cancelled by main frame navigation.");

                // Remove all cached keys for the tab.
                BrowserProtection.cacheManager.removeKeysByTabId(tabId);
                resultCounts.delete(tabId);
                resultSystemNames.delete(tabId);
            }

            // Set the hostname back to the URL object.
            urlObject.hostname = hostname;

            let blocked = false;
            let firstSystemName = "";

            resultCounts.set(tabId, 0);
            resultSystemNames.set(tabId, []);

            console.info(`Checking URL: ${currentUrl}`);

            // Check if the URL is malicious.
            BrowserProtection.checkIfUrlIsMalicious(tabId, currentUrl, (result, duration) => {
                const cacheName = ProtectionResult.CacheOriginNames[result.origin];
                const systemName = ProtectionResult.ShortOriginNames[result.origin];
                const resultType = result.result;

                // Remove the URL from the system's processing cache on every callback.
                // Don't remove it if the result is still waiting for a response.
                if (resultType !== ProtectionResult.ResultType.WAITING) {
                    BrowserProtection.cacheManager.removeUrlFromProcessingCache(urlObject, cacheName);
                }

                console.info(`[${systemName}] Result for ${currentUrl}: ${resultType} (${duration}ms)`);

                if (resultType !== ProtectionResult.ResultType.FAILED
                    && resultType !== ProtectionResult.ResultType.WAITING
                    && resultType !== ProtectionResult.ResultType.KNOWN_SAFE
                    && resultType !== ProtectionResult.ResultType.ALLOWED) {

                    if (!blocked) {
                        browserAPI.tabs.get(tabId, tab => {
                            if (!tab) {
                                console.debug(`tabs.get(${tabId}) failed '${browserAPI.runtime.lastError?.message}'; bailing out.`);
                                return;
                            }

                            const pendingUrl = tab.pendingUrl || tab.url;

                            if (!(currentUrl !== pendingUrl && frameId === 0)) {
                                if (pendingUrl.startsWith("chrome-extension:")
                                    || pendingUrl.startsWith("moz-extension:")
                                    || pendingUrl.startsWith("extension:")) {
                                    console.debug(`[${systemName}] The tab is at an extension page; bailing out. ${pendingUrl} ${frameId}`);
                                    return;
                                }
                            }

                            const targetUrl = frameId === 0 ? currentUrl : pendingUrl;

                            if (targetUrl) {
                                // Navigate to the block page.
                                const blockPageUrl = UrlHelpers.getBlockPageUrl(result);
                                console.debug(`[${systemName}] Navigating to block page: ${blockPageUrl}.`);
                                browserAPI.tabs.update(tab.id, {url: blockPageUrl});

                                // Build the warning notification options
                                if (settings.notificationsEnabled) {
                                    const notificationOptions = {
                                        type: "basic",
                                        iconUrl: "assets/icons/icon128.png",
                                        title: "Unsafe Website Blocked",
                                        message: `URL: ${currentUrl}\nReason: ${resultType}\nReported by: ${systemName}`,
                                        priority: 2,
                                    };

                                    // Create a unique notification ID based on a random number
                                    const randomNumber = Math.floor(Math.random() * 100000000);
                                    const notificationId = `warning-` + randomNumber;

                                    // Display the warning notification
                                    browserAPI.notifications.create(notificationId, notificationOptions, notificationId => {
                                        console.debug(`Notification created with ID: ${notificationId}`);
                                    });
                                }
                            } else {
                                console.debug(`Tab '${tabId}' failed to supply a top-level URL; bailing out.`);
                            }
                        });
                    }

                    blocked = true;
                    firstSystemName = firstSystemName === "" ? systemName : firstSystemName;

                    // Iterate through the results and update the counts.
                    resultCounts.set(tabId, (resultCounts.get(tabId) || 0) + 1);
                    const fullCount = resultCounts.get(tabId) || 0;

                    // Track the system name that flagged the URL
                    const existingSystems = resultSystemNames.get(tabId) || [];
                    if (!existingSystems.includes(systemName) && systemName !== firstSystemName) {
                        existingSystems.push(systemName);
                        resultSystemNames.set(tabId, existingSystems);
                    }

                    setTimeout(() => {
                        // Set the action text to the result count.
                        browserAPI.action.setBadgeText({
                            text: resultCounts.get(tabId).toString(),
                            tabId: tabId
                        });

                        // Set the action background color to red.
                        browserAPI.action.setBadgeBackgroundColor({
                            color: "#ff4b4b",
                            tabId: tabId
                        });

                        // Set the action text color to white.
                        browserAPI.action.setBadgeTextColor({
                            color: "white",
                            tabId: tabId
                        });

                        // If the page URL is the block page, send (count - 1)
                        browserAPI.tabs.get(tabId, tab => {
                            const isBlockPage = tab.url?.includes("/WarningPage.html");
                            const adjustedCount = isBlockPage && fullCount > 0 ? fullCount - 1 : fullCount;

                            // Send a PONG message to the content script to update the blocked counter.
                            browserAPI.tabs.sendMessage(tabId, {
                                messageType: Messages.MessageType.BLOCKED_COUNTER_PONG,
                                count: adjustedCount,
                                systems: resultSystemNames.get(tabId) || []
                            }).catch(() => {
                            });
                        });
                    }, 150);
                }
            });
        });
    };

    // Listens for PING messages from content scripts to get the blocked counter.
    browserAPI.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.messageType === Messages.MessageType.BLOCKED_COUNTER_PING && sender.tab && sender.tab.id != null) {
            const tabId = sender.tab.id;
            const fullCount = resultCounts.get(tabId) || 0;

            // If the page URL is the block page, send (count - 1)
            browserAPI.tabs.get(tabId, tab => {
                const isBlockPage = tab.url?.includes("/WarningPage.html");
                const adjustedCount = isBlockPage && fullCount > 0 ? fullCount - 1 : fullCount;

                sendResponse({
                    count: adjustedCount,
                    systems: resultSystemNames.get(tabId) || []
                });
            });
        }
    });

    // Gather all policy keys needed for managed policies
    const policyKeys = [
        'DisableContextMenu',
        'DisableNotifications',
        'HideContinueButtons',
        'HideReportButton',
        'IgnoreFrameNavigation',
        'CacheExpirationSeconds',
        'LockProtectionOptions',
        'HideProtectionOptions',

        // Official Partners
        'AdGuardSecurityEnabled',
        'AdGuardFamilyEnabled',
        'ControlDSecurityEnabled',
        'ControlDFamilyEnabled',
        'PrecisionSecEnabled',

        // Non-Partnered Providers
        'GDATAEnabled',
        'CERTEEEnabled',
        'CIRASecurityEnabled',
        'CIRAFamilyEnabled',
        'CleanBrowsingSecurityEnabled',
        'CleanBrowsingFamilyEnabled',
        'CleanBrowsingAdultEnabled',
        'CloudflareSecurityEnabled',
        'CloudflareFamilyEnabled',
        'DNS0SecurityEnabled',
        'DNS0KidsEnabled',
        'DNS4EUSecurityEnabled',
        'DNS4EUFamilyEnabled',
        'SmartScreenEnabled',
        'NortonEnabled',
        'OpenDNSSecurityEnabled',
        'OpenDNSFamilyShieldEnabled',
        'Quad9Enabled',
        'SwitchCHEnabled',
    ];

    // Creates the context menu and sets managed policies
    browserAPI.storage.managed.get(policyKeys, policies => {
        if (typeof policies === 'undefined') {
            supportsManagedPolicies = false;
            console.debug("Managed policies are not supported or setup correctly in this browser.");
        } else {
            supportsManagedPolicies = true;
            let settings = {};

            // Check and set the context menu settings using the policy.
            if (policies.DisableContextMenu === undefined) {
                settings.contextMenuEnabled = true;
            } else {
                if (policies.DisableContextMenu === true) {
                    settings.contextMenuEnabled = false;
                    console.debug("Context menu is disabled by system policy.");
                } else {
                    settings.contextMenuEnabled = true;
                }
            }

            // Check and set the cache expiration time using the policy.
            if (policies.CacheExpirationSeconds === undefined) {
                settings.cacheExpirationSeconds = 86400; // Default to 24 hours
            } else {
                if (typeof policies.CacheExpirationSeconds !== "number" || policies.CacheExpirationSeconds < 60) {
                    console.debug("Cache expiration time is invalid; using default value.");
                    settings.cacheExpirationSeconds = 86400;
                } else {
                    settings.cacheExpirationSeconds = policies.CacheExpirationSeconds;
                    console.debug("Cache expiration time set to: " + policies.CacheExpirationSeconds);
                }
            }

            // Check and set the continue buttons settings using the policy.
            if (policies.HideContinueButtons === undefined) {
                settings.hideContinueButtons = false;
            } else {
                if (policies.HideContinueButtons === true) {
                    settings.hideContinueButtons = policies.HideContinueButtons;
                    console.debug("Continue buttons are managed by system policy.");
                } else {
                    settings.hideContinueButtons = false;
                }
            }

            // Check and set the report button settings using the policy.
            if (policies.HideReportButton === undefined) {
                settings.hideReportButton = false;
            } else {
                if (policies.HideReportButton === true) {
                    settings.hideReportButton = policies.HideReportButton;
                    console.debug("Report button is managed by system policy.");
                } else {
                    settings.hideReportButton = false;
                }
            }

            // Check and set the lock protection options using the policy.
            if (policies.LockProtectionOptions === undefined) {
                settings.lockProtectionOptions = false;
            } else {
                if (policies.HideProtectionOptions === true) {
                    settings.lockProtectionOptions = policies.LockProtectionOptions;
                    console.debug("Protection options are locked by system policy.");
                } else {
                    settings.lockProtectionOptions = false;
                }
            }

            // Check and set the hide protection options using the policy.
            if (policies.HideProtectionOptions === undefined) {
                settings.hideProtectionOptions = false;
            } else {
                if (policies.HideProtectionOptions === true) {
                    settings.hideProtectionOptions = policies.HideProtectionOptions;
                    console.debug("Protection options are hidden by system policy.");
                } else {
                    settings.hideProtectionOptions = false;
                }
            }

            // Check and set the AdGuard Security settings using the policy.
            if (policies.AdGuardSecurityEnabled !== undefined) {
                settings.adGuardSecurityEnabled = policies.AdGuardSecurityEnabled;
                console.debug("AdGuard Security is managed by system policy.");
            }

            // Check and set the AdGuard Family settings using the policy.
            if (policies.AdGuardFamilyEnabled !== undefined) {
                settings.adGuardFamilyEnabled = policies.AdGuardFamilyEnabled;
                console.debug("AdGuard Family is managed by system policy.");
            }

            // Check and set the Control D Security settings using the policy.
            if (policies.ControlDSecurityEnabled !== undefined) {
                settings.controlDSecurityEnabled = policies.ControlDSecurityEnabled;
                console.debug("Control D Security is managed by system policy.");
            }

            // Check and set the Control D Family settings using the policy.
            if (policies.ControlDFamilyEnabled !== undefined) {
                settings.controlDFamilyEnabled = policies.ControlDFamilyEnabled;
                console.debug("Control D Family is managed by system policy.");
            }

            // Check and set the PrecisionSec settings using the policy.
            if (policies.PrecisionSecEnabled !== undefined) {
                settings.precisionSecEnabled = policies.PrecisionSecEnabled;
                console.debug("PrecisionSec is managed by system policy.");
            }

            // Check and set the G DATA settings using the policy.
            if (policies.GDATAEnabled !== undefined) {
                settings.gDataEnabled = policies.GDATAEnabled;
                console.debug("G DATA is managed by system policy.");
            }

            // Check and set the CERT-EE settings using the policy.
            if (policies.CERTEEEnabled !== undefined) {
                settings.certEEEnabled = policies.CERTEEEnabled;
                console.debug("CERT-EE is managed by system policy.");
            }

            // Check and set the CIRA Security settings using the policy.
            if (policies.CIRASecurityEnabled !== undefined) {
                settings.ciraSecurityEnabled = policies.CIRASecurityEnabled;
                console.debug("CIRA Security is managed by system policy.");
            }

            // Check and set the CIRA Family settings using the policy.
            if (policies.CIRAFamilyEnabled !== undefined) {
                settings.ciraFamilyEnabled = policies.CIRAFamilyEnabled;
                console.debug("CIRA Family is managed by system policy.");
            }

            // Check and set the CleanBrowsing Security settings using the policy.
            if (policies.CleanBrowsingSecurityEnabled !== undefined) {
                settings.cleanBrowsingSecurityEnabled = policies.CleanBrowsingSecurityEnabled;
                console.debug("CleanBrowsing Security is managed by system policy.");
            }

            // Check and set the CleanBrowsing Family settings using the policy.
            if (policies.CleanBrowsingFamilyEnabled !== undefined) {
                settings.cleanBrowsingFamilyEnabled = policies.CleanBrowsingFamilyEnabled;
                console.debug("CleanBrowsing Family is managed by system policy.");
            }

            // Check and set the CleanBrowsing Adult settings using the policy.
            if (policies.CleanBrowsingAdultEnabled !== undefined) {
                settings.cleanBrowsingAdultEnabled = policies.CleanBrowsingAdultEnabled;
                console.debug("CleanBrowsing Adult is managed by system policy.");
            }

            // Check and set the Cloudflare Security settings using the policy.
            if (policies.CloudflareSecurityEnabled !== undefined) {
                settings.cloudflareSecurityEnabled = policies.CloudflareSecurityEnabled;
                console.debug("Cloudflare Security is managed by system policy.");
            }

            // Check and set the Cloudflare Family settings using the policy.
            if (policies.CloudflareFamilyEnabled !== undefined) {
                settings.cloudflareFamilyEnabled = policies.CloudflareFamilyEnabled;
                console.debug("Cloudflare Family is managed by system policy.");
            }

            // Check and set the DNS0.eu Security settings using the policy.
            if (policies.DNS0SecurityEnabled !== undefined) {
                settings.dns0SecurityEnabled = policies.DNS0SecurityEnabled;
                console.debug("DNS0.eu Security is managed by system policy.");
            }

            // Check and set the DNS0.eu Kids settings using the policy.
            if (policies.DNS0KidsEnabled !== undefined) {
                settings.dns0KidsEnabled = policies.DNS0KidsEnabled;
                console.debug("DNS0.eu Kids is managed by system policy.");
            }

            // Check and set the DNS4EU Security settings using the policy.
            if (policies.DNS4EUSecurityEnabled !== undefined) {
                settings.dns4EUSecurityEnabled = policies.DNS4EUSecurityEnabled;
                console.debug("DNS4EU Security is managed by system policy.");
            }

            // Check and set the DNS4EU Family settings using the policy.
            if (policies.DNS4EUFamilyEnabled !== undefined) {
                settings.dns4EUFamilyEnabled = policies.DNS4EUFamilyEnabled;
                console.debug("DNS4EU Family is managed by system policy.");
            }

            // Check and set the SmartScreen settings using the policy.
            if (policies.SmartScreenEnabled !== undefined) {
                settings.smartScreenEnabled = policies.SmartScreenEnabled;
                console.debug("SmartScreen is managed by system policy.");
            }

            // Check and set the Norton settings using the policy.
            if (policies.NortonEnabled !== undefined) {
                settings.nortonEnabled = policies.NortonEnabled;
                console.debug("Norton is managed by system policy.");
            }

            // Check and set the OpenDNS Security settings using the policy.
            if (policies.OpenDNSSecurityEnabled !== undefined) {
                settings.openDNSSecurityEnabled = policies.OpenDNSSecurityEnabled;
                console.debug("OpenDNS Security is managed by system policy.");
            }

            // Check and set the OpenDNS Family Shield settings using the policy.
            if (policies.OpenDNSFamilyShieldEnabled !== undefined) {
                settings.openDNSFamilyShieldEnabled = policies.OpenDNSFamilyShieldEnabled;
                console.debug("OpenDNS Family Shield is managed by system policy.");
            }

            // Check and set the Quad9 settings using the policy.
            if (policies.Quad9Enabled !== undefined) {
                settings.quad9Enabled = policies.Quad9Enabled;
                console.debug("Quad9 is managed by system policy.");
            }

            // Check and set the Switch.ch settings using the policy.
            if (policies.SwitchCHEnabled !== undefined) {
                settings.switchCHEnabled = policies.SwitchCHEnabled;
                console.debug("Switch.ch is managed by system policy.");
            }

            // Finally, if there are any updates, update the stored settings in one go.
            if (Object.keys(settings).length > 0) {
                Settings.set(settings, () => {
                    console.debug("Updated settings on install: ", settings);
                });
            }
        }

        // Create the context menu.
        createContextMenu();
    });

    browserAPI.tabs.onRemoved.addListener((tabId, removeInfo) => {
        console.debug(`Tab removed: ${tabId} (windowId: ${removeInfo.windowId}) (isWindowClosing: ${removeInfo.isWindowClosing})`);

        // Remove all cached keys for the tab.
        BrowserProtection.cacheManager.removeKeysByTabId(tabId);
        resultCounts.delete(tabId);
        resultSystemNames.delete(tabId);
    });

    browserAPI.tabs.onReplaced.addListener((addedTabId, removedTabId) => {
        console.debug(`Tab replaced: ${removedTabId} with ${addedTabId}`);
    });

    // Listener for onBeforeNavigate events.
    browserAPI.webNavigation.onBeforeNavigate.addListener(navigationDetails => {
        console.debug(`[onBeforeNavigate] ${navigationDetails.url} (frameId: ${navigationDetails.frameId}) (tabId: ${navigationDetails.tabId})`);
        handleNavigation(navigationDetails);
    });

    // Listener for onCommitted events.
    browserAPI.webNavigation.onCommitted.addListener(navigationDetails => {
        if (navigationDetails.transitionQualifiers.includes("server_redirect")) {
            console.debug(`[server_redirect] ${navigationDetails.url} (frameId: ${navigationDetails.frameId}) (tabId: ${navigationDetails.tabId})`);
            handleNavigation(navigationDetails);
        } else if (navigationDetails.transitionQualifiers.includes("client_redirect")) {
            console.debug(`[client_redirect] ${navigationDetails.url} (frameId: ${navigationDetails.frameId}) (tabId: ${navigationDetails.tabId})`);
            handleNavigation(navigationDetails);
        }
    });

    // Listener for onHistoryStateUpdated events.
    browserAPI.webNavigation.onHistoryStateUpdated.addListener(navigationDetails => {
        console.debug(`[onHistoryStateUpdated] ${navigationDetails.url} (frameId: ${navigationDetails.frameId}) (tabId: ${navigationDetails.tabId})`);
        handleNavigation(navigationDetails);
    });

    // Listener for onReferenceFragmentUpdated events.
    browserAPI.webNavigation.onReferenceFragmentUpdated.addListener(navigationDetails => {
        console.debug(`[onReferenceFragmentUpdated] ${navigationDetails.url} (frameId: ${navigationDetails.frameId}) (tabId: ${navigationDetails.tabId})`);
        handleNavigation(navigationDetails);
    });

    // Listener for onTabReplaced events.
    browserAPI.webNavigation.onTabReplaced.addListener(navigationDetails => {
        console.debug(`[onTabReplaced] ${navigationDetails.url} (frameId: ${navigationDetails.frameId}) (tabId: ${navigationDetails.tabId})`);
        handleNavigation(navigationDetails);
    });

    // Listener for incoming messages.
    browserAPI.runtime.onMessage.addListener((message, sender) => {
        // Check if the message is valid and has a message type.
        if (!(message && message.messageType)) {
            return;
        }

        switch (message.messageType) {
            case Messages.MessageType.CONTINUE_TO_SITE: {
                if (!message.blockedUrl) {
                    console.debug(`No blocked URL was found; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                if (!message.origin) {
                    console.debug(`No origin was found; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                let blockedUrlObject = new URL(message.blockedUrl);

                // Redirects to the new tab page if the blocked URL is not a valid HTTP(S) URL.
                if (!validProtocols.includes(blockedUrlObject.protocol)) {
                    console.debug(`Invalid protocol in blocked URL: ${message.blockedUrl}; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                switch (message.origin) {
                    case "1":
                        console.debug(`Added AdGuard Security URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "adGuardSecurity");

                        console.debug(`Removed AdGuard Security URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "adGuardSecurity");
                        break;

                    case "2":
                        console.debug(`Added AdGuard Family URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "adGuardFamily");

                        console.debug(`Removed AdGuard Family URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "adGuardFamily");
                        break;

                    case "3":
                        console.debug(`Added Control D Security URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "controlDSecurity");

                        console.debug(`Removed Control D Security URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "controlDSecurity");
                        break;

                    case "4":
                        console.debug(`Added Control D Family URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "controlDFamily");

                        console.debug(`Removed Control D Family URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "controlDFamily");
                        break;

                    case "5":
                        console.debug(`Added PrecisionSec URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "precisionSec");

                        console.debug(`Removed PrecisionSec URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "precisionSec");
                        break;

                    case "6":
                        console.debug(`Added G DATA URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "gData");

                        console.debug(`Removed G DATA URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "gData");
                        break;

                    case "7":
                        console.debug(`Added CERT-EE URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "certEE");

                        console.debug(`Removed CERT-EE URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "certEE");
                        break;

                    case "8":
                        console.debug(`Added CIRA Security URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "ciraSecurity");

                        console.debug(`Removed CIRA Security URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "ciraSecurity");
                        break;

                    case "9":
                        console.debug(`Added CIRA Family URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "ciraFamily");

                        console.debug(`Removed CIRA Family URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "ciraFamily");
                        break;

                    case "10":
                        console.debug(`Added CleanBrowsing Security URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "cleanBrowsingSecurity");

                        console.debug(`Removed CleanBrowsing Security URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "cleanBrowsingSecurity");
                        break;

                    case "11":
                        console.debug(`Added CleanBrowsing Family URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "cleanBrowsingFamily");

                        console.debug(`Removed CleanBrowsing Family URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "cleanBrowsingFamily");
                        break;

                    case "12":
                        console.debug(`Added CleanBrowsing Adult URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "cleanBrowsingAdult");

                        console.debug(`Removed CleanBrowsing Adult URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "cleanBrowsingAdult");
                        break;

                    case "13":
                        console.debug(`Added Cloudflare Security URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "cloudflareSecurity");

                        console.debug(`Removed Cloudflare Security URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "cloudflareSecurity");
                        break;

                    case "14":
                        console.debug(`Added Cloudflare Family URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "cloudflareFamily");

                        console.debug(`Removed Cloudflare Family URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "cloudflareFamily");
                        break;

                    case "15":
                        console.debug(`Added DNS0.eu Security URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "dns0Security");

                        console.debug(`Removed DNS0.eu Security URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "dns0Security");
                        break;

                    case "16":
                        console.debug(`Added DNS0.eu Kids URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "dns0Kids");

                        console.debug(`Removed DNS0.eu Kids URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "dns0Kids");
                        break;

                    case "17":
                        console.debug(`Added DNS4EU Security URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "dns4EUSecurity");

                        console.debug(`Removed DNS4EU Security URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "dns4EUSecurity");
                        break;

                    case "18":
                        console.debug(`Added DNS4EU Family URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "dns4EUFamily");

                        console.debug(`Removed DNS4EU Family URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "dns4EUFamily");
                        break;

                    case "19":
                        console.debug(`Added SmartScreen URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "smartScreen");

                        console.debug(`Removed SmartScreen URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "smartScreen");
                        break;

                    case "20":
                        console.debug(`Added Norton URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "norton");

                        console.debug(`Removed Norton URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "norton");
                        break;

                    case "21":
                        console.debug(`Added OpenDNS Security URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "openDNSSecurity");

                        console.debug(`Removed OpenDNS Security URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "openDNSSecurity");
                        break;

                    case "22":
                        console.debug(`Added OpenDNS Family Shield URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "openDNSFamilyShield");

                        console.debug(`Removed OpenDNS Family Shield URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "openDNSFamilyShield");
                        break;

                    case "23":
                        console.debug(`Added Quad9 URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "quad9");

                        console.debug(`Removed Quad9 URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "quad9");
                        break;

                    case "24":
                        console.debug(`Added Switch.ch URL to allowed cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "switchCH");

                        console.debug(`Removed Switch.ch URL from blocked cache: ` + message.blockedUrl);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "switchCH");
                        break;

                    default:
                        console.warn(`Unknown origin: ${message.origin}`);
                        break;
                }

                browserAPI.tabs.update(sender.tab.id, {url: message.blockedUrl});
                break;
            }

            case Messages.MessageType.CONTINUE_TO_SAFETY: {
                setTimeout(() => {
                    sendToNewTabPage(sender.tab.id);
                }, 200);
                break;
            }

            case Messages.MessageType.REPORT_SITE: {
                // Ignores blank report URLs.
                if (message.reportUrl === null || message.reportUrl === "") {
                    console.debug(`Report URL is blank.`);
                    break;
                }

                if (!message.origin) {
                    console.debug(`No origin was found; doing nothing.`);
                    break;
                }

                let reportUrlObject = new URL(message.reportUrl);

                if (validProtocols.includes(reportUrlObject.protocol)) {
                    console.debug(`Navigating to report URL: ${message.reportUrl}`);
                    browserAPI.tabs.create({url: message.reportUrl});
                } else {
                    // Ignore the mailto: protocol.
                    if (reportUrlObject.protocol === "mailto:") {
                        browserAPI.tabs.create({url: message.reportUrl});
                    } else {
                        console.warn(`Invalid protocol in report URL: ${message.reportUrl}; doing nothing.`);
                    }
                }
                break;
            }

            case Messages.MessageType.ALLOW_SITE: {
                // Ignores blank blocked URLs.
                if (message.blockedUrl === null || message.blockedUrl === "") {
                    console.debug(`Blocked URL is blank.`);
                    break;
                }

                if (!message.origin) {
                    console.debug(`No origin was found; sending to the new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    break;
                }

                let blockedUrl = new URL(message.blockedUrl);
                const hostnameString = blockedUrl.hostname + " (allowed)";

                // Adds the hostname to every allowed cache.
                console.debug("Adding hostname to every allowed cache: " + hostnameString);
                BrowserProtection.cacheManager.addStringToAllowedCache(hostnameString, "all");

                // Removes the hostname from every blocked cache.
                console.debug("Removing hostname from every blocked cache: " + hostnameString);
                BrowserProtection.cacheManager.removeStringFromBlockedCache(hostnameString, "all");

                // Redirects to the new tab page if the blocked URL is not a valid HTTP(S) URL.
                if (!validProtocols.includes(blockedUrl.protocol)) {
                    console.debug(`Invalid protocol in blocked URL: ${message.blockedUrl}; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                browserAPI.tabs.update(sender.tab.id, {url: message.blockedUrl});
                break;
            }

            case Messages.MessageType.ADGUARD_FAMILY_TOGGLED:
            case Messages.MessageType.ADGUARD_SECURITY_TOGGLED:
            case Messages.MessageType.CERT_EE_TOGGLED:
            case Messages.MessageType.CIRA_FAMILY_TOGGLED:
            case Messages.MessageType.CIRA_SECURITY_TOGGLED:
            case Messages.MessageType.CLEANBROWSING_ADULT_TOGGLED:
            case Messages.MessageType.CLEANBROWSING_FAMILY_TOGGLED:
            case Messages.MessageType.CLEANBROWSING_SECURITY_TOGGLED:
            case Messages.MessageType.CLOUDFLARE_FAMILY_TOGGLED:
            case Messages.MessageType.CLOUDFLARE_SECURITY_TOGGLED:
            case Messages.MessageType.CONTROL_D_FAMILY_TOGGLED:
            case Messages.MessageType.CONTROL_D_SECURITY_TOGGLED:
            case Messages.MessageType.DNS0_KIDS_TOGGLED:
            case Messages.MessageType.DNS0_SECURITY_TOGGLED:
            case Messages.MessageType.DNS4EU_FAMILY_TOGGLED:
            case Messages.MessageType.DNS4EU_SECURITY_TOGGLED:
            case Messages.MessageType.G_DATA_TOGGLED:
            case Messages.MessageType.NORTON_TOGGLED:
            case Messages.MessageType.OPENDNS_FAMILY_SHIELD_TOGGLED:
            case Messages.MessageType.OPENDNS_SECURITY_TOGGLED:
            case Messages.MessageType.PRECISIONSEC_TOGGLED:
            case Messages.MessageType.QUAD9_TOGGLED:
            case Messages.MessageType.SMARTSCREEN_TOGGLED:
            case Messages.MessageType.SWITCH_CH_TOGGLED:
                console.info(`${message.title} has been ${message.toggleState ? "enabled" : "disabled"}.`);
                break;

            case Messages.MessageType.BLOCKED_COUNTER_PING:
            case Messages.MessageType.BLOCKED_COUNTER_PONG:
                // This message type is used for blocked counter pings and pongs.
                break;

            default:
                console.warn(`Received unknown message type: ${message.messageType}`);
                console.warn(`Message: ${JSON.stringify(message)}`);
                break;
        }
    });

    // Listener for context menu creation.
    contextMenuAPI.onClicked.addListener(info => {
        switch (info.menuItemId) {
            case "toggleNotifications":
                Settings.set({notificationsEnabled: info.checked});
                console.debug("Notifications: " + info.checked);
                break;

            case "toggleFrameNavigation":
                Settings.set({ignoreFrameNavigation: info.checked});
                console.debug("Ignoring frame navigation: " + info.checked);
                break;

            case "clearAllowedSites":
                BrowserProtection.cacheManager.clearAllowedCache();
                console.debug("Cleared all allowed site caches.");

                // Create a notification to inform the user.
                const notificationOptions = {
                    type: "basic",
                    iconUrl: "assets/icons/icon128.png",
                    title: "Allowed Sites Cleared",
                    message: "All allowed sites have been cleared.",
                    priority: 2,
                };

                const randomNumber = Math.floor(Math.random() * 100000000);
                const notificationId = `cache-cleared-${randomNumber}`;

                browserAPI.notifications.create(notificationId, notificationOptions, id => {
                    console.debug(`Notification created with ID: ${id}`);
                });
                break;

            default:
                break;
        }
    });

    /**
     * Creates the context menu for the extension.
     */
    function createContextMenu() {
        Settings.get(settings => {
            // First remove existing menu items to avoid duplicates.
            contextMenuAPI.removeAll();

            // If the context menu is disabled by policy, do not create it.
            if (!settings.contextMenuEnabled) {
                return;
            }

            // Create the toggle notifications menu item
            contextMenuAPI.create({
                id: "toggleNotifications",
                title: "Enable notifications",
                type: "checkbox",
                checked: settings.notificationsEnabled,
                contexts: ["action"],
            });

            // Create the toggle frame navigation menu item
            contextMenuAPI.create({
                id: "toggleFrameNavigation",
                title: "Ignore frame navigation",
                type: "checkbox",
                checked: settings.ignoreFrameNavigation,
                contexts: ["action"],
            });

            // Create the clear allowed sites menu item
            contextMenuAPI.create({
                id: "clearAllowedSites",
                title: "Clear list of allowed sites",
                contexts: ["action"],
            });

            // Returns early if managed policies are not supported.
            if (!supportsManagedPolicies) {
                return;
            }

            // Gather the policy values for updating the context menu.
            const policyKeys = [
                "DisableNotifications",
                "DisableClearAllowedSites",
                "IgnoreFrameNavigation"
            ];

            browserAPI.storage.managed.get(policyKeys, policies => {
                let updatedSettings = {};

                // Check if the enable notifications button should be disabled.
                if (policies.DisableNotifications !== undefined) {
                    contextMenuAPI.update("toggleNotifications", {
                        enabled: false,
                        checked: !policies.DisableNotifications,
                    });

                    updatedSettings.notificationsEnabled = !policies.DisableNotifications;
                    console.debug("Notifications are managed by system policy.");
                }

                // Check if the ignore frame navigation button should be disabled.
                if (policies.IgnoreFrameNavigation !== undefined) {
                    contextMenuAPI.update("toggleFrameNavigation", {
                        enabled: false,
                        checked: policies.IgnoreFrameNavigation,
                    });

                    updatedSettings.ignoreFrameNavigation = policies.IgnoreFrameNavigation;
                    console.debug("Ignoring frame navigation is managed by system policy.");
                }

                // Check if the clear allowed sites button should be disabled.
                if (policies.DisableClearAllowedSites !== undefined && policies.DisableClearAllowedSites) {
                    contextMenuAPI.update("clearAllowedSites", {
                        enabled: false,
                    });

                    console.debug("Clear allowed sites button is managed by system policy.");
                }

                // Update settings cumulatively if any policy-based changes were made.
                if (Object.keys(updatedSettings).length > 0) {
                    Settings.set(updatedSettings, () => {
                        console.debug("Updated settings from context menu creation:", updatedSettings);
                    });
                }
            });
        });
    }

    /**
     * Sends the user to the new tab page.
     *
     * @param {number} tabId - The ID of the tab to be closed. (Firefox only)
     */
    function sendToNewTabPage(tabId) {
        if (isFirefox) {
            browserAPI.tabs.remove(tabId);
            browserAPI.tabs.create({});
        } else {
            browserAPI.tabs.update(tabId, {url: "about:newtab"});
        }
    }
})();
