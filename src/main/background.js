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

// noinspection JSDeprecatedSymbols
(() => {
    // Browser API compatibility between Chrome and Firefox
    const isFirefox = typeof browser !== 'undefined';
    const browserAPI = isFirefox ? browser : chrome;
    const contextMenuAPI = isFirefox ? browserAPI.menus : browserAPI.contextMenus;
    let supportsManagedPolicies = true;

    // Maps for tab-related functions
    const resultSystemNames = new Map();
    const frameZeroURLs = new Map();

    // Interval for map cleanups
    const CLEANUP_INTERVAL = 1800000; // 30 minutes

    // Cleans up maps automatically
    setInterval(() => {
        console.debug(`Cleaning up maps...`);
        console.debug(`[BEFORE] resultSystemNames: ${resultSystemNames.keys().toArray().toString()}`);
        console.debug(`[BEFORE] frameZeroURLs: ${frameZeroURLs.keys().toArray().toString()}`);

        browserAPI.tabs.query({}, tabs => {
            const activeTabIds = new Set(tabs.map(tab => tab.id));

            // Deletes inactive tabs from local maps
            for (const [tabId] of resultSystemNames) {
                if (!activeTabIds.has(tabId)) {
                    resultSystemNames.delete(tabId);
                    frameZeroURLs.delete(tabId);
                }
            }
        });

        console.debug(`[AFTER] resultSystemNames: ${resultSystemNames.keys().toArray().toString()}`);
        console.debug(`[AFTER] frameZeroURLs: ${frameZeroURLs.keys().toArray().toString()}`);
    }, CLEANUP_INTERVAL);

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
        console.debug(`Error: ${error}`);
    }

    // Initializes the BrowserProtection module's API keys
    BrowserProtection.initializeKeys();

    // List of valid protocols to check for
    const validProtocols = ['http:', 'https:'];

    /**
     * Function to handle navigation checks.
     *
     * @param navigationDetails - The navigation details to handle.
     */
    function handleNavigation(navigationDetails) {
        Settings.get(settings => {
            // Retrieves settings to check if protection is enabled.
            if (!settings.adGuardSecurityEnabled &&
                !settings.adGuardFamilyEnabled &&
                !settings.alphaMountainEnabled &&
                !settings.certEEEnabled &&
                !settings.ciraFamilyEnabled &&
                !settings.ciraSecurityEnabled &&
                !settings.cleanBrowsingAdultEnabled &&
                !settings.cleanBrowsingFamilyEnabled &&
                !settings.cleanBrowsingSecurityEnabled &&
                !settings.cloudflareFamilyEnabled &&
                !settings.cloudflareSecurityEnabled &&
                !settings.controlDFamilyEnabled &&
                !settings.controlDSecurityEnabled &&
                !settings.dns0KidsEnabled &&
                !settings.dns0SecurityEnabled &&
                !settings.dns4EUFamilyEnabled &&
                !settings.dns4EUSecurityEnabled &&
                !settings.gDataEnabled &&
                !settings.nortonEnabled &&
                !settings.openDNSFamilyShieldEnabled &&
                !settings.openDNSSecurityEnabled &&
                !settings.precisionSecEnabled &&
                !settings.quad9Enabled &&
                !settings.smartScreenEnabled &&
                !settings.switchCHEnabled) {
                console.debug("Protection is disabled; bailing out early.");
                return;
            }

            let {tabId, frameId, url: currentUrl} = navigationDetails;

            // Checks if the frame ID is not the main frame.
            if (settings.ignoreFrameNavigation && frameId !== 0) {
                console.debug(`Ignoring frame navigation: ${currentUrl} #${frameId}; bailing out.`);
                return;
            }

            // Checks if the URL is missing or incomplete.
            if (!currentUrl || !currentUrl.includes('://')) {
                console.debug(`Incomplete or missing URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Removes the blob: prefix from the URL.
            currentUrl = currentUrl.replace(/^blob:http/, 'http');

            // Removes trailing slashes from the URL.
            currentUrl = currentUrl.replace(/\/+$/, '');

            // Removes www. from the start of the URL.
            currentUrl = currentUrl.replace(/https?:\/\/www\./, 'https://');

            // Removes query parameters, fragments (#) and & tags from the URL.
            currentUrl = currentUrl.replace(/[?#&].*$/, '');

            // Sanitizes and encodes the URL to handle spaces and special characters.
            try {
                currentUrl = encodeURI(currentUrl);
            } catch (error) {
                console.warn(`Failed to encode URL: ${currentUrl}; bailing out: ${error}`);
                return;
            }

            // Parses the URL object.
            let urlObject;
            try {
                urlObject = new URL(currentUrl);
            } catch (error) {
                console.warn(`Invalid URL format: ${currentUrl}; bailing out: ${error}`);
                return;
            }

            const protocol = urlObject.protocol;
            let hostname = urlObject.hostname;

            // Checks for incomplete URLs missing the scheme.
            if (!protocol || currentUrl.startsWith('//')) {
                console.warn(`URL is missing a scheme: ${currentUrl}; bailing out.`);
                return;
            }

            // Checks for valid protocols.
            if (!validProtocols.includes(protocol.toLowerCase())) {
                console.debug(`Invalid protocol: ${protocol}; bailing out.`);
                return;
            }

            // Checks for missing hostname.
            if (!hostname) {
                console.warn(`Missing hostname in URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Checks for missing the suffix.
            if (hostname.endsWith('.')) {
                console.warn(`Missing suffix in URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Excludes internal network addresses, loopback, or reserved domains.
            if (isInternalAddress(hostname)) {
                console.warn(`Local/internal network URL detected: ${currentUrl}; bailing out.`);
                return;
            }

            // Cancels all pending requests for the main frame navigation.
            if (frameId === 0) {
                BrowserProtection.abandonPendingRequests(tabId, "Cancelled by main frame navigation.");

                // Remove all cached keys for the tab.
                BrowserProtection.cacheManager.removeKeysByTabId(tabId);
                resultSystemNames.delete(tabId);

                // Reset the frame zero URLs for the tab.
                frameZeroURLs.delete(tabId);
                frameZeroURLs.set(tabId, currentUrl);
            }

            // Sets the hostname back to the URL object.
            urlObject.hostname = hostname;

            let blocked = false;
            let firstSystemName = "";
            resultSystemNames.set(tabId, []);

            console.info(`Checking URL: ${currentUrl}`);

            // Checks if the URL is malicious.
            BrowserProtection.checkIfUrlIsMalicious(tabId, currentUrl, (result, duration) => {
                const cacheName = ProtectionResult.CacheOriginNames[result.origin];
                const systemName = ProtectionResult.ShortOriginNames[result.origin];
                const resultType = result.result;

                // Removes the URL from the system's processing cache on every callback.
                // Doesn't remove it if the result is still waiting for a response.
                if (resultType !== ProtectionResult.ResultType.WAITING) {
                    BrowserProtection.cacheManager.removeUrlFromProcessingCache(urlObject, cacheName);
                }

                console.info(`[${systemName}] Result for ${currentUrl}: ${resultType} (${duration}ms)`);

                if (resultType !== ProtectionResult.ResultType.FAILED &&
                    resultType !== ProtectionResult.ResultType.WAITING &&
                    resultType !== ProtectionResult.ResultType.KNOWN_SAFE &&
                    resultType !== ProtectionResult.ResultType.ALLOWED) {

                    if (!blocked) {
                        browserAPI.tabs.get(tabId, tab => {
                            if (!tab) {
                                console.debug(`tabs.get(${tabId}) failed '${browserAPI.runtime.lastError?.message}'; bailing out.`);
                                return;
                            }

                            const pendingUrl = tab.pendingUrl || tab.url;

                            // Checks if the tab is at an extension page
                            if (!(currentUrl !== pendingUrl && frameId === 0)) {
                                if (pendingUrl.startsWith("chrome-extension:") ||
                                    pendingUrl.startsWith("moz-extension:") ||
                                    pendingUrl.startsWith("extension:")) {
                                    console.debug(`[${systemName}] The tab is at an extension page; bailing out. ${pendingUrl} ${frameId}`);
                                    return;
                                }
                            }

                            const targetUrl = frameId === 0 ? currentUrl : pendingUrl;

                            if (targetUrl) {
                                const blockPageUrl = UrlHelpers.getBlockPageUrl(result, frameZeroURLs.get(tabId) === undefined ? result.url : frameZeroURLs.get(tabId));

                                // Navigates to the block page
                                console.debug(`[${systemName}] Navigating to block page: ${blockPageUrl}.`);
                                browserAPI.tabs.update(tab.id, {url: blockPageUrl}).catch(error => {
                                    console.error(`Failed to update tab ${tabId}:`, error);
                                    sendToNewTabPage(tabId);
                                });

                                // Builds the warning notification options
                                if (settings.notificationsEnabled) {
                                    const notificationOptions = {
                                        type: "basic",
                                        iconUrl: "assets/icons/icon128.png",
                                        title: "Unsafe Website Blocked",
                                        message: `URL: ${currentUrl}\nReason: ${resultType}\nReported by: ${systemName}`,
                                        priority: 2,
                                    };

                                    // Creates a unique notification ID based on a random number
                                    const randomNumber = Math.floor(Math.random() * 100000000);
                                    const notificationId = `warning-${randomNumber}`;

                                    // Displays the warning notification
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

                    // Tracks the system name that flagged the URL
                    const existingSystems = resultSystemNames.get(tabId) || [];
                    if (!existingSystems.includes(systemName) && systemName !== firstSystemName) {
                        existingSystems.push(systemName);
                        resultSystemNames.set(tabId, existingSystems);
                    }

                    // Iterates through the results and update the counts.
                    const fullCount = resultSystemNames.get(tabId).length + 1 || 0;

                    setTimeout(() => {
                        // Sets the action text to the result count.
                        browserAPI.action.setBadgeText({
                            text: `${fullCount}`,
                            tabId: tabId
                        });

                        // Sets the action background color to red.
                        browserAPI.action.setBadgeBackgroundColor({
                            color: "rgb(255,75,75)",
                            tabId: tabId
                        });

                        // Sets the action text color to white.
                        browserAPI.action.setBadgeTextColor({
                            color: "white",
                            tabId: tabId
                        });

                        // If the page URL is the block page, send (count - 1)
                        browserAPI.tabs.get(tabId, tab => {
                            const isBlockPage = tab.url?.includes("/WarningPage.html");
                            const adjustedCount = isBlockPage && fullCount > 0 ? fullCount - 1 : fullCount;

                            // Sends a PONG message to the content script to update the blocked counter.
                            browserAPI.tabs.sendMessage(tabId, {
                                messageType: Messages.MessageType.BLOCKED_COUNTER_PONG,
                                count: adjustedCount,
                                systems: resultSystemNames.get(tabId) || []
                            });
                        });
                    }, 150);
                }
            });
        });
    }

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
        'AlphaMountainEnabled',
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

            // Checks and sets the context menu settings using the policy
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

            // Checks and sets the cache expiration time using the policy
            if (policies.CacheExpirationSeconds === undefined) {
                settings.cacheExpirationSeconds = 86400; // Default to 24 hours
            } else {
                if (typeof policies.CacheExpirationSeconds !== "number" || policies.CacheExpirationSeconds < 60) {
                    settings.cacheExpirationSeconds = 86400;
                    console.debug("Cache expiration time is invalid; using default value.");
                } else {
                    settings.cacheExpirationSeconds = policies.CacheExpirationSeconds;
                    console.debug(`Cache expiration time set to: ${policies.CacheExpirationSeconds}`);
                }
            }

            // Checks and sets the continue buttons settings using the policy
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

            // Checks and sets the report button settings using the policy
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

            // Checks and sets the lock protection options using the policy
            if (policies.LockProtectionOptions === undefined) {
                settings.lockProtectionOptions = false;
            } else {
                if (policies.LockProtectionOptions === true) {
                    settings.lockProtectionOptions = policies.LockProtectionOptions;
                    console.debug("Protection options are locked by system policy.");
                } else {
                    settings.lockProtectionOptions = false;
                }
            }

            // Checks and sets the hide protection options using the policy
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

            // Checks and sets the AdGuard Security settings using the policy
            if (policies.AdGuardSecurityEnabled !== undefined) {
                settings.adGuardSecurityEnabled = policies.AdGuardSecurityEnabled;
                console.debug("AdGuard Security is managed by system policy.");
            }

            // Checks and sets the AdGuard Family settings using the policy
            if (policies.AdGuardFamilyEnabled !== undefined) {
                settings.adGuardFamilyEnabled = policies.AdGuardFamilyEnabled;
                console.debug("AdGuard Family is managed by system policy.");
            }

            // Checks and sets the alphaMountain settings using the policy
            if (policies.AlphaMountainEnabled !== undefined) {
                settings.alphaMountainEnabled = policies.AlphaMountainEnabled;
                console.debug("alphaMountain Web Protection is managed by system policy.");
            }

            // Checks and sets the Control D Security settings using the policy
            if (policies.ControlDSecurityEnabled !== undefined) {
                settings.controlDSecurityEnabled = policies.ControlDSecurityEnabled;
                console.debug("Control D Security is managed by system policy.");
            }

            // Checks and sets the Control D Family settings using the policy
            if (policies.ControlDFamilyEnabled !== undefined) {
                settings.controlDFamilyEnabled = policies.ControlDFamilyEnabled;
                console.debug("Control D Family is managed by system policy.");
            }

            // Checks and sets the PrecisionSec settings using the policy
            if (policies.PrecisionSecEnabled !== undefined) {
                settings.precisionSecEnabled = policies.PrecisionSecEnabled;
                console.debug("PrecisionSec is managed by system policy.");
            }

            // Checks and sets the G DATA settings using the policy
            if (policies.GDATAEnabled !== undefined) {
                settings.gDataEnabled = policies.GDATAEnabled;
                console.debug("G DATA is managed by system policy.");
            }

            // Checks and sets the CERT-EE settings using the policy
            if (policies.CERTEEEnabled !== undefined) {
                settings.certEEEnabled = policies.CERTEEEnabled;
                console.debug("CERT-EE is managed by system policy.");
            }

            // Checks and sets the CIRA Security settings using the policy
            if (policies.CIRASecurityEnabled !== undefined) {
                settings.ciraSecurityEnabled = policies.CIRASecurityEnabled;
                console.debug("CIRA Security is managed by system policy.");
            }

            // Checks and sets the CIRA Family settings using the policy
            if (policies.CIRAFamilyEnabled !== undefined) {
                settings.ciraFamilyEnabled = policies.CIRAFamilyEnabled;
                console.debug("CIRA Family is managed by system policy.");
            }

            // Checks and sets the CleanBrowsing Security settings using the policy
            if (policies.CleanBrowsingSecurityEnabled !== undefined) {
                settings.cleanBrowsingSecurityEnabled = policies.CleanBrowsingSecurityEnabled;
                console.debug("CleanBrowsing Security is managed by system policy.");
            }

            // Checks and sets the CleanBrowsing Family settings using the policy
            if (policies.CleanBrowsingFamilyEnabled !== undefined) {
                settings.cleanBrowsingFamilyEnabled = policies.CleanBrowsingFamilyEnabled;
                console.debug("CleanBrowsing Family is managed by system policy.");
            }

            // Checks and sets the CleanBrowsing Adult settings using the policy
            if (policies.CleanBrowsingAdultEnabled !== undefined) {
                settings.cleanBrowsingAdultEnabled = policies.CleanBrowsingAdultEnabled;
                console.debug("CleanBrowsing Adult is managed by system policy.");
            }

            // Checks and sets the Cloudflare Security settings using the policy
            if (policies.CloudflareSecurityEnabled !== undefined) {
                settings.cloudflareSecurityEnabled = policies.CloudflareSecurityEnabled;
                console.debug("Cloudflare Security is managed by system policy.");
            }

            // Checks and sets the Cloudflare Family settings using the policy
            if (policies.CloudflareFamilyEnabled !== undefined) {
                settings.cloudflareFamilyEnabled = policies.CloudflareFamilyEnabled;
                console.debug("Cloudflare Family is managed by system policy.");
            }

            // Checks and sets the DNS0.eu Security settings using the policy
            if (policies.DNS0SecurityEnabled !== undefined) {
                settings.dns0SecurityEnabled = policies.DNS0SecurityEnabled;
                console.debug("DNS0.eu Security is managed by system policy.");
            }

            // Checks and sets the DNS0.eu Kids settings using the policy
            if (policies.DNS0KidsEnabled !== undefined) {
                settings.dns0KidsEnabled = policies.DNS0KidsEnabled;
                console.debug("DNS0.eu Kids is managed by system policy.");
            }

            // Checks and sets the DNS4EU Security settings using the policy
            if (policies.DNS4EUSecurityEnabled !== undefined) {
                settings.dns4EUSecurityEnabled = policies.DNS4EUSecurityEnabled;
                console.debug("DNS4EU Security is managed by system policy.");
            }

            // Checks and sets the DNS4EU Family settings using the policy
            if (policies.DNS4EUFamilyEnabled !== undefined) {
                settings.dns4EUFamilyEnabled = policies.DNS4EUFamilyEnabled;
                console.debug("DNS4EU Family is managed by system policy.");
            }

            // Checks and sets the SmartScreen settings using the policy
            if (policies.SmartScreenEnabled !== undefined) {
                settings.smartScreenEnabled = policies.SmartScreenEnabled;
                console.debug("SmartScreen is managed by system policy.");
            }

            // Checks and sets the Norton settings using the policy
            if (policies.NortonEnabled !== undefined) {
                settings.nortonEnabled = policies.NortonEnabled;
                console.debug("Norton is managed by system policy.");
            }

            // Checks and sets the OpenDNS Security settings using the policy
            if (policies.OpenDNSSecurityEnabled !== undefined) {
                settings.openDNSSecurityEnabled = policies.OpenDNSSecurityEnabled;
                console.debug("OpenDNS Security is managed by system policy.");
            }

            // Checks and sets the OpenDNS Family Shield settings using the policy
            if (policies.OpenDNSFamilyShieldEnabled !== undefined) {
                settings.openDNSFamilyShieldEnabled = policies.OpenDNSFamilyShieldEnabled;
                console.debug("OpenDNS Family Shield is managed by system policy.");
            }

            // Checks and sets the Quad9 settings using the policy
            if (policies.Quad9Enabled !== undefined) {
                settings.quad9Enabled = policies.Quad9Enabled;
                console.debug("Quad9 is managed by system policy.");
            }

            // Checks and sets the Switch.ch settings using the policy
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

        // Creates the context menu
        createContextMenu();
    });

    // Listens for PING messages from content scripts to get the blocked counter.
    browserAPI.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.messageType === Messages.MessageType.BLOCKED_COUNTER_PING && sender.tab && sender.tab.id !== null) {
            const tabId = sender.tab.id;

            // Potentially fixes a strange undefined error.
            if (resultSystemNames.get(tabId) === undefined) {
                console.warn(`Result system names is undefined for tab ID ${tabId}`);
                return;
            }

            const fullCount = resultSystemNames.get(tabId).length + 1 || 0;

            // If the page URL is the block page, sends (count - 1)
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

    // Listener for onRemoved events.
    browserAPI.tabs.onRemoved.addListener((tabId, removeInfo) => {
        console.debug(`Tab removed: ${tabId} (windowId: ${removeInfo.windowId}) (isWindowClosing: ${removeInfo.isWindowClosing})`);

        // Removes all cached keys for the tab
        BrowserProtection.cacheManager.removeKeysByTabId(tabId);

        // Removes the tab from local maps
        resultSystemNames.delete(tabId);
        frameZeroURLs.delete(tabId);
    });

    // Listener for onUpdated events.
    browserAPI.tabs.onUpdated.addListener((tabId, changeInfo) => {
        if (changeInfo.url) {
            changeInfo.tabId = tabId;
            changeInfo.frameId = 0;

            console.debug(`[onUpdated] ${tabId} updated URL to ${changeInfo.url})`);
            handleNavigation(changeInfo);
        }
    });

    // Listener for onBeforeNavigate events.
    browserAPI.webNavigation.onBeforeNavigate.addListener(navigationDetails => {
        console.debug(`[onBeforeNavigate] ${navigationDetails.url} (frameId: ${navigationDetails.frameId}) (tabId: ${navigationDetails.tabId})`);
        handleNavigation(navigationDetails);
    });

    // Listener for onCreatedNavigationTarget events.
    browserAPI.webNavigation.onCreatedNavigationTarget.addListener(navigationDetails => {
        console.debug(`[onCreatedNavigationTarget] ${navigationDetails.url} (frameId: ${navigationDetails.frameId}) (tabId: ${navigationDetails.tabId})`);
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
        // Checks if the message exists and has a valid type
        if (!(message && message.messageType)) {
            return;
        }

        switch (message.messageType) {
            case Messages.MessageType.CONTINUE_TO_SITE: {
                // Checks if the message has a blocked URL
                if (!message.blockedUrl) {
                    console.debug(`No blocked URL was found; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                // Checks if the message has a continue URL
                if (!message.continueUrl) {
                    console.debug(`No continue URL was found; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                // Checks if the message has an origin
                if (!message.origin) {
                    console.debug(`No origin was found; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                // Parses the blocked URL object
                let blockedUrlObject;
                try {
                    blockedUrlObject = new URL(message.blockedUrl);
                } catch (error) {
                    console.warn(`Invalid blocked URL format: ${message.blockedUrl}; sending to new tab page: ${error}`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                // Redirects to the new tab page if the blocked URL is not a valid HTTP(S) URL
                if (!validProtocols.includes(blockedUrlObject.protocol.toLowerCase())) {
                    console.debug(`Invalid protocol in blocked URL: ${message.blockedUrl}; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                // Parses the continue URL object
                let continueUrlObject;
                try {
                    continueUrlObject = new URL(message.continueUrl);
                } catch (error) {
                    console.warn(`Invalid continue URL format: ${message.continueUrl}; sending to new tab page: ${error}`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                // Redirects to the new tab page if the continue URL is not a valid HTTP(S) URL
                if (!validProtocols.includes(continueUrlObject.protocol.toLowerCase())) {
                    console.debug(`Invalid protocol in continue URL: ${message.continueUrl}; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                switch (message.origin) {
                    case "1":
                        console.debug(`Added AdGuard Security URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "adGuardSecurity");

                        console.debug(`Removed AdGuard Security URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "adGuardSecurity");
                        break;

                    case "2":
                        console.debug(`Added AdGuard Family URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "adGuardFamily");

                        console.debug(`Removed AdGuard Family URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "adGuardFamily");
                        break;

                    case "3":
                        console.debug(`Added alphaMountain URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "alphaMountain");

                        console.debug(`Removed alphaMountain URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "alphaMountain");
                        break;

                    case "4":
                        console.debug(`Added Control D Security URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "controlDSecurity");

                        console.debug(`Removed Control D Security URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "controlDSecurity");
                        break;

                    case "5":
                        console.debug(`Added Control D Family URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "controlDFamily");

                        console.debug(`Removed Control D Family URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "controlDFamily");
                        break;

                    case "6":
                        console.debug(`Added PrecisionSec URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "precisionSec");

                        console.debug(`Removed PrecisionSec URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "precisionSec");
                        break;

                    case "7":
                        console.debug(`Added G DATA URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "gData");

                        console.debug(`Removed G DATA URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "gData");
                        break;

                    case "8":
                        console.debug(`Added CERT-EE URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "certEE");

                        console.debug(`Removed CERT-EE URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "certEE");
                        break;

                    case "9":
                        console.debug(`Added CIRA Security URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "ciraSecurity");

                        console.debug(`Removed CIRA Security URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "ciraSecurity");
                        break;

                    case "10":
                        console.debug(`Added CIRA Family URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "ciraFamily");

                        console.debug(`Removed CIRA Family URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "ciraFamily");
                        break;

                    case "11":
                        console.debug(`Added CleanBrowsing Security URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "cleanBrowsingSecurity");

                        console.debug(`Removed CleanBrowsing Security URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "cleanBrowsingSecurity");
                        break;

                    case "12":
                        console.debug(`Added CleanBrowsing Family URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "cleanBrowsingFamily");

                        console.debug(`Removed CleanBrowsing Family URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "cleanBrowsingFamily");
                        break;

                    case "13":
                        console.debug(`Added CleanBrowsing Adult URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "cleanBrowsingAdult");

                        console.debug(`Removed CleanBrowsing Adult URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "cleanBrowsingAdult");
                        break;

                    case "14":
                        console.debug(`Added Cloudflare Security URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "cloudflareSecurity");

                        console.debug(`Removed Cloudflare Security URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "cloudflareSecurity");
                        break;

                    case "15":
                        console.debug(`Added Cloudflare Family URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "cloudflareFamily");

                        console.debug(`Removed Cloudflare Family URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "cloudflareFamily");
                        break;

                    case "16":
                        console.debug(`Added DNS0.eu Security URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "dns0Security");

                        console.debug(`Removed DNS0.eu Security URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "dns0Security");
                        break;

                    case "17":
                        console.debug(`Added DNS0.eu Kids URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "dns0Kids");

                        console.debug(`Removed DNS0.eu Kids URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "dns0Kids");
                        break;

                    case "18":
                        console.debug(`Added DNS4EU Security URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "dns4EUSecurity");

                        console.debug(`Removed DNS4EU Security URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "dns4EUSecurity");
                        break;

                    case "19":
                        console.debug(`Added DNS4EU Family URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "dns4EUFamily");

                        console.debug(`Removed DNS4EU Family URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "dns4EUFamily");
                        break;

                    case "20":
                        console.debug(`Added SmartScreen URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "smartScreen");

                        console.debug(`Removed SmartScreen URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "smartScreen");
                        break;

                    case "21":
                        console.debug(`Added Norton URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "norton");

                        console.debug(`Removed Norton URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "norton");
                        break;

                    case "22":
                        console.debug(`Added OpenDNS Security URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "openDNSSecurity");

                        console.debug(`Removed OpenDNS Security URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "openDNSSecurity");
                        break;

                    case "23":
                        console.debug(`Added OpenDNS Family Shield URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "openDNSFamilyShield");

                        console.debug(`Removed OpenDNS Family Shield URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "openDNSFamilyShield");
                        break;

                    case "24":
                        console.debug(`Added Quad9 URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "quad9");

                        console.debug(`Removed Quad9 URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "quad9");
                        break;

                    case "25":
                        console.debug(`Added Switch.ch URL to allowed cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.addUrlToAllowedCache(message.blockedUrl, "switchCH");

                        console.debug(`Removed Switch.ch URL from blocked cache: ${message.blockedUrl}`);
                        BrowserProtection.cacheManager.removeUrlFromBlockedCache(message.blockedUrl, "switchCH");
                        break;

                    default:
                        console.warn(`Unknown origin: ${message.origin}`);
                        break;
                }

                browserAPI.tabs.update(sender.tab.id, {url: message.continueUrl}).catch(error => {
                    console.error(`Failed to update tab ${tabId}:`, error);
                    sendToNewTabPage(tabId);
                });
                break;
            }

            case Messages.MessageType.CONTINUE_TO_SAFETY:
                // Redirects to the new tab page
                setTimeout(() => {
                    sendToNewTabPage(sender.tab.id);
                }, 200);
                break;

            case Messages.MessageType.REPORT_SITE: {
                // Ignores blank report URLs
                if (message.reportUrl === null || message.reportUrl === "") {
                    console.debug(`Report URL is blank.`);
                    break;
                }

                // Checks if the message has an origin
                if (!message.origin) {
                    console.debug(`No origin was found; doing nothing.`);
                    break;
                }

                let reportUrlObject = new URL(message.reportUrl);

                if (validProtocols.includes(reportUrlObject.protocol.toLowerCase())) {
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

                // Checks if the message has a continue URL
                if (!message.continueUrl) {
                    console.debug(`No continue URL was found; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                // Checks if the message has an origin
                if (!message.origin) {
                    console.debug(`No origin was found; sending to the new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    break;
                }

                // Parses the blocked URL object
                let blockedUrlObject;
                try {
                    blockedUrlObject = new URL(message.blockedUrl);
                } catch (error) {
                    console.warn(`Invalid blocked URL format: ${message.blockedUrl}; sending to new tab page: ${error}`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                // Redirects to the new tab page if the blocked URL is not a valid HTTP(S) URL
                if (!validProtocols.includes(blockedUrlObject.protocol.toLowerCase())) {
                    console.debug(`Invalid protocol in blocked URL: ${message.blockedUrl}; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                const hostnameString = `${blockedUrlObject.hostname} (allowed)`;

                // Adds the hostname to every allowed cache
                console.debug(`Adding hostname to every allowed cache: ${hostnameString}`);
                BrowserProtection.cacheManager.addStringToAllowedCache(hostnameString, "all");

                // Removes the hostname from every blocked cache
                console.debug(`Removing hostname from every blocked cache: ${hostnameString}`);
                BrowserProtection.cacheManager.removeStringFromBlockedCache(hostnameString, "all");

                // Parses the continue URL object
                let continueUrlObject;
                try {
                    continueUrlObject = new URL(message.continueUrl);
                } catch (error) {
                    console.warn(`Invalid continue URL format: ${message.continueUrl}; sending to new tab page: ${error}`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                // Redirects to the new tab page if the continue URL is not a valid HTTP(S) URL
                if (!validProtocols.includes(continueUrlObject.protocol.toLowerCase())) {
                    console.debug(`Invalid protocol in continue URL: ${message.continueUrl}; sending to new tab page.`);
                    sendToNewTabPage(sender.tab.id);
                    return;
                }

                browserAPI.tabs.update(sender.tab.id, {url: message.continueUrl}).catch(error => {
                    console.error(`Failed to update tab ${tabId}:`, error);
                    sendToNewTabPage(tabId);
                });
                break;
            }

            case Messages.MessageType.ADGUARD_FAMILY_TOGGLED:
            case Messages.MessageType.ADGUARD_SECURITY_TOGGLED:
            case Messages.MessageType.ALPHAMOUNTAIN_TOGGLED:
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
                console.debug(`Enable notifications: ${info.checked}`);
                break;

            case "toggleFrameNavigation":
                Settings.set({ignoreFrameNavigation: info.checked});
                console.debug(`Ignore frame navigation: ${info.checked}`);
                break;

            case "clearAllowedSites": {
                BrowserProtection.cacheManager.clearAllowedCache();
                console.debug("Cleared all allowed site caches.");

                // Builds the browser notification to send the user
                const notificationOptions = {
                    type: "basic",
                    iconUrl: "assets/icons/icon128.png",
                    title: "Allowed Sites Cleared",
                    message: "All allowed sites have been cleared.",
                    priority: 2,
                };

                const randomNumber = Math.floor(Math.random() * 100000000);
                const notificationId = `cache-cleared-${randomNumber}`;

                // Creates and displays the browser notification
                browserAPI.notifications.create(notificationId, notificationOptions, id => {
                    console.debug(`Notification created with ID: ${id}`);
                });
                break;
            }

            case "restoreDefaultSettings": {
                // Restores default settings
                Settings.restoreDefaultSettings();
                console.debug("Restored default settings.");

                // Builds the browser notification to send the user
                const notificationOptions = {
                    type: "basic",
                    iconUrl: "assets/icons/icon128.png",
                    title: "Restore Default Settings",
                    message: "Default settings have been restored.",
                    priority: 2,
                };

                const randomNumber = Math.floor(Math.random() * 100000000);
                const notificationId = `restore-defaults-${randomNumber}`;

                // Creates and displays a browser notification
                browserAPI.notifications.create(notificationId, notificationOptions, id => {
                    console.debug(`Notification created with ID: ${id}`);
                });

                // Re-creates the context menu
                setTimeout(() => {
                    createContextMenu();
                    console.debug("Re-created context menu.");
                }, 100);
                break;
            }

            default:
                break;
        }
    });

    /**
     * Creates the context menu for the extension.
     */
    function createContextMenu() {
        Settings.get(settings => {
            // Removes existing menu items to avoid duplicates
            contextMenuAPI.removeAll();

            // Checks if the context menu is disabled by policies
            if (!settings.contextMenuEnabled) {
                return;
            }

            // Creates the toggle notifications menu item
            contextMenuAPI.create({
                id: "toggleNotifications",
                title: "Enable notifications",
                type: "checkbox",
                checked: settings.notificationsEnabled,
                contexts: ["action"],
            });

            // Creates the toggle frame navigation menu item
            contextMenuAPI.create({
                id: "toggleFrameNavigation",
                title: "Ignore frame navigation",
                type: "checkbox",
                checked: settings.ignoreFrameNavigation,
                contexts: ["action"],
            });

            // Creates the clear allowed sites menu item
            contextMenuAPI.create({
                id: "clearAllowedSites",
                title: "Clear list of allowed sites",
                contexts: ["action"],
            });

            // Creates the restore default settings menu item
            contextMenuAPI.create({
                id: "restoreDefaultSettings",
                title: "Restore default settings",
                contexts: ["action"],
            });

            // Returns early if managed policies are not supported
            if (!supportsManagedPolicies) {
                return;
            }

            // Gathers the policy values for updating the context menu
            const policyKeys = [
                "DisableNotifications",
                "DisableClearAllowedSites",
                "IgnoreFrameNavigation",
                "DisableRestoreDefaultSettings"
            ];

            browserAPI.storage.managed.get(policyKeys, policies => {
                let updatedSettings = {};

                // Checks if the enable notifications button should be disabled
                if (policies.DisableNotifications !== undefined) {
                    contextMenuAPI.update("toggleNotifications", {
                        enabled: false,
                        checked: !policies.DisableNotifications,
                    });

                    updatedSettings.notificationsEnabled = !policies.DisableNotifications;
                    console.debug("Notifications are managed by system policy.");
                }

                // Checks if the ignore frame navigation button should be disabled
                if (policies.IgnoreFrameNavigation !== undefined) {
                    contextMenuAPI.update("toggleFrameNavigation", {
                        enabled: false,
                        checked: policies.IgnoreFrameNavigation,
                    });

                    updatedSettings.ignoreFrameNavigation = policies.IgnoreFrameNavigation;
                    console.debug("Ignoring frame navigation is managed by system policy.");
                }

                // Checks if the clear allowed sites button should be disabled
                if (policies.DisableClearAllowedSites !== undefined && policies.DisableClearAllowedSites) {
                    contextMenuAPI.update("clearAllowedSites", {
                        enabled: false,
                    });

                    console.debug("Clear allowed sites button is managed by system policy.");
                }

                // Checks if the restore default settings button should be disabled
                if (policies.DisableRestoreDefaultSettings !== undefined && policies.DisableRestoreDefaultSettings) {
                    contextMenuAPI.update("restoreDefaultSettings", {
                        enabled: false,
                    });

                    console.debug("Restore default settings button is managed by system policy.");
                }

                // Updates settings cumulatively if any policy-based changes were made
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

    /**
     * Checks if an IP address is private/locally hosted.
     *
     * @param ip - The IP address to check.
     * @returns {boolean|boolean|boolean} - If the IP address is private/locally hosted.
     */
    function isPrivateIP(ip) {
        return ip.startsWith("127.") ||
            ip.startsWith("10.") ||
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) ||
            ip.startsWith("192.168.") ||
            ip.startsWith("0.0.0.0");
    }

    /**
     * Normalizes an IP address.
     *
     * @param hostname - The IP/hostname to check.
     * @returns {null|string} - The normalized IP address.
     */
    function normalizeIP(hostname) {
        // Checks if the input is a decimal IP (e.g. "3232235777")
        if (/^\d+$/.test(hostname)) {
            const n = parseInt(hostname, 10);
            return [
                n >>> 24 & 255,
                n >>> 16 & 255,
                n >>> 8 & 255,
                n & 255
            ].join(".");
        }

        const parts = hostname.split(".");

        // Dotted format - may include decimal, octal, or hex
        if (parts.length === 4) {
            try {
                const nums = parts.map(p => {
                    if (/^0x/i.test(p)) {
                        return parseInt(p, 16); // hex
                    } else if (/^0[0-7]*$/.test(p)) {
                        return parseInt(p, 8); // octal (starts with 0, only digits 0–7)
                    } else {
                        return parseInt(p, 10); // decimal
                    }
                });

                if (nums.every(n => n >= 0 && n <= 255)) {
                    return nums.join('.');
                }
                return nums.join(".");
            } catch (error) {
                console.warn(`Error in checking for dotted quad in URL: ${error}`);
                return null;
            }
        }
        return null;
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

        const ip = normalizeIP(hostname);
        return ip ? isPrivateIP(ip) : false;
    }
})();
