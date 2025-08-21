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
            "util/StorageUtil.js",
            "util/Settings.js",
            "util/UrlHelpers.js",
            "util/CacheManager.js",
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
            if (Settings.allProvidersDisabled(settings)) {
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

            // Parses the URL object.
            let urlObject;
            try {
                urlObject = new URL(currentUrl);
            } catch (error) {
                console.warn(`Invalid URL format: ${currentUrl}; bailing out: ${error}`);
                return;
            }

            // Removes the blob: prefix from the URL.
            // Example: turns blob:http://example.com into http://example.com
            currentUrl = currentUrl.replace(/^blob:http/, 'http');

            // Removes www. from the start of the URL.
            // Example: turns https://www.example.com into https://example.com
            currentUrl = currentUrl.replace(/https?:\/\/www\./, 'https://');

            // Removes query parameters, fragments (#) and & tags from the URL.
            // Example: turns https://example.com?param=value#fragment into https://example.com
            currentUrl = currentUrl.replace(/[?#&].*$/, '');

            // Removes user and pass parameters from the start of the URL.
            // Example: turns https://user:pass@example.com into https://example.com
            currentUrl = currentUrl.replace(/https?:\/\/[^/]+@/, 'https://');

            // Removes port numbers from the URL, even if at a page.
            // Example: turns https://example.com:8080/test.php into https://example.com/test.php
            currentUrl = currentUrl.replace(/:(\d+)(\/|$)/, '$2');

            // Removes trailing slashes from the URL.
            // Example: turns https://example.com/ into https://example.com
            currentUrl = currentUrl.replace(/\/+$/, '');

            // Sanitizes and encodes the URL to handle spaces and special characters.
            try {
                currentUrl = encodeURI(currentUrl);
            } catch (error) {
                console.warn(`Failed to encode URL: ${currentUrl}; bailing out: ${error}`);
                return;
            }

            const protocol = urlObject.protocol;
            const hostname = urlObject.hostname;

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
            if (!hostname.includes('.') || hostname.endsWith('.')) {
                console.debug(`Missing suffix in URL: ${currentUrl}; bailing out.`);
                return;
            }

            // Checks for invalid characters in the hostname.
            if (!/^[a-zA-Z0-9._-]+$/.test(hostname)) {
                console.warn(`Hostname contains invalid characters: ${hostname}; bailing out.`);
                return;
            }

            // Excludes internal network addresses, loopback, or reserved domains.
            if (UrlHelpers.isInternalAddress(hostname)) {
                console.debug(`Local/internal network URL detected: ${currentUrl}; bailing out.`);
                return;
            }

            // Checks if the hostname is in the global allowed cache.
            if (CacheManager.isPatternInAllowedCache(hostname, "global")) {
                console.debug(`URL is in the global allowed cache: ${currentUrl}; bailing out.`);
                return;
            }

            // Cancels all pending requests for the main frame navigation.
            if (frameId === 0) {
                BrowserProtection.abandonPendingRequests(tabId, "Cancelled by main frame navigation.");

                // Remove all cached keys for the tab.
                CacheManager.removeKeysByTabId(tabId);
                resultSystemNames.delete(tabId);

                // Reset the frame zero URLs for the tab.
                frameZeroURLs.delete(tabId);
                frameZeroURLs.set(tabId, currentUrl);
            }

            let blocked = false;
            let firstSystemName = "";
            resultSystemNames.set(tabId, []);

            const startTime = Date.now();
            console.info(`Checking URL: ${currentUrl}`);

            // Checks if the URL is malicious.
            BrowserProtection.checkIfUrlIsMalicious(tabId, currentUrl, (result) => {
                const duration = Date.now() - startTime;
                const cacheName = ProtectionResult.CacheName[result.origin];
                const systemName = ProtectionResult.ShortName[result.origin];
                const resultType = result.resultType;

                // Removes the URL from the system's processing cache on every callback.
                // Doesn't remove it if the result is still waiting for a response.
                if (resultType !== ProtectionResult.ResultType.WAITING) {
                    CacheManager.removeUrlFromProcessingCache(urlObject, cacheName);
                }

                console.info(`[${systemName}] Result for ${currentUrl}: ${resultType} (${duration}ms)`);

                if (resultType !== ProtectionResult.ResultType.FAILED &&
                    resultType !== ProtectionResult.ResultType.WAITING &&
                    resultType !== ProtectionResult.ResultType.KNOWN_SAFE &&
                    resultType !== ProtectionResult.ResultType.ALLOWED) {

                    if (!blocked) {
                        browserAPI.tabs.get(tabId, tab => {
                            // Check if the tab or tab.url is undefined
                            if (!tab || tab.url === undefined) {
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

                    // TODO: Migrate this logic to work on refresh
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
                            // Check if the tab or tab.url is undefined
                            if (!tab || tab.url === undefined) {
                                console.debug(`tabs.get(${tabId}) failed '${browserAPI.runtime.lastError?.message}'; bailing out.`);
                                return;
                            }

                            const isBlockPage = tab.url?.includes("/WarningPage.html");
                            const adjustedCount = isBlockPage && fullCount > 0 ? fullCount - 1 : fullCount;

                            // Sends a PONG message to the content script to update the blocked counter.
                            browserAPI.tabs.sendMessage(tabId, {
                                messageType: Messages.BLOCKED_COUNTER_PONG,
                                count: adjustedCount,
                                systems: resultSystemNames.get(tabId) || []
                            }).catch(() => {
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
        'CERTEEEnabled',
        'CleanBrowsingSecurityEnabled',
        'CleanBrowsingFamilyEnabled',
        'CloudflareSecurityEnabled',
        'CloudflareFamilyEnabled',
        'DNS0SecurityEnabled',
        'DNS0FamilyEnabled',
        'DNS4EUSecurityEnabled',
        'DNS4EUFamilyEnabled',
        'SmartScreenEnabled',
        'NortonEnabled',
        'Quad9Enabled',
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

            // Checks and sets the CERT-EE settings using the policy
            if (policies.CERTEEEnabled !== undefined) {
                settings.certEEEnabled = policies.CERTEEEnabled;
                console.debug("CERT-EE is managed by system policy.");
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

            // Checks and sets the DNS0.eu Family settings using the policy
            if (policies.DNS0FamilyEnabled !== undefined) {
                settings.dns0FamilyEnabled = policies.DNS0FamilyEnabled;
                console.debug("DNS0.eu Family is managed by system policy.");
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

            // Checks and sets the Quad9 settings using the policy
            if (policies.Quad9Enabled !== undefined) {
                settings.quad9Enabled = policies.Quad9Enabled;
                console.debug("Quad9 is managed by system policy.");
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
        if (message.messageType === Messages.BLOCKED_COUNTER_PING && sender.tab && sender.tab.id !== null) {
            const tabId = sender.tab.id;

            // Ignores tabs that have already been cleaned up
            if (resultSystemNames.get(tabId) === undefined) {
                console.debug(`Result system names is undefined for tab ID ${tabId}`);
                return;
            }

            const fullCount = resultSystemNames.get(tabId).length + 1 || 0;

            // If the page URL is the block page, sends (count - 1)
            browserAPI.tabs.get(tabId, tab => {
                // Check if the tab or tab.url is undefined
                if (!tab || tab.url === undefined) {
                    console.debug(`tabs.get(${tabId}) failed '${browserAPI.runtime.lastError?.message}'; bailing out.`);
                    return;
                }

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
        CacheManager.removeKeysByTabId(tabId);

        // Removes the tab from local maps
        resultSystemNames.delete(tabId);
        frameZeroURLs.delete(tabId);
    });

    // Listener for onBeforeNavigate events.
    browserAPI.webNavigation.onBeforeNavigate.addListener(callback => {
        console.debug(`[onBeforeNavigate] ${callback.url} (frameId: ${callback.frameId}) (tabId: ${callback.tabId})`);
        handleNavigation(callback);
    });

    // Listener for onCommitted events.
    browserAPI.webNavigation.onCommitted.addListener(callback => {
        if (callback.transitionQualifiers.includes("server_redirect")) {
            console.debug(`[server_redirect] ${callback.url} (frameId: ${callback.frameId}) (tabId: ${callback.tabId}) (type: ${callback.transitionType})`);
            handleNavigation(callback);
        } else if (callback.transitionQualifiers.includes("client_redirect")) {
            console.debug(`[client_redirect] ${callback.url} (frameId: ${callback.frameId}) (tabId: ${callback.tabId}) (type: ${callback.transitionType})`);
            handleNavigation(callback);
        }
    });

    // Listener for onCreatedNavigationTarget events.
    browserAPI.webNavigation.onCreatedNavigationTarget.addListener(callback => {
        console.debug(`[onCreatedNavigationTarget] ${callback.url} (frameId: ${callback.frameId}) (tabId: ${callback.tabId})`);
        handleNavigation(callback);
    });

    // Listener for onHistoryStateUpdated events.
    browserAPI.webNavigation.onHistoryStateUpdated.addListener(callback => {
        console.debug(`[onHistoryStateUpdated] ${callback.url} (frameId: ${callback.frameId}) (tabId: ${callback.tabId})`);
        handleNavigation(callback);
    });

    // Listener for onReferenceFragmentUpdated events.
    browserAPI.webNavigation.onReferenceFragmentUpdated.addListener(callback => {
        console.debug(`[onReferenceFragmentUpdated] ${callback.url} (frameId: ${callback.frameId}) (tabId: ${callback.tabId})`);
        handleNavigation(callback);
    });

    // Listener for onTabReplaced events.
    browserAPI.webNavigation.onTabReplaced.addListener(callback => {
        console.debug(`[onTabReplaced] ${callback.url} (frameId: ${callback.frameId}) (tabId: ${callback.tabId})`);
        handleNavigation(callback);
    });

    // Listener for incoming messages.
    browserAPI.runtime.onMessage.addListener((message, sender) => {
        // Checks if the message exists and has a valid type
        if (!(message && message.messageType)) {
            return;
        }

        const tabId = sender.tab ? sender.tab.id : null;

        switch (message.messageType) {
            case Messages.CONTINUE_TO_SITE: {
                // Checks if the message has a blocked URL
                if (!message.blockedUrl) {
                    console.debug(`No blocked URL was found; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Checks if the message has a continue URL
                if (!message.continueUrl) {
                    console.debug(`No continue URL was found; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Checks if the message has an origin
                if (!message.origin) {
                    console.debug(`No origin was found; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Parses the blocked URL object
                let blockedUrlObject;
                try {
                    blockedUrlObject = new URL(message.blockedUrl);
                } catch (error) {
                    console.warn(`Invalid blocked URL format: ${message.blockedUrl}; sending to new tab page: ${error}`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Redirects to the new tab page if the blocked URL is not a valid HTTP(S) URL
                if (!validProtocols.includes(blockedUrlObject.protocol.toLowerCase())) {
                    console.debug(`Invalid protocol in blocked URL: ${message.blockedUrl}; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Parses the continue URL object
                let continueUrlObject;
                try {
                    continueUrlObject = new URL(message.continueUrl);
                } catch (error) {
                    console.warn(`Invalid continue URL format: ${message.continueUrl}; sending to new tab page: ${error}`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Redirects to the new tab page if the continue URL is not a valid HTTP(S) URL
                if (!validProtocols.includes(continueUrlObject.protocol.toLowerCase())) {
                    console.debug(`Invalid protocol in continue URL: ${message.continueUrl}; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                const origin = message.origin;

                if (origin === 0) {
                    console.warn(`Unknown origin: ${message.origin}`);
                } else {
                    const shortName = ProtectionResult.ShortName[origin];
                    const cacheName = ProtectionResult.CacheName[origin];

                    console.debug(`Added ${shortName} URL to allowed cache: ${message.blockedUrl}`);
                    CacheManager.addUrlToAllowedCache(message.blockedUrl, cacheName);

                    console.debug(`Removed ${shortName} URL from blocked cache: ${message.blockedUrl}`);
                    CacheManager.removeUrlFromBlockedCache(message.blockedUrl, cacheName);
                }

                browserAPI.tabs.update(tabId, {url: message.continueUrl}).catch(error => {
                    console.error(`Failed to update tab ${tabId}:`, error);
                    sendToNewTabPage(tabId);
                });
                break;
            }

            case Messages.CONTINUE_TO_SAFETY:
                // Redirects to the new tab page
                setTimeout(() => {
                    sendToNewTabPage(tabId);
                }, 200);
                break;

            case Messages.REPORT_SITE: {
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

            case Messages.ALLOW_SITE: {
                // Ignores blank blocked URLs.
                if (message.blockedUrl === null || message.blockedUrl === "") {
                    console.debug(`Blocked URL is blank.`);
                    break;
                }

                // Checks if the message has a continue URL
                if (!message.continueUrl) {
                    console.debug(`No continue URL was found; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Checks if the message has an origin
                if (!message.origin) {
                    console.debug(`No origin was found; sending to the new tab page.`);
                    sendToNewTabPage(tabId);
                    break;
                }

                // Parses the blocked URL object
                let blockedUrlObject;
                try {
                    blockedUrlObject = new URL(message.blockedUrl);
                } catch (error) {
                    console.warn(`Invalid blocked URL format: ${message.blockedUrl}; sending to new tab page: ${error}`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Redirects to the new tab page if the blocked URL is not a valid HTTP(S) URL
                if (!validProtocols.includes(blockedUrlObject.protocol.toLowerCase())) {
                    console.debug(`Invalid protocol in blocked URL: ${message.blockedUrl}; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                const hostnameString = `*.${blockedUrlObject.hostname}`;

                // Adds the hostname to the global allowed cache
                console.debug(`Adding hostname to the global allowed cache: ${hostnameString}`);
                CacheManager.addStringToAllowedCache(hostnameString, "global");

                // Parses the continue URL object
                let continueUrlObject;
                try {
                    continueUrlObject = new URL(message.continueUrl);
                } catch (error) {
                    console.warn(`Invalid continue URL format: ${message.continueUrl}; sending to new tab page: ${error}`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Redirects to the new tab page if the continue URL is not a valid HTTP(S) URL
                if (!validProtocols.includes(continueUrlObject.protocol.toLowerCase())) {
                    console.debug(`Invalid protocol in continue URL: ${message.continueUrl}; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                browserAPI.tabs.update(tabId, {url: message.continueUrl}).catch(error => {
                    console.error(`Failed to update tab ${tabId}:`, error);
                    sendToNewTabPage(tabId);
                });
                break;
            }

            case Messages.ADGUARD_FAMILY_TOGGLED:
            case Messages.ADGUARD_SECURITY_TOGGLED:
            case Messages.ALPHAMOUNTAIN_TOGGLED:
            case Messages.CERT_EE_TOGGLED:
            case Messages.CLEANBROWSING_FAMILY_TOGGLED:
            case Messages.CLEANBROWSING_SECURITY_TOGGLED:
            case Messages.CLOUDFLARE_FAMILY_TOGGLED:
            case Messages.CLOUDFLARE_SECURITY_TOGGLED:
            case Messages.CONTROL_D_FAMILY_TOGGLED:
            case Messages.CONTROL_D_SECURITY_TOGGLED:
            case Messages.DNS0_FAMILY_TOGGLED:
            case Messages.DNS0_SECURITY_TOGGLED:
            case Messages.DNS4EU_FAMILY_TOGGLED:
            case Messages.DNS4EU_SECURITY_TOGGLED:
            case Messages.NORTON_TOGGLED:
            case Messages.PRECISIONSEC_TOGGLED:
            case Messages.QUAD9_TOGGLED:
            case Messages.SMARTSCREEN_TOGGLED:
                console.info(`${message.title} has been ${message.toggleState ? "enabled" : "disabled"}.`);
                break;

            case Messages.BLOCKED_COUNTER_PING:
            case Messages.BLOCKED_COUNTER_PONG:
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
                CacheManager.clearAllowedCache();
                CacheManager.clearBlockedCache();
                CacheManager.clearProcessingCache();
                console.debug("Cleared all internal site caches.");

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
})();
