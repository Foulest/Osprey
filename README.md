# Osprey: Browser Protection

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![CodeQL](https://github.com/Foulest/Osprey/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Foulest/Osprey/actions/workflows/github-code-scanning/codeql)
![Chrome Users](https://img.shields.io/chrome-web-store/users/jmnpibhfpmpfjhhkmpadlbgjnbhpjgnd?label=Chrome%20Users&color=00CC00)
![Edge Users](https://img.shields.io/badge/dynamic/json?label=Edge%20Users&color=00CC00&query=%24.activeInstallCount&url=https%3A%2F%2Fmicrosoftedge.microsoft.com%2Faddons%2Fgetproductdetailsbycrxid%2Fnopglhplnghfhpniofkcopmhbjdonlgn)
![Firefox Users](https://img.shields.io/amo/users/osprey-browser-protection?label=Firefox%20Users&color=00CC00)

**Osprey** is a browser extension that protects you from malicious websites.

[Privacy Policy](https://github.com/Foulest/Osprey/blob/main/.github/PRIVACY.md)
• [Wiki (FAQs)](https://github.com/Foulest/Osprey/wiki)
• [MalwareTips](https://malwaretips.com/threads/osprey-browser-protection-discussion-and-updates.135565)
• [Wilders Security](https://www.wilderssecurity.com/threads/osprey-browser-protection.456729)

###

[![Google Chrome](https://i.imgur.com/R9AN3cA.png)](https://chromewebstore.google.com/detail/osprey-browser-protection/jmnpibhfpmpfjhhkmpadlbgjnbhpjgnd)
[![Microsoft Edge](https://i.imgur.com/oVmDDtj.png)](https://microsoftedge.microsoft.com/addons/detail/osprey-browser-protectio/nopglhplnghfhpniofkcopmhbjdonlgn)
[![Firefox](https://i.imgur.com/uXgho1n.png)](https://addons.mozilla.org/en-US/firefox/addon/osprey-browser-protection)

###

![Osprey Banner](https://i.imgur.com/2G7nwOA.png)

## Official Partners

Osprey has **officially partnered** with industry-leading security companies to provide you with the best protection
possible. Check out some of our partners below:

###

<p align="center">
  <a href="https://adguard-dns.io?aid=135732"><img src="https://i.imgur.com/4AXgbsC.png" alt="AdGuard DNS"></a>
  <a href="https://www.alphamountain.ai/?utm_source=osprey"><img src="https://i.imgur.com/EbcGHb2.png" alt="alphaMountain"></a>
  <a href="https://controld.com/?utm_source=osprey"><img src="https://i.imgur.com/xh7qTT8.png" alt="Control D"></a>
  <a href="https://precisionsec.com/?utm_source=osprey"><img src="https://i.imgur.com/gf9ahFa.png" alt="PrecisionSec"></a>
</p>

###

## Warning

If the website is malicious, Osprey will block the page and display a warning:

![Osprey Warning](https://i.imgur.com/ZmVOFfU.png)

From this page, you can report the website as safe, always ignore the website, go back to safety, and continue
anyway. By default, Osprey creates a browser notification for blocked pages that
[you can toggle on and off](https://github.com/Foulest/Osprey/wiki/Toggling-Notifications) using the context menu.
You can hide the continue and report buttons, lock down the protection options, and even hide the context menu
entirely using [the system policies](https://github.com/Foulest/Osprey/wiki/Setting-Up-System-Policies).

## Settings

You can configure the extension's protection options in the settings:

![Osprey Settings (Page 1)](https://i.imgur.com/Cu73wfB.png)
![Osprey Settings (Page 2)](https://i.imgur.com/PGPBvsu.png)

If you're unsure about the functions of each protection provider, **it's best to keep the default settings.**

You can restore them by right-clicking the extension icon and selecting **Restore default settings**.

## Detections

Osprey blocks websites that are classified as:

- [Malicious](https://us.norton.com/blog/malware/what-are-malicious-websites)
- [Phishing](https://us.norton.com/blog/online-scams/what-is-phishing)
- [Untrusted](https://mcafee.com/blogs/internet-security/how-to-tell-whether-a-website-is-safe-or-unsafe)
- [Adult Content](https://library.fiveable.me/key-terms/mass-media-society/adult-content)

## Protection Providers

The following providers are **enabled** by default:

- [x] **[AdGuard Security DNS](https://adguard-dns.io?aid=135732)**
- [x] **[alphaMountain Web Protection](https://www.alphamountain.ai/?utm_source=osprey)**
- [x] **[PrecisionSec Web Protection](https://www.precisionsec.com/?utm_source=osprey)**
- [x] [CleanBrowsing Security DNS](https://www.cleanbrowsing.org/filters/#step3)
- [x] [Cloudflare Security DNS](https://blog.cloudflare.com/introducing-1-1-1-1-for-families/#two-flavors-1-1-1-2-no-malware-1-1-1-3-no-malware-or-adult-content)
- [x] [DNS0.eu Security DNS](https://www.dns0.eu/zero)
- [x] [DNS4EU Security DNS](https://www.joindns4.eu/for-public)
- [x] [Quad9 Security DNS](https://www.quad9.net)

The following providers are **disabled** by default:

#### Security Filters

- [ ] **[Control D Security DNS](https://controld.com/?utm_source=osprey)**
- [ ] [Microsoft SmartScreen](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen)
- [ ] [G DATA Web Protection](https://www.gdata.de/help/en/consumer/FAQ/webProtectionWinFAQ)
- [ ] [CERT-EE Security DNS](https://www.ria.ee/en/news/application-developed-cert-ee-protects-against-phishing-and-malware)
- [ ] [Norton Safe Web](https://safeweb.norton.com)

#### Adult Content Filters

- [ ] **[AdGuard Family DNS](https://adguard-dns.io?aid=135732)**
- [ ] **[Control D Family DNS](https://controld.com/?utm_source=osprey)**
- [ ] [CleanBrowsing Family DNS](https://www.cleanbrowsing.org/filters/#step2)
- [ ] [Cloudflare Family DNS](https://blog.cloudflare.com/introducing-1-1-1-1-for-families)
- [ ] [DNS0.eu Family DNS](https://www.dns0.eu/kids)
- [ ] [DNS4EU Family DNS](https://www.joindns4.eu/for-public)

Providers disabled by default are either due to:

- Frequent reports of false positives
- Failure to respond to false positive reports
- Being an optional adult content filter
- Being a paid service that requires a license or API key

If a provider gives you false positives, report the links to them directly and disable them in the Protection Options
panel if needed. Osprey is designed to be customizable, so you can enable or disable any of the providers at any time.
Osprey does not have control over the providers' databases or how they classify URLs.

## Privacy

Osprey strips down each URL of tracking parameters before sending it to any APIs.

For example:

1. If you search for shirts on Amazon and
   visit: https://www.amazon.com/s?k=shirts&crid=3TOVSW14ZHF8V&sprefix=shirt%2Caps%2C175&ref=nb_sb_noss_1
2. Osprey will only send https://amazon.com/s to any APIs you have enabled.
3. If the APIs report that the page is safe to visit, Osprey caches the result for 24 hours.
4. It will also be cached if you click 'Continue anyway' or 'Always ignore this website' on a blocked site.
5. As long as a URL is cached, no new network requests will be made for it.

The only data the APIs receive is the stripped-down URL, your user agent, and your IP address. Use a reputable VPN or
proxy service if you're concerned about IP-related privacy. There are also extensions that mask your user agent, if
you're so inclined.

As for why Osprey needs to check complete URLs instead of just the domain, many phishing attacks use legitimate
companies such as Jotform to host their phishing campaigns. If Osprey only checked a website's domain name, it wouldn't
detect those threats. Osprey only sends your hostname to its various DNS API providers, so if you're highly concerned
about URL page privacy, the DNS APIs are there for you.

## Manual Install

> **Note:** You need to have a GitHub account to download artifacts.

You can install Osprey from the web stores listed at the top.

For other installations, you can install the extension manually:

### Chrome/Edge

1. Navigate to the [Actions section](https://github.com/Foulest/Osprey/actions/workflows) and click `Compile for Chrome`
   or `Compile for Edge`.
2. Scroll down to the `Artifacts` section and download the artifact file.
3. Extract the artifact's ZIP file to a folder on your computer.
4. Navigate to `about://extensions` in your browser.
5. Enable `Developer mode` and click `Load unpacked`.
6. Select the downloaded ZIP file and click `Select Folder`.

### Firefox

> **Note:** This only works
> for [builds of Firefox that allow unsigned addons.](https://support.mozilla.org/en-US/kb/add-on-signing-in-firefox)

1. Navigate to the [Actions section](https://github.com/Foulest/Osprey/actions/workflows) and click
   `Compile for Firefox`.
2. Scroll down to the `Artifacts` section and download the artifact file.
3. Extract the artifact's ZIP file to a folder on your computer.
4. Navigate to `about:addons` in your browser.
5. Click the gear icon and select `Install Add-on From File`.
6. Select the downloaded ZIP file and click `Select Folder`.

Osprey should now be installed in your browser.

## Disclaimer

Osprey: Browser Protection uses the names of third-party DNS and security providers solely for descriptive and
interoperability purposes. All trademarks, logos, and brand names are the property of their respective owners.

Osprey is not affiliated with or endorsed by any of the third-party providers listed in the extension, unless stated
otherwise. Use of their services is subject to their respective terms of use and privacy policies.

If you represent a listed provider and have questions, feedback, or concerns regarding attribution or inclusion, please
contact the developer via the
[Chrome Web Store contact link](https://chromewebstore.google.com/detail/osprey-browser-protection/jmnpibhfpmpfjhhkmpadlbgjnbhpjgnd#:~:text=English-,Developer,-Website).

## Getting Help

For support or queries, please open an issue in the [Issues section](https://github.com/Foulest/Osprey/issues).
