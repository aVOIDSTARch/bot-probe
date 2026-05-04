# bot-probe

A headless Playwright probe that inspects a target URL for bot detection and agent prevention signals. Produces a structured terminal report organized by detection category, with an optional JSON output mode for pipeline integration.

---

## Setup & Usage

### Prerequisites

- Node.js 18 or higher
- npm

### Install

```bash
npm install
npx playwright install chromium
```

### Run

```bash
# Formatted terminal report
node bot-probe.mjs <url>

# Visible browser window (useful for debugging navigation failures)
node bot-probe.mjs <url> --headed

# Raw JSON output (pipe into jq, log to file, feed into another system)
node bot-probe.mjs <url> --json
```

### Examples

```bash
node bot-probe.mjs https://example.com
node bot-probe.mjs https://portal.example.com --headed
node bot-probe.mjs https://example.com --json | jq '.cookies'
node bot-probe.mjs https://example.com --json > results.json
```

### Flags

| Flag | Effect |
|---|---|
| `--headed` | Launches a visible Chromium window instead of running headless |
| `--json` | Emits raw JSON to stdout instead of the formatted report |

---

## How It Works

The probe launches a Chromium instance via Playwright, navigates to the target URL, and runs a battery of passive checks across six detection categories. It does not interact with the page beyond navigation — no clicks, no form input, no JavaScript injection beyond a single read-only `evaluate()` call. Everything it finds is from observation alone.

A second Chromium page fetches `robots.txt` from the same origin as a separate lightweight check.

The overall severity rating in the report header (`HIGH`, `MEDIUM`, `LOW`, `NONE`) is the worst individual severity across all findings. It is a signal, not a verdict — a `HIGH` from a Cloudflare cookie on a public marketing site means something very different from the same cookie on a supply chain portal.

---

## Detection Categories

### 1. Infrastructure

**What it does:** Inspects HTTP response headers returned by the server on the initial navigation response.

**How:** Playwright's `response` event exposes all response headers. The probe matches these against a known list of vendor-specific header names.

**What it finds:**

| Header | Vendor | Severity |
|---|---|---|
| `cf-ray` | Cloudflare | LOW |
| `cf-cache-status` | Cloudflare | LOW |
| `server: cloudflare` | Cloudflare (general) | LOW |
| `x-datadome` | DataDome | HIGH |
| `x-px-client-uuid` | PerimeterX / HUMAN | HIGH |
| `x-akamai-edgescape` | Akamai | MEDIUM |
| `x-incap-ses` | Imperva | HIGH |

**Interpretation:** Infrastructure headers establish which CDN or WAF sits in front of the target. Cloudflare alone is low risk — it is ubiquitous and its free tier has minimal bot management. Vendor-specific headers from DataDome, PerimeterX, or Imperva indicate purpose-built bot management is active, not just proxying.

---

### 2. Bot Management Cookies

**What it does:** After navigation completes, reads the full cookie jar for the page context and matches cookie names against known bot management vendor signatures.

**How:** `context.cookies()` returns all cookies set during and after navigation, including those set by JavaScript. The probe matches on exact name and name prefix (e.g. `_px`, `_px2`, `_px3` all match the PerimeterX family).

**What it finds:**

| Cookie | Vendor | Severity |
|---|---|---|
| `__cf_bm` | Cloudflare Bot Management | HIGH |
| `__cfruid` | Cloudflare | MEDIUM |
| `datadome` | DataDome | HIGH |
| `_px`, `_px2`, `_px3`, `_pxvid` | PerimeterX / HUMAN | HIGH |
| `reese84` | Akamai Bot Manager | HIGH |
| `_abck` | Akamai Bot Manager | HIGH |
| `bm_sz` | Akamai Bot Manager | MEDIUM |
| `incap_ses` | Imperva Incapsula | HIGH |
| `visid_incap` | Imperva Incapsula | HIGH |

**Interpretation:** These cookies are set by bot management SDKs to track session state and behavioral scores across requests. Their presence confirms that a vendor's client-side agent is running. `__cf_bm` specifically indicates Cloudflare's paid Bot Management product is active, distinct from the free Cloudflare CDN.

---

### 3. Third-Party Bot Detection Scripts

**What it does:** Monitors every network request made by the page — including scripts, XHR, fetch, and sub-resource loads — and matches request URLs against known vendor patterns.

**How:** Playwright's `page.on('request', ...)` event fires for every outgoing request before it is sent. The probe pattern-matches the URL against a regex table. It also scans `<script src="...">` tags in the DOM via `page.evaluate()` as a secondary pass.

**What it finds:**

| Pattern | Vendor | Type |
|---|---|---|
| `datadome` | DataDome | SDK |
| `perimeterx`, `px.js`, `/px/` | PerimeterX / HUMAN | SDK |
| `akam.net`, `akstat` | Akamai | CDN/Bot |
| `imperva`, `incapsula` | Imperva | SDK |
| `recaptcha`, `grecaptcha` | Google reCAPTCHA | CAPTCHA |
| `hcaptcha` | hCaptcha | CAPTCHA |
| `challenges.cloudflare` | Cloudflare Turnstile | CAPTCHA |
| `fingerprintjs`, `fpjs.io` | FingerprintJS | Fingerprint |
| `threatmetrix` | ThreatMetrix | Fingerprint |
| `kasada` | Kasada | SDK |
| `shape.security`, `f5.com` | F5 Shape Security | SDK |

**Interpretation:** Network interception is the most reliable detection method in this probe. It catches vendor scripts even when they are loaded asynchronously or injected dynamically, and it is not defeated by script obfuscation since the request URL itself reveals the vendor. A script hit confirms the SDK is present and executing.

---

### 4. CAPTCHA

**What it does:** Queries the DOM for known CAPTCHA widget selectors and attributes that indicate a challenge is rendered or embedded on the page.

**How:** Run inside `page.evaluate()`, the probe uses `document.querySelector()` against known CAPTCHA marker patterns — CSS classes, data attributes, and element IDs used by each vendor's embed code.

**What it finds:**

| Selector | Type |
|---|---|
| `.g-recaptcha`, `#g-recaptcha`, `[data-sitekey]` | Google reCAPTCHA |
| `.h-captcha`, `[data-hcaptcha-sitekey]` | hCaptcha |
| `[data-cf-turnstile]`, `.cf-turnstile` | Cloudflare Turnstile |

**Interpretation:** A CAPTCHA present in the DOM on initial load means the site is already challenging unauthenticated or bot-suspected visitors at entry. This is categorically different from a CAPTCHA that only appears after a failed form submission. Note that invisible CAPTCHA variants (reCAPTCHA v3, Turnstile in managed mode) may not render visible DOM elements — their presence may only be detectable via script interception in category 3.

---

### 5. Behavioral Event Hooks

**What it does:** Scans inline `<script>` tags (scripts without a `src` attribute) for event listener registrations targeting human behavioral signals.

**How:** The probe reads the raw text content of all inline scripts via `page.evaluate()` and checks for the presence of known event name strings. It does not execute or parse the JavaScript — it performs text matching only.

**What it finds:**

| Signal | Label |
|---|---|
| `mousemove` | Mouse movement tracking |
| `keydown` | Keystroke timing capture |
| `touchstart` | Touch event tracking |
| `devicemotion` | Accelerometer/gyro capture |
| `scroll` | Scroll behavior tracking |
| `focus` | Focus event tracking |
| `getTimezoneOffset` | Timezone fingerprinting |

**Interpretation:** Bot management systems build behavioral profiles by recording the entropy of human interaction — mouse trajectories, inter-keystroke timing, scroll velocity, touch pressure patterns. These signals feed ML classifiers that score the session as human or bot. Detection here means the site is doing active behavioral analysis, not just checking static fingerprints. This is harder to defeat than header or cookie checks.

**Limitation:** This check only covers inline scripts. Behavioral hooks loaded from external scripts are not caught here, though their presence may be inferred from category 3 hits (e.g. a DataDome SDK load implies behavioral tracking is occurring regardless of whether it is visible in inline code).

---

### 6. Fingerprinting APIs

**What it does:** Scans inline scripts for calls to browser APIs commonly used to construct a device fingerprint.

**How:** Same text-matching approach as category 5, applied to a different set of API surface keywords.

**What it finds:**

| API | Purpose |
|---|---|
| `Canvas.toDataURL` / `getImageData` | Canvas fingerprinting — renders text or shapes and reads pixel data to get a GPU/font rendering signature |
| `WebGL getParameter` | GPU fingerprinting — queries graphics card model and driver details |
| `AudioContext` / `OfflineAudioContext` | Audio fingerprinting — processes a signal through the audio stack to get a hardware-unique output |
| `navigator.plugins` | Plugin enumeration — real browsers have plugins, headless instances typically do not |
| `navigator.webdriver` | Explicit automation check — reads the flag Playwright sets to `true` by default |
| `navigator.languages` | Language fingerprinting — bots often have unusual or empty language arrays |

**Interpretation:** These APIs are used to build a stable device identifier that persists across sessions and is not affected by cookie clearing. Canvas and WebGL fingerprinting are particularly robust because they depend on GPU hardware and driver versions. A site using these APIs is building a persistent profile of visiting devices and can re-identify an automated session even after clearing cookies or changing IP.

---

### 7. Automation Detection (`navigator.webdriver`)

**What it does:** Evaluates `navigator.webdriver` inside the page context and reports its value.

**How:** A single `page.evaluate(() => navigator.webdriver)` call. This is executed in the actual page JavaScript context, so whatever the page would see, the probe sees.

**What it means:**

- `true` — Playwright is exposing itself as an automated session. This is the default behavior. Any site checking this property, which is trivial and extremely common, will detect the session as a bot immediately.
- `false` or `undefined` — The automation signal is suppressed. Playwright has a `--disable-blink-features=AutomationControlled` launch flag that achieves this, though some detection systems probe deeper and check for other V8 automation artifacts.

**Interpretation:** This is the single highest-signal, lowest-effort check a site can run. It is one line of JavaScript: `if (navigator.webdriver) blockUser()`. Any automation framework that does not explicitly suppress this is trivially detectable. If the probe reports `true`, every subsequent finding in the report is likely moot — the session is already flagged.

---

### 8. robots.txt

**What it does:** Fetches `<origin>/robots.txt` and extracts `User-agent` and `Disallow` directives for display.

**How:** A separate page navigates to the robots.txt URL. The probe strips any HTML wrapper (some servers return a styled 404 page) and filters for lines containing `disallow` or `user-agent`, capping output at 20 lines.

**Interpretation:** `robots.txt` is not enforcement — it is a declaration of intent. A site that explicitly disallows common bot user agents (`Googlebot`, `*`) signals awareness of automated traffic and policy around it. It does not directly tell you what technical detection is in place, but it is a useful contextual signal and takes two seconds to check.

---

## Output Modes

### Terminal Report

The default output. Severity icons indicate risk level per finding:

| Icon | Severity | Meaning |
|---|---|---|
| 🔴 | HIGH | Active bot management SDK or explicit automation detection |
| 🟡 | MEDIUM | Behavioral or fingerprinting signals; indirect detection risk |
| 🟢 | LOW | Infrastructure presence only; minimal direct detection risk |
| ✓ | NONE | Category clean |

### JSON Output (`--json`)

Emits a single JSON object to stdout. Useful for piping into downstream tools or storing probe results alongside portal definitions in a larger automation system.

Top-level fields:

```
url               string    — Target URL as provided
timestamp         string    — ISO 8601 probe time
navigationStatus  string    — "success" or "failed"
finalUrl          string    — URL after any redirects
httpStatus        number    — HTTP status code of final response
responseHeaders   object    — All response headers from final response
infrastructure    array     — Header-based vendor findings
cookies           array     — Bot management cookie findings
scripts           array     — Third-party SDK script findings
behavioralHooks   array     — Inline script behavioral event findings
fingerprintingAPIs array    — Inline script fingerprinting API findings
captcha           array     — DOM CAPTCHA widget findings
webdriverExposed  boolean   — navigator.webdriver value
robotsTxt         string    — Raw robots.txt content, or null
redirectChain     array     — Intermediate redirects
errors            array     — Any errors encountered during probe
```

---

## Known Limitations

**Obfuscated inline scripts:** The behavioral hook and fingerprinting API checks are text-matching against raw inline script content. Scripts that are base64-encoded, eval-chained, or otherwise obfuscated will not expose readable keywords and will not be caught by these checks. Third-party SDKs loaded over the network are not affected by this limitation since the request URL is matched before the payload is inspected.

**Headless-specific rendering:** Some detection systems serve different content to headless browsers entirely — returning a clean page with no signals while simultaneously flagging the session server-side. The probe cannot detect what it cannot observe.

**Dynamic injection:** Bot management scripts injected via tag managers (Google Tag Manager, Tealium) after a deliberate delay may not fire within the `networkidle` wait window. Increasing the timeout or switching `waitUntil` to `domcontentloaded` may help in specific cases.

**Authenticated sessions:** The probe runs as an unauthenticated visitor. Detection behavior behind a login wall may differ substantially — some portals apply bot management only to authenticated API endpoints, not the login page itself.

**`navigator.webdriver` suppression:** Passing `--disable-blink-features=AutomationControlled` to the Playwright launch options will set `navigator.webdriver` to `false`, but advanced detection systems (Kasada, Shape Security) probe additional V8 automation artifacts that this flag does not address.
