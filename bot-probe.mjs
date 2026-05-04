/**
 * bot-probe.mjs
 * Headless Playwright probe for bot/agent detection signals.
 *
 * Usage:
 *   node bot-probe.mjs <url> [--headed] [--json]
 *
 * Options:
 *   --headed   Run with a visible browser window
 *   --json     Output raw JSON instead of formatted report
 */


import { chromium } from 'playwright';

// ─── Constants ────────────────────────────────────────────────────────────────

const BOT_COOKIES = {
  '__cf_bm':   { vendor: 'Cloudflare Bot Management', severity: 'HIGH' },
  '__cfruid':  { vendor: 'Cloudflare',                severity: 'MEDIUM' },
  'datadome':  { vendor: 'DataDome',                  severity: 'HIGH' },
  '_px':       { vendor: 'PerimeterX / HUMAN',        severity: 'HIGH' },
  '_pxvid':    { vendor: 'PerimeterX / HUMAN',        severity: 'HIGH' },
  '_px2':      { vendor: 'PerimeterX / HUMAN',        severity: 'HIGH' },
  '_px3':      { vendor: 'PerimeterX / HUMAN',        severity: 'HIGH' },
  'reese84':   { vendor: 'Akamai Bot Manager',        severity: 'HIGH' },
  '_abck':     { vendor: 'Akamai Bot Manager',        severity: 'HIGH' },
  'bm_sz':     { vendor: 'Akamai Bot Manager',        severity: 'MEDIUM' },
  'incap_ses': { vendor: 'Imperva Incapsula',         severity: 'HIGH' },
  'visid_incap': { vendor: 'Imperva Incapsula',       severity: 'HIGH' },
};

const BOT_HEADERS = {
  'cf-ray':          { vendor: 'Cloudflare',    severity: 'LOW' },
  'cf-cache-status': { vendor: 'Cloudflare',    severity: 'LOW' },
  'x-datadome':      { vendor: 'DataDome',      severity: 'HIGH' },
  'x-px-client-uuid':{ vendor: 'PerimeterX',   severity: 'HIGH' },
  'x-akamai-edgescape': { vendor: 'Akamai',    severity: 'MEDIUM' },
  'x-incap-ses':     { vendor: 'Imperva',       severity: 'HIGH' },
};

const FINGERPRINT_PATTERNS = [
  { pattern: /datadome/i,                 vendor: 'DataDome',            type: 'SDK' },
  { pattern: /perimeterx|px\.js|\/px\//i, vendor: 'PerimeterX / HUMAN', type: 'SDK' },
  { pattern: /akam\.net|akstat/i,         vendor: 'Akamai',              type: 'CDN/Bot' },
  { pattern: /imperva|incapsula/i,        vendor: 'Imperva',             type: 'SDK' },
  { pattern: /\.kastatic\.org/i,          vendor: 'Khan Academy reCAPTCHA', type: 'CAPTCHA' },
  { pattern: /recaptcha|grecaptcha/i,     vendor: 'Google reCAPTCHA',   type: 'CAPTCHA' },
  { pattern: /hcaptcha/i,                 vendor: 'hCaptcha',            type: 'CAPTCHA' },
  { pattern: /challenges\.cloudflare/i,   vendor: 'Cloudflare Turnstile', type: 'CAPTCHA' },
  { pattern: /fingerprintjs|fpjs\.io/i,   vendor: 'FingerprintJS',       type: 'Fingerprint' },
  { pattern: /threatmetrix/i,             vendor: 'ThreatMetrix',        type: 'Fingerprint' },
  { pattern: /kasada/i,                   vendor: 'Kasada',              type: 'SDK' },
  { pattern: /shape\.security|f5\.com/i,  vendor: 'F5 Shape Security',   type: 'SDK' },
];

// ─── CLI Parsing ──────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const url = args.find(a => !a.startsWith('--'));
const headed = args.includes('--headed');
const jsonOutput = args.includes('--json');

if (!url) {
  console.error('Usage: node bot-probe.mjs <url> [--headed] [--json]');
  process.exit(1);
}

// ─── Probe Logic ──────────────────────────────────────────────────────────────

async function probe(targetUrl) {
  const results = {
    url: targetUrl,
    timestamp: new Date().toISOString(),
    navigationStatus: null,
    finalUrl: null,
    httpStatus: null,
    responseHeaders: {},
    infrastructure: [],
    cookies: [],
    scripts: [],
    behavioralHooks: [],
    fingerprintingAPIs: [],
    captcha: [],
    webdriverExposed: null,
    robotsTxt: null,
    redirectChain: [],
    errors: [],
  };

  const browser = await chromium.launch({ headless: !headed });
  const context = await browser.newContext({
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
      '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  });

  const page = await context.newPage();
  const collectedScripts = new Set();

  // Intercept all network requests
  page.on('request', req => {
    const u = req.url();
    for (const fp of FINGERPRINT_PATTERNS) {
      if (fp.pattern.test(u) && !collectedScripts.has(u)) {
        collectedScripts.add(u);
        results.scripts.push({ url: u, vendor: fp.vendor, type: fp.type });
      }
    }
  });

  // Capture redirect chain and final response headers
  page.on('response', res => {
    if (res.url() === targetUrl || res.request().isNavigationRequest()) {
      const status = res.status();
      if ([301, 302, 307, 308].includes(status)) {
        results.redirectChain.push({ from: res.url(), status });
      }
      if (res.url() === page.url() || results.httpStatus === null) {
        results.httpStatus = status;
        results.responseHeaders = res.headers();
      }
    }
  });

  // Navigate
  try {
    const response = await page.goto(targetUrl, {
      waitUntil: 'networkidle',
      timeout: 20000,
    });
    results.navigationStatus = 'success';
    results.finalUrl = page.url();
    if (response) {
      results.httpStatus = response.status();
      results.responseHeaders = response.headers();
    }
  } catch (err) {
    results.navigationStatus = 'failed';
    results.errors.push(`Navigation error: ${err.message}`);
  }

  // ── In-page evaluation ────────────────────────────────────────────────────
  if (results.navigationStatus === 'success') {
    const pageData = await page.evaluate(() => {
      const hooks = [];
      const fpAPIs = [];
      const captcha = [];

      // Check navigator.webdriver
      const webdriverExposed = navigator.webdriver === true;

      // Scan all script tags for known patterns
      const scriptUrls = Array.from(document.querySelectorAll('script[src]'))
        .map(s => s.src);

      // Check for CAPTCHA widgets in DOM
      if (document.querySelector('.g-recaptcha, #g-recaptcha, [data-sitekey]')) {
        captcha.push({ type: 'reCAPTCHA', location: 'DOM element' });
      }
      if (document.querySelector('.h-captcha, [data-hcaptcha-sitekey]')) {
        captcha.push({ type: 'hCaptcha', location: 'DOM element' });
      }
      if (document.querySelector('[data-cf-turnstile], .cf-turnstile')) {
        captcha.push({ type: 'Cloudflare Turnstile', location: 'DOM element' });
      }

      // Detect behavioral event hooking via inline scripts
      const inlineScripts = Array.from(document.querySelectorAll('script:not([src])'))
        .map(s => s.textContent || '');

      const behavioralKeywords = [
        { key: 'mousemove',     label: 'Mouse movement tracking' },
        { key: 'keydown',       label: 'Keystroke timing capture' },
        { key: 'touchstart',    label: 'Touch event tracking' },
        { key: 'devicemotion',  label: 'Accelerometer/gyro capture' },
        { key: 'scroll',        label: 'Scroll behavior tracking' },
        { key: 'focus',         label: 'Focus event tracking' },
        { key: 'getTimezoneOffset', label: 'Timezone fingerprinting' },
      ];

      for (const script of inlineScripts) {
        for (const bk of behavioralKeywords) {
          if (script.includes(bk.key)) {
            if (!hooks.find(h => h.label === bk.label)) {
              hooks.push({ signal: bk.key, label: bk.label });
            }
          }
        }
      }

      // Canvas fingerprinting
      const allScripts = inlineScripts.join('\n');
      if (allScripts.includes('toDataURL') || allScripts.includes('getImageData')) {
        fpAPIs.push({ api: 'Canvas.toDataURL / getImageData', purpose: 'Canvas fingerprinting' });
      }
      if (allScripts.includes('getParameter') || allScripts.includes('WebGLRenderingContext')) {
        fpAPIs.push({ api: 'WebGL getParameter', purpose: 'GPU fingerprinting' });
      }
      if (allScripts.includes('AudioContext') || allScripts.includes('OfflineAudioContext')) {
        fpAPIs.push({ api: 'AudioContext', purpose: 'Audio fingerprinting' });
      }
      if (allScripts.includes('navigator.plugins')) {
        fpAPIs.push({ api: 'navigator.plugins', purpose: 'Plugin enumeration' });
      }
      if (allScripts.includes('navigator.webdriver')) {
        fpAPIs.push({ api: 'navigator.webdriver', purpose: 'Explicit automation detection check' });
      }
      if (allScripts.includes('navigator.languages')) {
        fpAPIs.push({ api: 'navigator.languages', purpose: 'Language fingerprinting' });
      }

      return { webdriverExposed, scriptUrls, hooks, fpAPIs, captcha };
    });

    results.webdriverExposed = pageData.webdriverExposed;
    results.behavioralHooks.push(...pageData.hooks);
    results.fingerprintingAPIs.push(...pageData.fpAPIs);
    results.captcha.push(...pageData.captcha);

    // Cross-check script URLs against patterns
    for (const scriptUrl of pageData.scriptUrls) {
      for (const fp of FINGERPRINT_PATTERNS) {
        if (fp.pattern.test(scriptUrl) && !collectedScripts.has(scriptUrl)) {
          collectedScripts.add(scriptUrl);
          results.scripts.push({ url: scriptUrl, vendor: fp.vendor, type: fp.type });
        }
      }
    }
  }

  // ── Cookie analysis ───────────────────────────────────────────────────────
  const cookies = await context.cookies();
  for (const cookie of cookies) {
    for (const [name, meta] of Object.entries(BOT_COOKIES)) {
      if (cookie.name === name || cookie.name.startsWith(name)) {
        results.cookies.push({
          name: cookie.name,
          vendor: meta.vendor,
          severity: meta.severity,
          domain: cookie.domain,
        });
      }
    }
  }

  // ── Response header analysis ──────────────────────────────────────────────
  for (const [header, meta] of Object.entries(BOT_HEADERS)) {
    if (results.responseHeaders[header] !== undefined) {
      results.infrastructure.push({
        signal: header,
        vendor: meta.vendor,
        severity: meta.severity,
        value: results.responseHeaders[header],
      });
    }
  }

  // Cloudflare general detection
  if (results.responseHeaders['server'] === 'cloudflare') {
    if (!results.infrastructure.find(i => i.vendor === 'Cloudflare')) {
      results.infrastructure.push({
        signal: 'Server: cloudflare',
        vendor: 'Cloudflare',
        severity: 'LOW',
        value: 'cloudflare',
      });
    }
  }

  // ── robots.txt ────────────────────────────────────────────────────────────
  try {
    const origin = new URL(targetUrl).origin;
    const robotsPage = await context.newPage();
    const robotsRes = await robotsPage.goto(`${origin}/robots.txt`, { timeout: 8000 });
    if (robotsRes && robotsRes.status() === 200) {
      results.robotsTxt = await robotsPage.content();
    } else {
      results.robotsTxt = null;
    }
    await robotsPage.close();
  } catch {
    results.robotsTxt = null;
  }

  await browser.close();
  return results;
}

// ─── Report Rendering ─────────────────────────────────────────────────────────

const SEVERITY_ICON = { HIGH: '🔴', MEDIUM: '🟡', LOW: '🟢' };
const SEP = '─'.repeat(64);

function severityOf(results) {
  const all = [
    ...results.cookies.map(c => c.severity),
    ...results.infrastructure.map(i => i.severity),
    ...(results.scripts.length ? ['MEDIUM'] : []),
    ...(results.behavioralHooks.length ? ['MEDIUM'] : []),
    ...(results.fingerprintingAPIs.length ? ['MEDIUM'] : []),
    ...(results.captcha.length ? ['HIGH'] : []),
    ...(results.webdriverExposed ? ['HIGH'] : []),
  ];
  if (all.includes('HIGH')) return 'HIGH';
  if (all.includes('MEDIUM')) return 'MEDIUM';
  if (all.length) return 'LOW';
  return 'NONE';
}

function renderRobotsTxt(raw) {
  if (!raw) return '  None found or not accessible.';
  // Extract only Disallow lines mentioning common bot UAs
  const lines = raw
    .replace(/<[^>]+>/g, '') // strip HTML tags if any
    .split('\n')
    .filter(l => /disallow|user-agent/i.test(l))
    .slice(0, 20);
  return lines.length
    ? lines.map(l => `  ${l.trim()}`).join('\n')
    : '  robots.txt present but no notable Disallow rules found.';
}

function renderReport(r) {
  const overall = severityOf(r);
  const lines = [];

  lines.push('');
  lines.push('╔══════════════════════════════════════════════════════════════╗');
  lines.push('║              BOT DETECTION PROBE REPORT                     ║');
  lines.push('╚══════════════════════════════════════════════════════════════╝');
  lines.push('');
  lines.push(`  Target  : ${r.url}`);
  if (r.finalUrl && r.finalUrl !== r.url) {
    lines.push(`  Final   : ${r.finalUrl}`);
  }
  lines.push(`  Status  : HTTP ${r.httpStatus ?? 'unknown'} — ${r.navigationStatus}`);
  lines.push(`  Scanned : ${r.timestamp}`);
  lines.push(`  Overall : ${SEVERITY_ICON[overall] ?? '⚪'} ${overall} detection risk`);

  if (r.redirectChain.length) {
    lines.push('');
    lines.push(`  Redirects: ${r.redirectChain.map(rd => `${rd.status} from ${rd.from}`).join(' → ')}`);
  }

  // Infrastructure
  lines.push('');
  lines.push(SEP);
  lines.push('  INFRASTRUCTURE');
  lines.push(SEP);
  if (r.infrastructure.length) {
    for (const i of r.infrastructure) {
      lines.push(`  ${SEVERITY_ICON[i.severity]} ${i.vendor}`);
      lines.push(`     Header: ${i.signal} = ${i.value}`);
    }
  } else {
    lines.push('  ✓  No known CDN/WAF vendor headers detected.');
  }

  // Cookies
  lines.push('');
  lines.push(SEP);
  lines.push('  BOT MANAGEMENT COOKIES');
  lines.push(SEP);
  if (r.cookies.length) {
    for (const c of r.cookies) {
      lines.push(`  ${SEVERITY_ICON[c.severity]} ${c.vendor}`);
      lines.push(`     Cookie: ${c.name}  (domain: ${c.domain})`);
    }
  } else {
    lines.push('  ✓  No known bot management cookies detected.');
  }

  // Third-party scripts
  lines.push('');
  lines.push(SEP);
  lines.push('  THIRD-PARTY BOT DETECTION SCRIPTS');
  lines.push(SEP);
  if (r.scripts.length) {
    for (const s of r.scripts) {
      lines.push(`  🟡 ${s.vendor} [${s.type}]`);
      lines.push(`     ${s.url}`);
    }
  } else {
    lines.push('  ✓  No known bot detection SDK scripts detected.');
  }

  // CAPTCHA
  lines.push('');
  lines.push(SEP);
  lines.push('  CAPTCHA');
  lines.push(SEP);
  if (r.captcha.length) {
    for (const c of r.captcha) {
      lines.push(`  🔴 ${c.type} — ${c.location}`);
    }
  } else {
    lines.push('  ✓  No CAPTCHA widgets detected in DOM.');
  }

  // Behavioral hooks
  lines.push('');
  lines.push(SEP);
  lines.push('  BEHAVIORAL EVENT HOOKS (inline scripts)');
  lines.push(SEP);
  if (r.behavioralHooks.length) {
    for (const h of r.behavioralHooks) {
      lines.push(`  🟡 ${h.label}`);
      lines.push(`     Event: "${h.signal}"`);
    }
  } else {
    lines.push('  ✓  No behavioral tracking hooks detected in inline scripts.');
  }

  // Fingerprinting APIs
  lines.push('');
  lines.push(SEP);
  lines.push('  FINGERPRINTING APIs (inline scripts)');
  lines.push(SEP);
  if (r.fingerprintingAPIs.length) {
    for (const f of r.fingerprintingAPIs) {
      lines.push(`  🟡 ${f.purpose}`);
      lines.push(`     API: ${f.api}`);
    }
  } else {
    lines.push('  ✓  No fingerprinting API calls detected in inline scripts.');
  }

  // navigator.webdriver
  lines.push('');
  lines.push(SEP);
  lines.push('  AUTOMATION DETECTION');
  lines.push(SEP);
  if (r.webdriverExposed === true) {
    lines.push('  🔴 navigator.webdriver === true');
    lines.push('     The page can trivially identify this as an automated session.');
  } else if (r.webdriverExposed === false) {
    lines.push('  ✓  navigator.webdriver is false or undefined.');
  } else {
    lines.push('  ⚪  Could not evaluate navigator.webdriver (navigation may have failed).');
  }

  // robots.txt
  lines.push('');
  lines.push(SEP);
  lines.push('  ROBOTS.TXT');
  lines.push(SEP);
  lines.push(renderRobotsTxt(r.robotsTxt));

  // Errors
  if (r.errors.length) {
    lines.push('');
    lines.push(SEP);
    lines.push('  ERRORS');
    lines.push(SEP);
    for (const e of r.errors) {
      lines.push(`  ⚠  ${e}`);
    }
  }

  lines.push('');
  lines.push(SEP);
  lines.push('');

  return lines.join('\n');
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

(async () => {
  console.error(`\nProbing: ${url}\n`);
  try {
    const results = await probe(url);
    if (jsonOutput) {
      console.log(JSON.stringify(results, null, 2));
    } else {
      console.log(renderReport(results));
    }
  } catch (err) {
    console.error('Fatal probe error:', err);
    process.exit(1);
  }
})();
