// Each entry describes one fingerprinting data point.
// getValue() may return a string or a Promise<string> (resolved after the
// card is already rendered, so async signals like canvas/audio don't block).
const FINGERPRINT_POINTS = [
  {
    label: 'IP address',
    method: 'Server reads the connecting socket address (or X-Forwarded-For behind a proxy) — req.ip in Express.',
    explanation: 'Your public IP address, seen by the server on every request. Reveals your ISP and rough geographic location, and is a stable identifier across visits unless it changes.',
    prevention: 'Use a VPN, proxy, or Tor to hide your real IP from the sites you visit.',
    common: 'e.g. 203.0.113.42 or an IPv6 address',
    getValue: () => getServerIp(),
  },
  {
    label: 'HTTP request headers',
    method: 'Server inspects the raw incoming request — req.headers in Express/Node.',
    explanation: 'Headers sent with every request (Accept-Language, Accept-Encoding, Sec-CH-UA client hints, etc.) reveal browser, OS, and preference details independent of JavaScript, and their exact order/casing can itself be a signal.',
    prevention: 'Privacy-focused browsers and proxies (e.g. Tor Browser, some VPN apps) normalize or strip non-essential headers before they reach the server.',
    common: 'accept-language, accept-encoding, sec-ch-ua, sec-fetch-*, connection',
    getValue: () => getServerHeaders(),
  },
  {
    label: 'User Agent',
    method: 'navigator.userAgent',
    explanation: 'A string identifying your browser, engine, and OS. Historically the primary fingerprinting signal, though browsers increasingly freeze or reduce it ("User-Agent reduction").',
    prevention: 'Use a browser that freezes/generalizes the UA string (e.g. Chrome\'s reduction, Firefox\'s resist-fingerprinting mode), or a UA-spoofing extension.',
    common: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/120.0.0.0 Safari/537.36',
    getValue: () => navigator.userAgent,
  },
  {
    label: 'Platform',
    method: 'navigator.platform',
    explanation: 'Reports the OS the browser reports itself as running on (e.g. Win32, MacIntel, Linux x86_64).',
    prevention: 'Firefox resist-fingerprinting normalizes this; some hardening extensions spoof it to a common value like "Win32".',
    common: 'Win32, MacIntel, Linux x86_64',
    getValue: () => navigator.platform || 'unavailable',
  },
  {
    label: 'Language(s)',
    method: 'navigator.languages / navigator.language',
    explanation: 'Your preferred UI/content languages, taken from OS or browser settings — narrows you to a region/locale.',
    prevention: 'Set browser language to a common default (e.g. en-US) instead of a rare locale, or use resist-fingerprinting mode.',
    common: 'en-US, en-GB, de-DE',
    getValue: () => (navigator.languages && navigator.languages.join(', ')) || navigator.language,
  },
  {
    label: 'Timezone',
    method: 'Intl.DateTimeFormat().resolvedOptions().timeZone',
    explanation: 'Derived from Intl.DateTimeFormat or Date offset. Combined with language, narrows your rough geographic location.',
    prevention: 'Firefox resist-fingerprinting mode reports a rounded/UTC timezone; Tor Browser forces UTC for all users.',
    common: 'UTC, Europe/Berlin, America/New_York',
    getValue: () => {
      try {
        return Intl.DateTimeFormat().resolvedOptions().timeZone;
      } catch {
        return 'unavailable';
      }
    },
  },
  {
    label: 'Screen resolution',
    method: 'screen.width/height, screen.availWidth/availHeight, screen.colorDepth',
    explanation: 'Physical screen size, available area, and pixel depth. Common resolutions are shared by millions of devices, but combined with other signals it adds entropy.',
    prevention: 'Browser resist-fingerprinting modes round the reported viewport/screen size to common buckets; using a non-maximized window also helps.',
    common: '1920x1080, 2560x1440, 375x812 (mobile)',
    getValue: () => `${screen.width}x${screen.height} (avail ${screen.availWidth}x${screen.availHeight}), ${screen.colorDepth}-bit`,
  },
  {
    label: 'Device pixel ratio',
    method: 'window.devicePixelRatio',
    explanation: 'Ratio between physical and CSS pixels — reveals display density (e.g. Retina/HiDPI screens).',
    prevention: 'Not commonly spoofed by default; some anti-fingerprinting extensions normalize it to 1.',
    common: '1, 1.5, 2, 3',
    getValue: () => String(window.devicePixelRatio),
  },
  {
    label: 'Hardware concurrency',
    method: 'navigator.hardwareConcurrency',
    explanation: 'Number of logical CPU cores reported by navigator.hardwareConcurrency — a coarse hardware signal.',
    prevention: 'Firefox resist-fingerprinting caps this to a fixed value (e.g. 2 or 4) regardless of real core count.',
    common: '4, 8, 12, 16',
    getValue: () => String(navigator.hardwareConcurrency || 'unavailable'),
  },
  {
    label: 'Device memory',
    method: 'navigator.deviceMemory',
    explanation: 'Approximate RAM in GB, rounded to a power of two, exposed by the Device Memory API (Chromium only).',
    prevention: 'Use Firefox or Safari, which do not implement this API; Chromium-based resist-fingerprinting settings can also block it.',
    common: '4, 8, 16 (GB)',
    getValue: () => (navigator.deviceMemory ? `${navigator.deviceMemory} GB` : 'not supported by this browser'),
  },
  {
    label: 'Touch support',
    method: 'navigator.maxTouchPoints',
    explanation: 'Whether the device reports touch input and how many simultaneous touch points it supports — hints at mobile/tablet vs. desktop hardware.',
    prevention: 'Rarely spoofed; using a device-appropriate browser is the main mitigation since this reflects real hardware.',
    common: '0 (desktop), 1-10 (touchscreens)',
    getValue: () => `maxTouchPoints: ${navigator.maxTouchPoints ?? 0}`,
  },
  {
    label: 'Cookies enabled',
    method: 'navigator.cookieEnabled',
    explanation: 'Whether the browser accepts cookies at all — a weak signal on its own, but feeds into tracking-capability profiling.',
    prevention: 'Disabling cookies breaks most sites, so this alone isn\'t a great mitigation; use per-site cookie controls or a privacy-focused browser instead.',
    common: 'true (vast majority of users)',
    getValue: () => String(navigator.cookieEnabled),
  },
  {
    label: 'Do Not Track',
    method: 'navigator.doNotTrack',
    explanation: 'A now largely-ignored opt-out signal. Because most users leave it unset, having a non-default value can itself be identifying.',
    prevention: 'Leaving it at the default is often more private than enabling it, precisely because enabling it is a minority signal.',
    common: 'null/unspecified (most common), "1"',
    getValue: () => String(navigator.doNotTrack ?? 'unspecified'),
  },
  {
    label: 'Canvas fingerprint',
    method: 'Draw to a hidden <canvas>, then canvas.toDataURL() and hash the pixel output.',
    explanation: 'Renders hidden text/shapes to a &lt;canvas&gt; and hashes the pixel output. Tiny differences in GPU, drivers, and font rendering produce a highly distinguishing hash.',
    prevention: 'Browsers like Tor Browser and Brave add noise or prompt before allowing canvas reads; extensions like CanvasBlocker do the same.',
    common: 'A short hex hash, e.g. "a34f9c21" — near-unique per device/GPU/driver combo',
    getValue: () => getCanvasFingerprint(),
  },
  {
    label: 'WebGL renderer',
    method: 'WEBGL_debug_renderer_info extension, gl.getParameter(UNMASKED_RENDERER_WEBGL)',
    explanation: 'Exposes your GPU vendor and model string via the WebGL context — one of the strongest single hardware signals.',
    prevention: 'Firefox resist-fingerprinting and Tor Browser return a generic "unknown" renderer string instead of the real GPU.',
    common: 'ANGLE (NVIDIA GeForce RTX 3060), Apple M1, Mesa Intel(R) UHD Graphics',
    getValue: () => getWebGLRenderer(),
  },
  {
    label: 'Audio fingerprint',
    method: 'Render a tone through OfflineAudioContext + DynamicsCompressor, sum the output samples.',
    explanation: 'Processes an audio signal through the Web Audio API and hashes the output. Subtle differences in audio hardware/drivers and floating-point math make this distinguishing across devices.',
    prevention: 'Tor Browser and Brave add noise to AudioContext output; extensions like AudioContext Fingerprint Defender do similarly.',
    common: 'A short hex hash, e.g. "129.9421" summed sample value — near-unique per device',
    getValue: () => getAudioFingerprint(),
  },
  {
    label: 'Installed fonts (approx.)',
    method: 'Measure span.offsetWidth for test strings rendered in each candidate font vs. generic fallbacks.',
    explanation: 'Measures text width across many font names to infer which are installed. A large, unusual font set narrows you down significantly.',
    prevention: 'Avoid installing many extra fonts; resist-fingerprinting browser modes limit font enumeration to a system default list.',
    common: '~10-20 common fonts on a fresh OS install (Arial, Times New Roman, Verdana...)',
    getValue: () => detectFonts(),
  },
  {
    label: 'Color scheme / reduced motion',
    method: "window.matchMedia('(prefers-color-scheme: dark)') / matchMedia('(prefers-reduced-motion: reduce)')",
    explanation: 'The prefers-color-scheme and prefers-reduced-motion media queries reveal OS-level accessibility and theme preferences.',
    prevention: 'Low-entropy signal on its own; resist-fingerprinting modes may normalize it, but the main mitigation is combining it with fewer other signals.',
    common: 'light or dark; no-preference (most common) for motion',
    getValue: () => {
      const scheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      const motion = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'reduce' : 'no-preference';
      return `scheme: ${scheme}, motion: ${motion}`;
    },
  },
  {
    label: 'Storage support',
    method: 'Feature-detect window.localStorage, window.sessionStorage, and "indexedDB" in window.',
    explanation: 'Whether localStorage, sessionStorage, and IndexedDB are available — used both for feature detection and as tracking storage.',
    prevention: 'Private/incognito browsing modes and cookie/site-data clearing limit long-term use of these APIs for tracking.',
    common: 'all supported (typical modern browser)',
    getValue: () => {
      const has = (fn) => { try { return !!fn(); } catch { return false; } };
      const local = has(() => window.localStorage);
      const session = has(() => window.sessionStorage);
      const idb = 'indexedDB' in window;
      return `localStorage: ${local}, sessionStorage: ${session}, indexedDB: ${idb}`;
    },
  },
  {
    label: 'Connection type',
    method: 'navigator.connection.effectiveType / .downlink (Network Information API)',
    explanation: 'The Network Information API exposes effective connection type and downlink speed (Chromium only) — can hint at mobile vs. broadband usage patterns.',
    prevention: 'Use Firefox or Safari, which do not expose this API to scripts.',
    common: '4g, wifi (Chromium/Android); not supported on Firefox/Safari',
    getValue: () => {
      const c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
      return c ? `${c.effectiveType || 'unknown'}, ~${c.downlink ?? '?'} Mbps` : 'not supported by this browser';
    },
  },
];

async function getServerIp() {
  try {
    const response = await fetch('/api/ip');
    if (!response.ok) return 'unavailable';
    const data = await response.json();
    return data.ip || 'unavailable';
  } catch {
    return 'unavailable (server not reachable)';
  }
}

async function getServerHeaders() {
  try {
    const response = await fetch('/api/headers');
    if (!response.ok) return 'unavailable';
    const headers = await response.json();
    return Object.entries(headers)
      .map(([key, value]) => `${key}: ${value}`)
      .join('\n');
  } catch {
    return 'unavailable (server not reachable)';
  }
}

function getCanvasFingerprint() {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 220;
    canvas.height = 30;
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px "Arial"';
    ctx.fillStyle = '#f60';
    ctx.fillRect(0, 0, 220, 30);
    ctx.fillStyle = '#069';
    ctx.fillText('Fingerprint test 🔍 canvas', 2, 2);
    ctx.strokeStyle = 'rgba(120, 20, 200, 0.7)';
    ctx.strokeRect(0, 0, 220, 30);
    const dataUrl = canvas.toDataURL();
    return hashString(dataUrl);
  } catch {
    return 'blocked or unsupported';
  }
}

function getWebGLRenderer() {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'WebGL not supported';
    const info = gl.getExtension('WEBGL_debug_renderer_info');
    if (!info) return 'renderer info blocked by browser';
    const vendor = gl.getParameter(info.UNMASKED_VENDOR_WEBGL);
    const renderer = gl.getParameter(info.UNMASKED_RENDERER_WEBGL);
    return `${vendor} — ${renderer}`;
  } catch {
    return 'blocked or unsupported';
  }
}

function getAudioFingerprint() {
  return new Promise((resolve) => {
    try {
      const AudioCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!AudioCtx) return resolve('AudioContext not supported');
      const context = new AudioCtx(1, 5000, 44100);
      const oscillator = context.createOscillator();
      oscillator.type = 'triangle';
      oscillator.frequency.value = 10000;
      const compressor = context.createDynamicsCompressor();
      oscillator.connect(compressor);
      compressor.connect(context.destination);
      oscillator.start(0);

      const timeout = setTimeout(() => resolve('timed out'), 1500);

      context.startRendering();
      context.oncomplete = (event) => {
        clearTimeout(timeout);
        const output = event.renderedBuffer.getChannelData(0);
        let sum = 0;
        for (let i = 4500; i < 5000; i++) sum += Math.abs(output[i]);
        resolve(sum.toFixed(6));
      };
    } catch {
      resolve('blocked or unsupported');
    }
  });
}

function detectFonts() {
  try {
    const testFonts = [
      'Arial', 'Verdana', 'Times New Roman', 'Courier New', 'Georgia',
      'Comic Sans MS', 'Impact', 'Trebuchet MS', 'Segoe UI', 'Tahoma',
      'Helvetica', 'Calibri', 'Consolas', 'Roboto', 'Menlo',
    ];
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    const testString = 'mmmmmmmmmmlli';
    const testSize = '72px';
    const span = document.createElement('span');
    span.style.position = 'absolute';
    span.style.left = '-9999px';
    span.style.fontSize = testSize;
    span.textContent = testString;
    document.body.appendChild(span);

    const baseWidths = {};
    baseFonts.forEach((base) => {
      span.style.fontFamily = base;
      baseWidths[base] = span.offsetWidth;
    });

    const detected = testFonts.filter((font) => {
      return baseFonts.some((base) => {
        span.style.fontFamily = `"${font}", ${base}`;
        return span.offsetWidth !== baseWidths[base];
      });
    });

    document.body.removeChild(span);
    return detected.length ? `${detected.length} detected: ${detected.join(', ')}` : 'none detected';
  } catch {
    return 'detection failed';
  }
}

function hashString(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (Math.imul(31, hash) + str.charCodeAt(i)) | 0;
  }
  return (hash >>> 0).toString(16);
}

function renderCards() {
  const list = document.getElementById('card-list');
  FINGERPRINT_POINTS.forEach((point, index) => {
    const card = document.createElement('article');
    card.className = 'card';

    const valueCell = document.createElement('div');
    valueCell.className = 'cell cell-value';
    const label = document.createElement('h2');
    label.textContent = `${index + 1}. ${point.label}`;
    const value = document.createElement('p');
    value.className = 'value';
    value.textContent = 'detecting…';
    valueCell.append(label, value);

    const methodCell = document.createElement('div');
    methodCell.className = 'cell cell-method';
    methodCell.innerHTML = `<h3>How to get it</h3><p><code>${point.method}</code></p>`;

    const explanationCell = document.createElement('div');
    explanationCell.className = 'cell cell-explanation';
    explanationCell.innerHTML = `<h3>What it is</h3><p>${point.explanation}</p>`;

    const preventionCell = document.createElement('div');
    preventionCell.className = 'cell cell-prevention';
    preventionCell.innerHTML = `<h3>Reducing exposure</h3><p>${point.prevention}</p>`;

    const commonCell = document.createElement('div');
    commonCell.className = 'cell cell-common';
    commonCell.innerHTML = `<h3>Common values</h3><p>${point.common}</p>`;

    card.append(valueCell, methodCell, explanationCell, preventionCell, commonCell);
    list.appendChild(card);

    Promise.resolve(point.getValue())
      .then((result) => { value.textContent = result; })
      .catch(() => { value.textContent = 'error reading value'; });
  });
}

renderCards();
