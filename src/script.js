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
    label: 'Browser BuildID',
    method: 'navigator.buildID',
    explanation: 'A Firefox-only property that historically reported the exact build timestamp of the browser, down to the second — extremely identifying when present.',
    prevention: 'Modern Firefox freezes this to a fixed placeholder date instead of the real build time; the property is undefined in Chromium and WebKit browsers entirely.',
    common: '20181001000000 (frozen placeholder in modern Firefox); undefined on Chrome/Safari',
    getValue: () => navigator.buildID || 'not supported by this browser',
  },
  {
    label: 'Navigator vendor/product strings',
    method: 'navigator.vendor, navigator.vendorSub, navigator.product, navigator.productSub',
    explanation: 'A handful of legacy identity strings the browser reports about itself, holdovers from the Netscape era. Mostly frozen to fixed values today, but the exact combination still differs between browser engines.',
    prevention: 'All major browsers already freeze these to fixed values; nothing further to configure.',
    common: 'Chrome/Safari: "Google Inc." / "" / "Gecko" / "20030107"; Firefox: "" / "" / "Gecko" / "20100101"',
    getValue: () => `vendor: ${navigator.vendor || '(empty)'}, vendorSub: ${navigator.vendorSub || '(empty)'}, product: ${navigator.product || '(empty)'}, productSub: ${navigator.productSub || '(empty)'}`,
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
    label: 'Screen position',
    method: 'window.screenX/screenY (or screen.left/top), screen.availLeft/availTop',
    explanation: 'The window\'s position on the screen and the offset of the usable desktop area (excluding OS taskbars/docks). On multi-monitor setups this reveals which monitor a window sits on and how the taskbar is positioned.',
    prevention: 'Low-entropy signal on its own; mostly useful combined with other signals, since window position varies constantly with normal use.',
    common: '0, 0 (single monitor, un-moved window); non-zero values common with taskbars or multi-monitor setups',
    getValue: () => `screenX/Y: ${window.screenX ?? 'n/a'}/${window.screenY ?? 'n/a'}, availLeft/Top: ${screen.availLeft ?? 'n/a'}/${screen.availTop ?? 'n/a'}`,
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
    label: 'List of plugins',
    method: 'navigator.plugins',
    explanation: 'A browser-populated array describing installed browser plugins (PDF viewer, etc.). The exact set and order of plugins can vary by browser, OS, and installed software, adding entropy.',
    prevention: 'Modern Chrome/Firefox report a small, standardized plugin list regardless of what\'s actually installed; Firefox resist-fingerprinting mode further reduces this to a fixed generic list.',
    common: 'Chrome: PDF Viewer, Chrome PDF Viewer, Chromium PDF Viewer, Microsoft Edge PDF Viewer, WebKit built-in PDF; often empty on mobile/Firefox',
    getValue: () => {
      const plugins = Array.from(navigator.plugins || []);
      return plugins.length ? plugins.map((p) => p.name).join(', ') : 'none reported';
    },
  },
  {
    label: 'List of MIME types',
    method: 'navigator.mimeTypes',
    explanation: 'A browser-populated array of media types the browser can handle natively (often tied to installed plugins, e.g. PDF viewers). The exact set adds entropy alongside the plugin list.',
    prevention: 'Modern browsers report a small, standardized MIME type list rather than the true set of installed handlers; Firefox resist-fingerprinting mode further reduces this.',
    common: 'application/pdf, text/pdf; often empty on Firefox and mobile browsers',
    getValue: () => {
      const mimeTypes = Array.from(navigator.mimeTypes || []);
      return mimeTypes.length ? mimeTypes.map((m) => m.type).join(', ') : 'none reported';
    },
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
    label: 'Canvas rendering (visual)',
    method: 'Draw a fixed picture (gradient, shape, text) to a visible <canvas> using the exact same instructions every time.',
    explanation: 'The canvas below is rendered from the same fixed set of drawing instructions on every browser. The result usually looks identical to the eye, but anti-aliasing, sub-pixel hinting, and GPU/driver differences between OS and browser combinations produce slightly different pixel data — which is what canvas fingerprinting hashes.',
    prevention: 'Same as the canvas fingerprint above: Tor Browser and Brave add noise or require a permission prompt before a page can read canvas pixel data; extensions like CanvasBlocker do the same.',
    common: 'Visually near-identical across devices, but pixel-level differences are common between OS/browser/GPU combinations',
    renderValue: (container) => renderCanvasPicture(container),
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
    label: 'WebGL fingerprint (hash)',
    method: 'Render a shaded gradient triangle pair via a WebGL shader program, then canvas.toDataURL() and hash the pixel output.',
    explanation: 'Similar to the canvas fingerprint, but rendered through the GPU-accelerated WebGL pipeline instead of the 2D canvas API. Differences in GPU, drivers, and shader compilation produce a distinguishing hash independent of the canvas one.',
    prevention: 'Firefox resist-fingerprinting and Tor Browser block or return generic output for WebGL reads; extensions like CanvasBlocker also cover WebGL.',
    common: 'A short hex hash, e.g. "7c21f9a3" — near-unique per device/GPU/driver combo',
    getValue: () => getWebGLImageHash(),
  },
  {
    label: 'WebGL parameters & extensions',
    method: 'gl.getParameter(MAX_TEXTURE_SIZE / ALIASED_LINE_WIDTH_RANGE / MAX_VIEWPORT_DIMS), gl.getSupportedExtensions()',
    explanation: 'Beyond the renderer string, WebGL exposes numeric hardware limits (max texture size, line width range, viewport dimensions) and the list of supported extensions — both vary by GPU, driver version, and browser, adding further entropy.',
    prevention: 'Firefox resist-fingerprinting and Tor Browser limit or normalize these values alongside the renderer string.',
    common: 'MAX_TEXTURE_SIZE: 16384 (common on modern GPUs); ~30-40 supported extensions on desktop, fewer on mobile',
    getValue: () => getWebGLParameters(),
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
    label: 'Supported audio formats',
    method: 'new Audio().canPlayType(mimeType) probed against a fixed list of audio codecs.',
    explanation: 'Which audio codecs a browser can play (MP3, AAC, Ogg Vorbis/Opus, WAV, FLAC) depends on licensing and the underlying OS media framework, so the supported set varies by browser and platform.',
    prevention: 'Low-entropy signal on its own since most mainstream browsers support a similar core set; mainly useful combined with other signals.',
    common: 'probably: mp3, aac, wav; maybe: ogg/opus (varies by browser and OS codec licensing)',
    getValue: () => getSupportedMediaFormats('audio'),
  },
  {
    label: 'Supported video formats',
    method: 'document.createElement("video").canPlayType(mimeType) probed against a fixed list of video codecs.',
    explanation: 'Which video codecs a browser can play (H.264, WebM/VP8/VP9, Ogg Theora, HEVC) depends on licensing deals and OS-level hardware decoders, so the supported set varies by browser, OS, and even device model.',
    prevention: 'Low-entropy signal on its own; mainly useful combined with other signals such as OS/platform.',
    common: 'probably: mp4/H.264; maybe: webm/vp9 (varies by browser, OS, and hardware decoder support)',
    getValue: () => getSupportedMediaFormats('video'),
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
  {
    label: 'Ad blocker detection',
    method: 'Insert a hidden bait element with classic ad-related class names (e.g. "adsbox"), then check if it was hidden/collapsed by a filter list.',
    explanation: 'Ad blockers and privacy extensions apply filter-list CSS rules that hide elements matching known ad-related names. Whether a page can detect this reveals which extensions are active — a meaningful cross-site identifier since only a minority of users run specific combinations.',
    prevention: 'Ad blockers with "anti-adblock-detection" filter lists (e.g. some EasyList add-ons) specifically prevent this kind of probing.',
    common: 'not detected (majority of users); likely blocked (ad blocker detected) for extension users',
    getValue: () => detectAdBlocker(),
  },
  {
    label: 'Media devices',
    method: 'navigator.mediaDevices.enumerateDevices()',
    explanation: 'Lists the number of audio input, audio output, and video input devices attached to the system. Device labels are hidden until microphone/camera permission is granted, but the counts alone reveal hardware setup (e.g. laptop with one webcam vs. a multi-monitor streaming rig).',
    prevention: 'Firefox resist-fingerprinting mode reports a single generic device per kind instead of the real count; denying camera/microphone permission does not hide the counts, only the labels.',
    common: '1 audio input, 1-2 audio outputs, 1 video input (typical laptop)',
    getValue: () => getMediaDeviceCounts(),
  },
  {
    label: 'Keyboard layout',
    method: 'navigator.keyboard.getLayoutMap() (Keyboard API, Chromium only)',
    explanation: 'Exposes the physical-to-character mapping of the keyboard layout (e.g. which key produces "y" vs. "z"), revealing regional/language keyboard hardware independent of the browser\'s UI language.',
    prevention: 'Only implemented in Chromium browsers; Firefox and Safari never expose this API to scripts.',
    common: 'QWERTY (US/UK), QWERTZ (DE/AT/CH), AZERTY (FR); not supported on Firefox/Safari',
    getValue: () => getKeyboardLayout(),
  },
  {
    label: 'Window chrome visibility',
    method: 'window.locationbar.visible, .menubar, .personalbar, .scrollbars, .statusbar, .toolbar',
    explanation: 'Reports which browser UI chrome (address bar, menu bar, bookmarks bar, scrollbars, status bar, toolbar) is visible in the current window. Normal tabs report all as visible; popups opened via window.open() with specific features often hide several of them.',
    prevention: 'Low-entropy signal on its own; mainly useful to detect popup vs. normal-tab context rather than to identify a specific user.',
    common: 'all true (normal browser tab); several false (popup windows)',
    getValue: () => getWindowChromeVisibility(),
  },
  {
    label: 'Battery status',
    method: 'navigator.getBattery() (Battery Status API)',
    explanation: 'Previously exposed real-time battery charge level and charging state, which researchers showed could act as a short-lived tracking identifier across sites. Now removed or restricted in most browsers because of that privacy risk.',
    prevention: 'Firefox and Safari never implemented it; Chrome restricted it to secure/top-level contexts. No user action needed on modern browsers.',
    common: 'not supported by this browser (removed/restricted in Firefox, Safari, and recent Chrome policy)',
    getValue: () => getBatteryStatus(),
  },
  {
    label: 'Permissions API states',
    method: 'navigator.permissions.query({ name }) for a fixed list of permission names',
    explanation: 'Reports the granted/denied/prompt state of several browser permissions (geolocation, notifications, camera, microphone, etc.), without triggering a permission prompt. Your specific combination of prior grants/denials across sites is a meaningful cross-site identifier.',
    prevention: 'Reset site permissions periodically in browser settings, or use a browser profile that starts with all permissions at "prompt" by default.',
    common: 'geolocation/notifications: prompt (most users never asked); camera/microphone: prompt or denied',
    getValue: () => getPermissionStates(),
  },
  {
    label: 'Motion & sensor APIs',
    method: 'Feature-detect the Accelerometer, Gyroscope, and ProximitySensor constructors (Generic Sensor API)',
    explanation: 'Modern phones and some laptops expose motion and proximity sensors to the browser. Their mere availability (mobile hardware vs. desktop) and construction behavior (often blocked by Permissions Policy) add another hardware-class signal.',
    prevention: 'Desktop browsers without the hardware simply don\'t implement these constructors; Firefox and Safari don\'t implement the Generic Sensor API at all.',
    common: 'available on many Android Chrome devices; not supported on Firefox, Safari, or most desktops',
    getValue: () => getSensorSupport(),
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

function renderCanvasPicture(container) {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 260;
    canvas.height = 60;
    canvas.className = 'canvas-preview';
    const ctx = canvas.getContext('2d');

    const gradient = ctx.createLinearGradient(0, 0, 260, 0);
    gradient.addColorStop(0, '#f60');
    gradient.addColorStop(1, '#069');
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, 260, 60);

    ctx.beginPath();
    ctx.arc(35, 30, 20, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
    ctx.fill();

    ctx.textBaseline = 'middle';
    ctx.font = 'italic 16px Arial';
    ctx.fillStyle = '#fff';
    ctx.fillText('Fingerprint 🔍 test', 65, 32);

    container.appendChild(canvas);
  } catch {
    const message = document.createElement('p');
    message.className = 'value';
    message.textContent = 'blocked or unsupported';
    container.appendChild(message);
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

function getWebGLParameters() {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'WebGL not supported';

    const maxTextureSize = gl.getParameter(gl.MAX_TEXTURE_SIZE);
    const lineWidthRange = gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE);
    const viewportDims = gl.getParameter(gl.MAX_VIEWPORT_DIMS);
    const extensionCount = (gl.getSupportedExtensions() || []).length;

    return `MAX_TEXTURE_SIZE: ${maxTextureSize}, line width range: [${lineWidthRange}], max viewport: [${viewportDims}], ${extensionCount} extensions supported`;
  } catch {
    return 'blocked or unsupported';
  }
}

function getWebGLImageHash() {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 256;
    canvas.height = 128;
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'WebGL not supported';

    const vertexSrc = `
      attribute vec2 position;
      varying vec2 vPos;
      void main() {
        vPos = position;
        gl_Position = vec4(position, 0.0, 1.0);
      }
    `;
    const fragmentSrc = `
      precision mediump float;
      varying vec2 vPos;
      void main() {
        gl_FragColor = vec4(vPos.x * 0.5 + 0.5, vPos.y * 0.5 + 0.5, 0.5, 1.0);
      }
    `;

    const compile = (type, src) => {
      const shader = gl.createShader(type);
      gl.shaderSource(shader, src);
      gl.compileShader(shader);
      return shader;
    };

    const program = gl.createProgram();
    gl.attachShader(program, compile(gl.VERTEX_SHADER, vertexSrc));
    gl.attachShader(program, compile(gl.FRAGMENT_SHADER, fragmentSrc));
    gl.linkProgram(program);
    gl.useProgram(program);

    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([
      -1, -1, 1, -1, -1, 1,
      -1, 1, 1, -1, 1, 1,
    ]), gl.STATIC_DRAW);

    const posLoc = gl.getAttribLocation(program, 'position');
    gl.enableVertexAttribArray(posLoc);
    gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 0, 0);

    gl.viewport(0, 0, canvas.width, canvas.height);
    gl.drawArrays(gl.TRIANGLES, 0, 6);

    const dataUrl = canvas.toDataURL();
    return hashString(dataUrl);
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

function getSupportedMediaFormats(kind) {
  try {
    const element = document.createElement(kind);
    if (!element.canPlayType) return 'canPlayType not supported';

    const candidates = kind === 'audio'
      ? [
        ['mp3', 'audio/mpeg'],
        ['aac', 'audio/mp4; codecs="mp4a.40.2"'],
        ['wav', 'audio/wav; codecs="1"'],
        ['ogg/vorbis', 'audio/ogg; codecs="vorbis"'],
        ['ogg/opus', 'audio/ogg; codecs="opus"'],
        ['flac', 'audio/flac'],
      ]
      : [
        ['mp4/h264', 'video/mp4; codecs="avc1.42E01E"'],
        ['webm/vp8', 'video/webm; codecs="vp8"'],
        ['webm/vp9', 'video/webm; codecs="vp9"'],
        ['ogg/theora', 'video/ogg; codecs="theora"'],
        ['hevc', 'video/mp4; codecs="hvc1"'],
      ];

    const supported = candidates
      .map(([label, mimeType]) => [label, element.canPlayType(mimeType)])
      .filter(([, result]) => result === 'probably' || result === 'maybe')
      .map(([label, result]) => `${label} (${result})`);

    return supported.length ? supported.join(', ') : 'none supported';
  } catch {
    return 'detection failed';
  }
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

function detectAdBlocker() {
  return new Promise((resolve) => {
    try {
      const bait = document.createElement('div');
      bait.className = 'adsbox ad-banner ads advertisement';
      bait.style.position = 'absolute';
      bait.style.left = '-9999px';
      bait.style.width = '1px';
      bait.style.height = '1px';
      document.body.appendChild(bait);

      setTimeout(() => {
        const style = getComputedStyle(bait);
        const blocked = bait.offsetHeight === 0 || style.display === 'none' || style.visibility === 'hidden';
        document.body.removeChild(bait);
        resolve(blocked ? 'likely blocked (ad blocker detected)' : 'not detected');
      }, 100);
    } catch {
      resolve('detection failed');
    }
  });
}

async function getMediaDeviceCounts() {
  try {
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
      return 'not supported by this browser';
    }
    const devices = await navigator.mediaDevices.enumerateDevices();
    const counts = { audioinput: 0, audiooutput: 0, videoinput: 0 };
    devices.forEach((device) => {
      if (device.kind in counts) counts[device.kind] += 1;
    });
    return `audio input: ${counts.audioinput}, audio output: ${counts.audiooutput}, video input: ${counts.videoinput}`;
  } catch {
    return 'blocked or unsupported';
  }
}

async function getKeyboardLayout() {
  try {
    if (!navigator.keyboard || !navigator.keyboard.getLayoutMap) {
      return 'not supported by this browser';
    }
    const layoutMap = await navigator.keyboard.getLayoutMap();
    const sample = ['KeyY', 'KeyZ', 'KeyQ', 'KeyW'];
    const mapped = sample
      .filter((code) => layoutMap.has(code))
      .map((code) => `${code} → ${layoutMap.get(code)}`);
    return mapped.length ? mapped.join(', ') : 'layout map empty';
  } catch {
    return 'blocked or unsupported';
  }
}

function getWindowChromeVisibility() {
  try {
    const bars = ['locationbar', 'menubar', 'personalbar', 'scrollbars', 'statusbar', 'toolbar'];
    return bars.map((bar) => `${bar}: ${window[bar]?.visible ?? 'unknown'}`).join(', ');
  } catch {
    return 'detection failed';
  }
}

function getBatteryStatus() {
  if (!navigator.getBattery) return Promise.resolve('not supported by this browser');
  return navigator.getBattery()
    .then((battery) => `level: ${Math.round(battery.level * 100)}%, charging: ${battery.charging}`)
    .catch(() => 'blocked or unsupported');
}

async function getPermissionStates() {
  if (!navigator.permissions || !navigator.permissions.query) {
    return 'not supported by this browser';
  }
  const names = ['geolocation', 'notifications', 'camera', 'microphone', 'persistent-storage'];
  const results = await Promise.all(names.map(async (name) => {
    try {
      const status = await navigator.permissions.query({ name });
      return `${name}: ${status.state}`;
    } catch {
      return `${name}: unsupported`;
    }
  }));
  return results.join(', ');
}

function getSensorSupport() {
  try {
    const sensors = ['Accelerometer', 'Gyroscope', 'ProximitySensor', 'Magnetometer'];
    const results = sensors.map((name) => {
      if (!(name in window)) return `${name}: not supported`;
      try {
        new window[name]();
        return `${name}: available`;
      } catch (error) {
        return `${name}: blocked (${error.name || 'error'})`;
      }
    });
    return results.join(', ');
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
    valueCell.append(label);
    let value = null;
    if (!point.renderValue) {
      value = document.createElement('p');
      value.className = 'value';
      value.textContent = 'detecting…';
      valueCell.append(value);
    }

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

    if (point.renderValue) {
      point.renderValue(valueCell);
    } else {
      Promise.resolve(point.getValue())
        .then((result) => { value.textContent = result; })
        .catch(() => { value.textContent = 'error reading value'; });
    }
  });
}

renderCards();
