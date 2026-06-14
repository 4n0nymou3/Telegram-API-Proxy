const URL_PATH_REGEX = /^\/bot(?<bot_token>[^/]+)\/(?<api_method>[a-zA-Z0-9_]+)/i;

const RATE_LIMITS = {
    IP: { max: 100, window: 60000 },
    TOKEN: { max: 200, window: 60000 },
    GLOBAL: { max: 5000, window: 60000 },
    BURST: { max: 10, window: 1000 }
};

const CIRCUIT_BREAKER = {
    FAILURE_THRESHOLD: 5,
    TIMEOUT: 30000,
    HALF_OPEN_MAX_CALLS: 3
};

const RETRY_CONFIG = {
    MAX_RETRIES: 3,
    INITIAL_DELAY: 1000,
    MAX_DELAY: 8000,
    BACKOFF_FACTOR: 2
};

const requestCounters = {
    ip: new Map(),
    token: new Map(),
    burst: new Map(),
    global: { count: 0, resetTime: Date.now() + RATE_LIMITS.GLOBAL.window }
};

const circuitBreakers = new Map();
const tokenValidationCache = new Map();
const suspiciousIPs = new Map();
const CACHE_TTL = 300000;
const CACHE_MAX_SIZE = 1000;
const SUSPICIOUS_THRESHOLD = 10;

const ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
const MAX_BODY_SIZE = 50 * 1024 * 1024;
const ALLOWED_COUNTRIES = ['IR'];
const BLOCKED_COUNTRIES = [];
const ALLOWED_USER_AGENTS = /telegram|bot|curl|postman|httpie|axios|fetch|requests|python|java|go-http|node/i;
const BLOCKED_USER_AGENTS = /scanner|crawler|spider|bot.*attack|sqlmap|nikto|nmap/i;

const TELEGRAM_API_HOST = 'api.telegram.org';

const CACHE_CONFIGS = {
    getChatMember: { ttl: 300, edge: true },
    getMe: { ttl: 3600, edge: true },
    getUpdates: { ttl: 0, edge: false },
    sendMessage: { ttl: 0, edge: false },
    sendPhoto: { ttl: 0, edge: false },
    sendDocument: { ttl: 0, edge: false },
    sendVideo: { ttl: 0, edge: false },
    sendAudio: { ttl: 0, edge: false },
    sendVoice: { ttl: 0, edge: false },
    sendAnimation: { ttl: 0, edge: false },
    sendSticker: { ttl: 0, edge: false },
    sendVideoNote: { ttl: 0, edge: false },
    sendMediaGroup: { ttl: 0, edge: false },
    getChat: { ttl: 600, edge: true },
    getChatAdministrators: { ttl: 1800, edge: true }
};

const MALICIOUS_PATTERNS = [
    /(\.\.\/|\/\.\//|%2e%2e|%252e%252e)/i,
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /vbscript:/gi,
    /onload\s*=/gi,
    /onerror\s*=/gi,
    /eval\s*\(/gi,
    /union\s+select/gi,
    /(\bor\b|\band\b)\s+\d+\s*=\s*\d+/gi
];

const FILE_UPLOAD_METHODS = new Set([
    'sendPhoto', 'sendDocument', 'sendVideo', 'sendAudio',
    'sendVoice', 'sendAnimation', 'sendSticker', 'sendVideoNote',
    'sendMediaGroup', 'setChatPhoto', 'uploadStickerFile',
    'createNewStickerSet', 'addStickerToSet', 'setStickerSetThumb'
]);

let stats = {
    startTime: Date.now(),
    totalRequests: 0,
    successfulRequests: 0,
    failedRequests: 0,
    rateLimited: 0,
    blocked: 0,
    retries: 0,
    avgResponseTime: 0,
    lastReset: Date.now()
};

export default {
    async fetch(request) {
        const { pathname } = new URL(request.url);

        if (pathname === '/') return handleRootRequest(request);
        if (pathname === '/stats') return handleStatsRequest();
        if (pathname === '/favicon.ico') return new Response(null, { status: 204 });
        if (request.method === 'OPTIONS') return handleCorsPreflightRequest();
        if (URL_PATH_REGEX.test(pathname)) return handleProxyRequest(request);

        return handle404Request();
    }
};

function handleStatsRequest() {
    const uptime = Math.floor((Date.now() - stats.startTime) / 1000);
    return new Response(JSON.stringify({
        ok: true,
        uptime,
        totalRequests: stats.totalRequests,
        successfulRequests: stats.successfulRequests,
        failedRequests: stats.failedRequests,
        rateLimited: stats.rateLimited,
        blocked: stats.blocked,
        retries: stats.retries,
        avgLatency: Math.floor(stats.avgResponseTime)
    }), {
        status: 200,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-store'
        }
    });
}

function handleRootRequest(request) {
    const origin = new URL(request.url).origin;
    const apiUrl = origin + '/bot';

    const jsCode = escHtml(
        'const BOT_TOKEN = "YOUR_BOT_TOKEN";\n' +
        'const CHAT_ID = "YOUR_CHAT_ID";\n' +
        'const PROXY_URL = "' + apiUrl + '";\n\n' +
        'async function sendMessage(text) {\n' +
        '    const url = PROXY_URL + BOT_TOKEN + "/sendMessage";\n' +
        '    const res = await fetch(url, {\n' +
        '        method: "POST",\n' +
        '        headers: { "Content-Type": "application/json" },\n' +
        '        body: JSON.stringify({\n' +
        '            chat_id: CHAT_ID,\n' +
        '            text: text,\n' +
        '            parse_mode: "Markdown"\n' +
        '        })\n' +
        '    });\n' +
        '    return res.json();\n' +
        '}\n\n' +
        'sendMessage("Hello from Proxy!").then(console.log);'
    );

    const pythonCode = escHtml(
        'import requests\n\n' +
        'PROXY_URL = "' + apiUrl + '"\n' +
        'BOT_TOKEN = "YOUR_BOT_TOKEN"\n' +
        'CHAT_ID = "YOUR_CHAT_ID"\n\n' +
        'def send_message(text):\n' +
        '    url = f"{PROXY_URL}{BOT_TOKEN}/sendMessage"\n' +
        '    payload = {\n' +
        '        "text": text,\n' +
        '        "chat_id": CHAT_ID,\n' +
        '        "parse_mode": "Markdown",\n' +
        '        "disable_web_page_preview": True\n' +
        '    }\n' +
        '    response = requests.post(url, json=payload)\n' +
        '    return response.json()\n\n' +
        'result = send_message("Hello from Proxy!")\n' +
        'print(result)'
    );

    const nodejsCode = escHtml(
        'const TelegramBot = require("node-telegram-bot-api");\n\n' +
        'const TOKEN = "YOUR_BOT_TOKEN";\n' +
        'const PROXY_URL = "' + apiUrl + '";\n\n' +
        'const bot = new TelegramBot(TOKEN, {\n' +
        '    polling: true,\n' +
        '    baseApiUrl: PROXY_URL.replace("/bot", "")\n' +
        '});\n\n' +
        'bot.onText(/\\/start/, (msg) => {\n' +
        '    bot.sendMessage(msg.chat.id, "Hello via Proxy!");\n' +
        '});'
    );

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Telegram API Proxy</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bg4:#010409;
--border:#30363d;--border2:#21262d;
--text:#e6edf3;--text2:#c9d1d9;--muted:#8b949e;--subtle:#6e7681;
--accent:#58a6ff;--accent2:#1f6feb;
--green:#3fb950;--green2:#238636;
--red:#f85149;--orange:#f78166
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text2);min-height:100vh;padding:32px 16px;font-size:14px;line-height:1.6}
.wrap{max-width:860px;margin:0 auto;animation:fadeUp .4s ease}
@keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.header{text-align:center;padding:40px 24px 32px}
.badge{display:inline-flex;align-items:center;gap:8px;background:rgba(35,134,54,.12);border:1px solid var(--green2);border-radius:2em;padding:5px 14px;margin-bottom:18px;font-size:12px;font-weight:600;color:var(--green)}
.dot{width:8px;height:8px;background:var(--green);border-radius:50%;animation:ping 2s infinite}
@keyframes ping{0%{box-shadow:0 0 0 0 rgba(63,185,80,.5)}70%{box-shadow:0 0 0 7px rgba(63,185,80,0)}100%{box-shadow:0 0 0 0 rgba(63,185,80,0)}}
h1{font-size:26px;font-weight:600;color:var(--text);margin-bottom:6px;letter-spacing:-.3px}
.sub{color:var(--muted);font-size:13px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;margin-bottom:16px;overflow:hidden;transition:border-color .2s}
.card:hover{border-color:#444c56}
.ch{display:flex;align-items:center;gap:8px;padding:14px 20px;border-bottom:1px solid var(--border)}
.ch h2{font-size:13px;font-weight:600;color:var(--text)}
.ch svg{width:15px;height:15px;color:var(--muted);flex-shrink:0;fill:currentColor}
.cb{padding:16px 20px}
.url-box{display:flex;align-items:center;gap:8px;background:var(--bg4);border:1px solid var(--border);border-radius:6px;padding:11px 14px;direction:ltr;text-align:left}
.url-txt{flex:1;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:12px;color:var(--accent);word-break:break-all}
.btn{border:none;border-radius:6px;padding:5px 14px;font-size:12px;font-weight:600;cursor:pointer;transition:background .15s,transform .1s;white-space:nowrap}
.btn-green{background:var(--green2);color:#fff}.btn-green:hover{background:#2ea043}.btn-green.ok{background:var(--accent2)}
.btn-blue{background:var(--accent2);color:#fff;width:100%}.btn-blue:hover{background:#388bfd}
.btn:active{transform:scale(.97)}
.tabs{display:flex;border-bottom:1px solid var(--border);padding:0 20px;gap:0}
.tab{background:none;border:none;padding:10px 16px;font-size:12px;font-weight:500;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;transition:color .15s}
.tab:hover{color:var(--text2)}.tab.on{color:var(--text);border-bottom-color:var(--orange)}
.panel{display:none;direction:ltr;text-align:left}.panel.on{display:block}
.panel pre{margin:0;padding:20px;overflow-x:auto;background:var(--bg) !important;border-radius:0}
.panel code{font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:12px;line-height:1.75;background:none!important;border:none!important;padding:0!important}
.test-out{margin-top:14px;padding:12px 14px;border-radius:6px;font-size:13px;display:none}
.test-out.ok{background:rgba(35,134,54,.12);border:1px solid var(--green2);color:var(--green)}
.test-out.err{background:rgba(248,81,73,.12);border:1px solid var(--red);color:var(--red)}
.spin{display:inline-block;width:12px;height:12px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle;margin-right:6px}
@keyframes spin{to{transform:rotate(360deg)}}
footer{text-align:center;padding:32px 0 16px;color:var(--muted);font-size:12px}
footer a{color:var(--accent);text-decoration:none}
footer a:hover{text-decoration:underline}
@media(max-width:600px){h1{font-size:20px}.url-box{flex-direction:column;align-items:flex-start}.btn-green{width:100%}.panel pre{padding:14px}.tabs{padding:0 12px}}
</style>
</head>
<body>
<div class="wrap">
<div class="header">
<div class="badge"><span class="dot"></span>API Active</div>
<h1>Telegram API Proxy</h1>
<p class="sub">Cloudflare Workers &mdash; Stable Telegram Bot API relay</p>
</div>

<div class="card">
<div class="ch">
<svg viewBox="0 0 16 16"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
<h2>API Endpoint</h2>
</div>
<div class="cb">
<div class="url-box">
<span class="url-txt" id="apiUrl">${apiUrl}</span>
<button class="btn btn-green" id="copyBtn">Copy</button>
</div>
</div>
</div>

<div class="card">
<div class="ch">
<svg viewBox="0 0 16 16"><path d="M14.064 0a8.75 8.75 0 00-6.187 2.563l-.459.458c-.314.314-.616.641-.904.979H3.31a1.75 1.75 0 00-1.49.833L.11 7.607a.75.75 0 00.418 1.11l3.102.954c.086.283.186.565.299.843l-1.3 1.3a1.75 1.75 0 000 2.474L3.89 15.44a1.75 1.75 0 002.475 0l1.3-1.3c.278.113.56.213.843.299l.954 3.102a.75.75 0 001.11.418l2.773-1.71a1.75 1.75 0 00.833-1.49v-3.164c.338-.288.665-.59.979-.904l.458-.459A8.75 8.75 0 0016 1.936V1.75A1.75 1.75 0 0014.25 0h-.186zM10.5 10c-.282 0-.553-.087-.776-.246l-1.177 1.176a.75.75 0 01-1.06 0l-1.415-1.414a.75.75 0 010-1.06l1.176-1.177A1.5 1.5 0 1110.5 10z"/></svg>
<h2>Code Examples</h2>
</div>
<div class="tabs">
<button class="tab on" data-tab="js">JavaScript</button>
<button class="tab" data-tab="py">Python</button>
<button class="tab" data-tab="node">Node.js</button>
</div>
<div class="panel on" id="p-js"><pre><code class="language-javascript">${jsCode}</code></pre></div>
<div class="panel" id="p-py"><pre><code class="language-python">${pythonCode}</code></pre></div>
<div class="panel" id="p-node"><pre><code class="language-javascript">${nodejsCode}</code></pre></div>
</div>

<div class="card">
<div class="ch">
<svg viewBox="0 0 16 16"><path d="M8 0a8 8 0 100 16A8 8 0 008 0zm3.71 5.81L6.89 10.6a.75.75 0 01-.54.24.75.75 0 01-.54-.24L4.3 9.07a.75.75 0 011.08-1.05l1.02 1.04 4.29-4.3a.75.75 0 011.06 1.05z"/></svg>
<h2>Connection Test</h2>
</div>
<div class="cb">
<button class="btn btn-blue" id="testBtn">Test API Connection</button>
<div class="test-out" id="testOut"></div>
</div>
</div>

<footer>
<p>Powered by Cloudflare Workers &nbsp;&middot;&nbsp; Created by <a href="https://t.me/BXAMbot" target="_blank">Anonymous</a></p>
</footer>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<script>
document.addEventListener('DOMContentLoaded', function() {
    hljs.highlightAll();

    document.getElementById('copyBtn').addEventListener('click', function() {
        const text = document.getElementById('apiUrl').textContent;
        const btn = this;
        const copy = function() {
            btn.textContent = 'Copied!';
            btn.classList.add('ok');
            setTimeout(function() { btn.textContent = 'Copy'; btn.classList.remove('ok'); }, 2000);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(copy);
        } else {
            const el = document.createElement('textarea');
            el.value = text;
            el.style.position = 'fixed';
            el.style.opacity = '0';
            document.body.appendChild(el);
            el.select();
            document.execCommand('copy');
            document.body.removeChild(el);
            copy();
        }
    });

    document.querySelectorAll('.tab').forEach(function(tab) {
        tab.addEventListener('click', function() {
            document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('on'); });
            document.querySelectorAll('.panel').forEach(function(p) { p.classList.remove('on'); });
            this.classList.add('on');
            document.getElementById('p-' + this.dataset.tab).classList.add('on');
        });
    });

    document.getElementById('testBtn').addEventListener('click', async function() {
        const btn = this;
        const out = document.getElementById('testOut');
        btn.innerHTML = '<span class="spin"></span>Testing...';
        btn.disabled = true;
        out.style.display = 'none';
        try {
            const t = Date.now();
            const res = await fetch('/stats');
            const latency = Date.now() - t;
            const data = await res.json();
            if (data.ok) {
                out.className = 'test-out ok';
                out.textContent = 'Connection successful — Ping: ' + latency + 'ms  |  Avg API latency: ' + data.avgLatency + 'ms  |  Total requests: ' + data.totalRequests;
            } else {
                throw new Error('not ok');
            }
        } catch(e) {
            out.className = 'test-out err';
            out.textContent = 'Connection failed. Check if the Worker is deployed correctly.';
        }
        out.style.display = 'block';
        btn.textContent = 'Test API Connection';
        btn.disabled = false;
    });
});
</script>
</body>
</html>`;

    return new Response(html, {
        status: 200,
        headers: {
            'Content-Type': 'text/html;charset=UTF-8',
            'Cache-Control': 'no-cache'
        }
    });
}

function escHtml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function handle404Request() {
    return new Response(JSON.stringify({
        ok: false,
        error_code: 404,
        description: 'Invalid endpoint. Use /bot{TOKEN}/{METHOD} format.'
    }), {
        status: 404,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
}

async function handleProxyRequest(request) {
    const startTime = Date.now();
    try {
        await cleanupExpiredData();

        const securityCheck = await performSecurityChecks(request);
        if (securityCheck.blocked) {
            stats.blocked++;
            return createErrorResponse(securityCheck.reason, securityCheck.status);
        }

        const requestInfo = parseRequest(request);
        if (!requestInfo.valid) {
            stats.blocked++;
            return createErrorResponse('Invalid request format', 400);
        }

        const circuitState = checkCircuitBreaker(requestInfo.clientIP);
        if (circuitState === 'OPEN') {
            return createErrorResponse('Service temporarily unavailable', 503);
        }

        const rateLimitResult = checkRateLimit(requestInfo.clientIP, requestInfo.botToken);
        if (rateLimitResult.limited) {
            stats.rateLimited++;
            return createRateLimitResponse(rateLimitResult.retryAfter);
        }

        if (!validateBotToken(requestInfo.botToken)) {
            await recordSuspiciousActivity(requestInfo.clientIP, 'invalid_token');
            stats.blocked++;
            return createErrorResponse('Invalid bot token', 401);
        }

        const response = await proxyWithRetry(request, requestInfo);

        updateCircuitBreaker(requestInfo.clientIP, response.ok);
        updateStats(startTime, response.ok);

        return response;

    } catch (error) {
        console.error('Proxy error:', error);
        stats.failedRequests++;
        updateCircuitBreaker(getClientIP(request), false);
        return handleProxyError(error);
    }
}

async function cleanupExpiredData() {
    const now = Date.now();

    for (const [token, data] of tokenValidationCache.entries()) {
        if (now >= data.expires) tokenValidationCache.delete(token);
    }

    for (const [ip, data] of suspiciousIPs.entries()) {
        if (now >= data.expires) suspiciousIPs.delete(ip);
    }

    for (const [, breaker] of circuitBreakers.entries()) {
        if (breaker.state !== 'CLOSED' && now - breaker.lastFailureTime > CIRCUIT_BREAKER.TIMEOUT) {
            breaker.state = 'CLOSED';
            breaker.failureCount = 0;
        }
    }

    if (now - stats.lastReset > 3600000) {
        stats.totalRequests = 0;
        stats.successfulRequests = 0;
        stats.failedRequests = 0;
        stats.rateLimited = 0;
        stats.blocked = 0;
        stats.retries = 0;
        stats.lastReset = now;
        stats.avgResponseTime = 0;
    }
}

async function performSecurityChecks(request) {
    const clientIP = getClientIP(request);
    const userAgent = request.headers.get('user-agent') || '';
    const country = request.headers.get('cf-ipcountry');
    const referer = request.headers.get('referer') || '';
    const contentType = request.headers.get('content-type') || '';

    if (!ALLOWED_METHODS.includes(request.method)) {
        return { blocked: true, reason: 'Method not allowed', status: 405 };
    }

    const contentLength = request.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > MAX_BODY_SIZE) {
        return { blocked: true, reason: 'Request too large', status: 413 };
    }

    if (ALLOWED_COUNTRIES.length > 0 && !ALLOWED_COUNTRIES.includes(country)) {
        return { blocked: true, reason: 'Geographic restriction', status: 403 };
    }

    if (BLOCKED_COUNTRIES.length > 0 && BLOCKED_COUNTRIES.includes(country)) {
        return { blocked: true, reason: 'Geographic restriction', status: 403 };
    }

    if (BLOCKED_USER_AGENTS.test(userAgent)) {
        await recordSuspiciousActivity(clientIP, 'blocked_user_agent');
        return { blocked: true, reason: 'Blocked user agent', status: 403 };
    }

    if (!ALLOWED_USER_AGENTS.test(userAgent) && userAgent.length < 10) {
        await recordSuspiciousActivity(clientIP, 'suspicious_user_agent');
        return { blocked: true, reason: 'Invalid user agent', status: 403 };
    }

    const suspicious = suspiciousIPs.get(clientIP);
    if (suspicious && suspicious.count >= SUSPICIOUS_THRESHOLD) {
        return { blocked: true, reason: 'IP temporarily blocked', status: 429 };
    }

    const url = new URL(request.url);
    const fullPath = url.pathname + url.search;

    for (const pattern of MALICIOUS_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(fullPath) || pattern.test(referer)) {
            await recordSuspiciousActivity(clientIP, 'malicious_pattern');
            return { blocked: true, reason: 'Malicious request detected', status: 400 };
        }
    }

    if (request.method === 'POST' && contentType.includes('multipart/form-data')) {
        const boundaryMatch = contentType.match(/boundary=([^;]+)/);
        if (boundaryMatch && boundaryMatch[1].length > 200) {
            return { blocked: true, reason: 'Invalid multipart boundary', status: 400 };
        }
    }

    const xff = request.headers.get('x-forwarded-for');
    if (xff && xff.split(',').length > 10) {
        await recordSuspiciousActivity(clientIP, 'excessive_forwarded_headers');
        return { blocked: true, reason: 'Suspicious request headers', status: 400 };
    }

    return { blocked: false };
}

async function recordSuspiciousActivity(ip, type) {
    const now = Date.now();
    const existing = suspiciousIPs.get(ip) || { count: 0, types: new Set(), expires: now + 3600000 };
    existing.count++;
    existing.types.add(type);
    existing.lastActivity = now;
    suspiciousIPs.set(ip, existing);
}

function parseRequest(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const clientIP = getClientIP(request);

    if (!URL_PATH_REGEX.test(path)) return { valid: false };

    const match = path.match(URL_PATH_REGEX);
    const botToken = match?.groups?.bot_token || '';
    const apiMethod = match?.groups?.api_method || '';

    if (botToken.length > 200 || apiMethod.length > 50) return { valid: false };

    return { valid: true, clientIP, botToken, apiMethod, path };
}

function getClientIP(request) {
    const cfIP = request.headers.get('cf-connecting-ip');
    if (cfIP) return cfIP;

    const xff = request.headers.get('x-forwarded-for');
    if (xff) {
        const first = xff.split(',')[0]?.trim();
        if (first && /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(first)) return first;
    }

    return request.headers.get('x-real-ip') || 'unknown';
}

function checkRateLimit(clientIP, botToken) {
    const now = Date.now();
    cleanupCounters(now);

    if (requestCounters.global.count >= RATE_LIMITS.GLOBAL.max) {
        return { limited: true, retryAfter: Math.ceil((requestCounters.global.resetTime - now) / 1000) };
    }

    const bKey = 'b_' + clientIP;
    if (getCount(requestCounters.burst, bKey, now, RATE_LIMITS.BURST.window) >= RATE_LIMITS.BURST.max) {
        return { limited: true, retryAfter: 1 };
    }

    const iKey = 'i_' + clientIP;
    if (getCount(requestCounters.ip, iKey, now, RATE_LIMITS.IP.window) >= RATE_LIMITS.IP.max) {
        return { limited: true, retryAfter: 60 };
    }

    const tKey = 't_' + botToken;
    if (getCount(requestCounters.token, tKey, now, RATE_LIMITS.TOKEN.window) >= RATE_LIMITS.TOKEN.max) {
        return { limited: true, retryAfter: 60 };
    }

    incCount(requestCounters.burst, bKey, now, RATE_LIMITS.BURST.window);
    incCount(requestCounters.ip, iKey, now, RATE_LIMITS.IP.window);
    incCount(requestCounters.token, tKey, now, RATE_LIMITS.TOKEN.window);
    requestCounters.global.count++;

    return { limited: false };
}

function cleanupCounters(now) {
    if (now >= requestCounters.global.resetTime) {
        requestCounters.global.count = 0;
        requestCounters.global.resetTime = now + RATE_LIMITS.GLOBAL.window;
    }
    for (const map of [requestCounters.ip, requestCounters.token, requestCounters.burst]) {
        for (const [key, data] of map.entries()) {
            if (now >= data.resetTime) map.delete(key);
        }
    }
}

function getCount(map, key, now, win) {
    const d = map.get(key);
    return (!d || now >= d.resetTime) ? 0 : d.count;
}

function incCount(map, key, now, win) {
    const e = map.get(key);
    if (!e || now >= e.resetTime) map.set(key, { count: 1, resetTime: now + win });
    else e.count++;
}

function checkCircuitBreaker(clientIP) {
    const b = circuitBreakers.get(clientIP);
    if (!b) return 'CLOSED';

    const now = Date.now();

    if (b.state === 'OPEN') {
        if (now - b.lastFailureTime >= CIRCUIT_BREAKER.TIMEOUT) {
            b.state = 'HALF_OPEN';
            b.halfOpenAttempts = 0;
            return 'HALF_OPEN';
        }
        return 'OPEN';
    }

    if (b.state === 'HALF_OPEN') {
        if (b.halfOpenAttempts >= CIRCUIT_BREAKER.HALF_OPEN_MAX_CALLS) return 'OPEN';
        b.halfOpenAttempts++;
    }

    return b.state;
}

function updateCircuitBreaker(clientIP, success) {
    let b = circuitBreakers.get(clientIP);
    if (!b) {
        b = { state: 'CLOSED', failureCount: 0, lastFailureTime: 0, halfOpenAttempts: 0 };
        circuitBreakers.set(clientIP, b);
    }

    if (success) {
        if (b.state === 'HALF_OPEN') { b.state = 'CLOSED'; b.failureCount = 0; }
        else if (b.state === 'CLOSED') b.failureCount = Math.max(0, b.failureCount - 1);
    } else {
        b.failureCount++;
        b.lastFailureTime = Date.now();
        if (b.failureCount >= CIRCUIT_BREAKER.FAILURE_THRESHOLD) b.state = 'OPEN';
    }
}

function validateBotToken(token) {
    const cached = tokenValidationCache.get(token);
    if (cached && Date.now() < cached.expires) return cached.valid;

    if (tokenValidationCache.size >= CACHE_MAX_SIZE) {
        tokenValidationCache.delete(tokenValidationCache.keys().next().value);
    }

    let valid = false;

    if (token && token.length >= 35 && token.length <= 200 && token.includes(':')) {
        const [botId, botHash] = token.split(':');
        valid = !!(
            botId && botHash &&
            botId.length >= 5 && botHash.length >= 25 &&
            /^\d+$/.test(botId) && /^[A-Za-z0-9_-]+$/.test(botHash)
        );
    }

    tokenValidationCache.set(token, { valid, expires: Date.now() + CACHE_TTL });
    return valid;
}

async function proxyWithRetry(request, requestInfo) {
    let lastError;

    for (let attempt = 0; attempt <= RETRY_CONFIG.MAX_RETRIES; attempt++) {
        try {
            if (attempt > 0) {
                stats.retries++;
                const delay = Math.min(
                    RETRY_CONFIG.INITIAL_DELAY * Math.pow(RETRY_CONFIG.BACKOFF_FACTOR, attempt - 1),
                    RETRY_CONFIG.MAX_DELAY
                );
                await new Promise(r => setTimeout(r, delay));
            }

            const response = await proxyToTelegram(request, requestInfo);

            if (response.ok || response.status < 500) return response;

            lastError = new Error('HTTP ' + response.status);

        } catch (error) {
            lastError = error;
            if (error.name === 'AbortError') continue;
            if (attempt === RETRY_CONFIG.MAX_RETRIES) throw error;
        }
    }

    throw lastError || new Error('Max retries exceeded');
}

async function proxyToTelegram(request, requestInfo) {
    const { apiMethod, path } = requestInfo;

    const newUrl = new URL(request.url);
    newUrl.hostname = TELEGRAM_API_HOST;
    newUrl.port = '';
    newUrl.pathname = path;

    const requestHeaders = new Headers(request.headers);
    sanitizeHeaders(requestHeaders);
    requestHeaders.set('Connection', 'keep-alive');
    requestHeaders.set('User-Agent', 'Cloudflare-Worker-Proxy/2.0');
    requestHeaders.set('Cache-Control', 'no-cache');

    let requestBody;
    const contentType = request.headers.get('content-type') || '';

    if (request.method !== 'GET' && request.method !== 'HEAD') {
        try {
            if (contentType.includes('multipart/form-data') || FILE_UPLOAD_METHODS.has(apiMethod)) {
                requestBody = await request.formData();
                requestHeaders.delete('content-type');
            } else {
                requestBody = await request.arrayBuffer();
                if (request.method === 'POST' && !contentType) {
                    requestHeaders.set('Content-Type', 'application/json');
                } else if (contentType) {
                    requestHeaders.set('Content-Type', contentType);
                }
            }
        } catch {
            throw new Error('Failed to read request body');
        }
    }

    const controller = new AbortController();
    const isUpload = FILE_UPLOAD_METHODS.has(apiMethod);
    const timeout = setTimeout(() => controller.abort(), isUpload ? 120000 : 30000);

    try {
        const cacheConfig = CACHE_CONFIGS[apiMethod] || { ttl: 0, edge: false };

        const response = await fetch(new Request(newUrl.toString(), {
            method: request.method,
            headers: requestHeaders,
            body: requestBody,
            redirect: 'follow',
            signal: controller.signal
        }), {
            cf: {
                cacheTtl: cacheConfig.ttl,
                cacheEverything: cacheConfig.edge && request.method === 'GET',
                polish: 'off',
                minify: { javascript: false, css: false, html: false },
                timeout: isUpload ? 100000 : 25000
            }
        });

        if (!response.ok && response.status >= 500) {
            throw new Error('Server error: ' + response.status);
        }

        const responseHeaders = new Headers(response.headers);
        addSecurityHeaders(responseHeaders);

        return new Response(await response.arrayBuffer(), {
            status: response.status,
            statusText: response.statusText,
            headers: getCorsHeaders(responseHeaders)
        });

    } finally {
        clearTimeout(timeout);
    }
}

function sanitizeHeaders(headers) {
    const toDelete = [];
    for (const [key] of headers) {
        const lower = key.toLowerCase();
        if (
            lower === 'host' || lower === 'origin' || lower === 'referer' ||
            lower === 'cookie' || lower === 'authorization' ||
            lower.startsWith('cf-') || lower.startsWith('x-') ||
            lower.startsWith('sec-') || lower.includes('proxy')
        ) {
            toDelete.push(key);
        }
    }
    toDelete.forEach(k => headers.delete(k));
    return headers;
}

function addSecurityHeaders(headers) {
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-Frame-Options', 'DENY');
    headers.set('X-XSS-Protection', '1; mode=block');
    headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    headers.set('Content-Security-Policy', "default-src 'none'; script-src 'none'; object-src 'none'");
    headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    headers.set('X-Permitted-Cross-Domain-Policies', 'none');
    headers.set('X-Download-Options', 'noopen');
    headers.set('X-DNS-Prefetch-Control', 'off');
    headers.set('Permissions-Policy', "geolocation=(), microphone=(), camera=()");
}

function getCorsHeaders(headers) {
    const h = new Headers(headers || {});
    h.set('Access-Control-Allow-Origin', '*');
    h.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    h.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    h.set('Access-Control-Expose-Headers', 'X-RateLimit-Remaining, X-RateLimit-Reset');
    h.set('Access-Control-Max-Age', '86400');
    h.set('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers');
    return h;
}

function handleCorsPreflightRequest() {
    return new Response(null, { status: 204, headers: getCorsHeaders() });
}

function createErrorResponse(message, status) {
    if (!status) status = 400;
    const headers = getCorsHeaders();
    headers.set('Content-Type', 'application/json');
    headers.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    return new Response(JSON.stringify({
        ok: false,
        error: message,
        error_code: status,
        timestamp: new Date().toISOString(),
        request_id: generateId()
    }), { status, headers });
}

function createRateLimitResponse(retryAfter) {
    const headers = getCorsHeaders();
    headers.set('Content-Type', 'application/json');
    headers.set('Retry-After', retryAfter.toString());
    headers.set('X-RateLimit-Remaining', '0');
    headers.set('X-RateLimit-Reset', (Date.now() + retryAfter * 1000).toString());
    headers.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    return new Response(JSON.stringify({
        ok: false,
        error: 'Rate limit exceeded. Please try again later.',
        retry_after: retryAfter,
        timestamp: new Date().toISOString(),
        request_id: generateId()
    }), { status: 429, headers });
}

function handleProxyError(error) {
    const msg = error.message || 'Unknown error';
    const isTimeout = error.name === 'AbortError' || msg.includes('timeout');
    const headers = getCorsHeaders();
    headers.set('Content-Type', 'application/json');
    return new Response(JSON.stringify({
        ok: false,
        error: isTimeout ? 'Gateway timeout' : 'Proxy service temporarily unavailable',
        details: msg.substring(0, 200),
        timestamp: new Date().toISOString(),
        request_id: generateId()
    }), { status: isTimeout ? 504 : 500, headers });
}

function updateStats(startTime, success) {
    const responseTime = Date.now() - startTime;
    stats.totalRequests++;
    if (success) stats.successfulRequests++;
    else stats.failedRequests++;
    stats.avgResponseTime = stats.totalRequests === 1
        ? responseTime
        : ((stats.avgResponseTime * (stats.totalRequests - 1)) + responseTime) / stats.totalRequests;
}

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substring(2, 7);
}