const URL_PATH_REGEX = /^\/bot(?<bot_token>[^/]+)\/(?<api_method>[a-zA-Z0-9_]+)/i;

const RATE_LIMITS = {
    IP:     { max: 100,  window: 60000 },
    TOKEN:  { max: 200,  window: 60000 },
    GLOBAL: { max: 5000, window: 60000 },
    BURST:  { max: 10,   window: 1000  }
};

const CIRCUIT_BREAKER = {
    FAILURE_THRESHOLD:   5,
    TIMEOUT:             30000,
    HALF_OPEN_MAX_CALLS: 3
};

const RETRY_CONFIG = {
    MAX_RETRIES:    3,
    INITIAL_DELAY:  1000,
    MAX_DELAY:      8000,
    BACKOFF_FACTOR: 2
};

const requestCounters = {
    ip:     new Map(),
    token:  new Map(),
    burst:  new Map(),
    global: { count: 0, resetTime: Date.now() + RATE_LIMITS.GLOBAL.window }
};

const circuitBreakers      = new Map();
const tokenValidationCache = new Map();
const suspiciousIPs        = new Map();

const CACHE_TTL            = 300000;
const CACHE_MAX_SIZE       = 1000;
const SUSPICIOUS_THRESHOLD = 10;

const ALLOWED_METHODS   = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
const MAX_BODY_SIZE     = 50 * 1024 * 1024;
const ALLOWED_COUNTRIES = [];
const BLOCKED_COUNTRIES = [];

const ALLOWED_USER_AGENTS = /telegram|bot|curl|postman|httpie|axios|fetch|requests|python|java|go-http|node/i;
const BLOCKED_USER_AGENTS = /scanner|crawler|spider|bot.*attack|sqlmap|nikto|nmap/i;

const TELEGRAM_API_HOST = 'api.telegram.org';

const CACHE_CONFIGS = {
    getChatMember:         { ttl: 300,  edge: true  },
    getMe:                 { ttl: 3600, edge: true  },
    getUpdates:            { ttl: 0,    edge: false },
    sendMessage:           { ttl: 0,    edge: false },
    sendPhoto:             { ttl: 0,    edge: false },
    sendDocument:          { ttl: 0,    edge: false },
    sendVideo:             { ttl: 0,    edge: false },
    sendAudio:             { ttl: 0,    edge: false },
    sendVoice:             { ttl: 0,    edge: false },
    sendAnimation:         { ttl: 0,    edge: false },
    sendSticker:           { ttl: 0,    edge: false },
    sendVideoNote:         { ttl: 0,    edge: false },
    sendMediaGroup:        { ttl: 0,    edge: false },
    getChat:               { ttl: 600,  edge: true  },
    getChatAdministrators: { ttl: 1800, edge: true  }
};

const MALICIOUS_PATTERNS = [
    /(\.\.\/|\/\.\/|%2e%2e|%252e%252e)/i,
    /<script[^>]*>[\s\S]*?<\/script>/gi,
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
    startTime:          Date.now(),
    totalRequests:      0,
    successfulRequests: 0,
    failedRequests:     0,
    rateLimited:        0,
    blocked:            0,
    retries:            0,
    avgResponseTime:    0,
    lastReset:          Date.now()
};

export default {
    async fetch(request) {
        const { pathname } = new URL(request.url);

        if (pathname === '/')             return handleRootRequest(request);
        if (pathname === '/stats')        return handleStatsRequest();
        if (pathname === '/favicon.ico')  return new Response(null, { status: 204 });
        if (request.method === 'OPTIONS') return handleCorsPreflightRequest();
        if (URL_PATH_REGEX.test(pathname)) return handleProxyRequest(request);

        return handle404Request();
    }
};

function escHtml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function handleRootRequest(request) {
    const origin = new URL(request.url).origin;
    const apiUrl = origin + '/bot';

    const jsCode = escHtml([
        'const BOT_TOKEN = "YOUR_BOT_TOKEN";',
        'const CHAT_ID   = "YOUR_CHAT_ID";',
        'const PROXY_URL = "' + apiUrl + '";',
        '',
        'async function sendMessage(text) {',
        '    const url = PROXY_URL + BOT_TOKEN + "/sendMessage";',
        '    const response = await fetch(url, {',
        '        method: "POST",',
        '        headers: { "Content-Type": "application/json" },',
        '        body: JSON.stringify({',
        '            chat_id: CHAT_ID,',
        '            text: text,',
        '            parse_mode: "Markdown"',
        '        })',
        '    });',
        '    return response.json();',
        '}',
        '',
        'sendMessage("Hello from Proxy!").then(console.log);'
    ].join('\n'));

    const pyCode = escHtml([
        'import requests',
        '',
        'PROXY_URL = "' + apiUrl + '"',
        'BOT_TOKEN = "YOUR_BOT_TOKEN"',
        'CHAT_ID   = "YOUR_CHAT_ID"',
        '',
        'def send_message(text):',
        '    url = PROXY_URL + BOT_TOKEN + "/sendMessage"',
        '    payload = {',
        '        "text": text,',
        '        "chat_id": CHAT_ID,',
        '        "parse_mode": "Markdown",',
        '        "disable_web_page_preview": True',
        '    }',
        '    response = requests.post(url, json=payload)',
        '    return response.json()',
        '',
        'result = send_message("Hello from Proxy!")',
        'print(result)'
    ].join('\n'));

    const nodeCode = escHtml([
        'const TelegramBot = require("node-telegram-bot-api");',
        '',
        'const TOKEN     = "YOUR_BOT_TOKEN";',
        'const PROXY_URL = "' + apiUrl + '";',
        '',
        'const bot = new TelegramBot(TOKEN, {',
        '    polling: true,',
        '    baseApiUrl: PROXY_URL.replace("/bot", "")',
        '});',
        '',
        'bot.on("message", function (msg) {',
        '    bot.sendMessage(msg.chat.id, "Echo: " + msg.text);',
        '});'
    ].join('\n'));

    const aiogramCode = escHtml([
        'import asyncio',
        'from aiogram import Bot, Dispatcher, types',
        'from aiogram.client.session.aiohttp import AiohttpSession',
        '',
        'PROXY_URL = "' + apiUrl + '"',
        'BOT_TOKEN = "YOUR_BOT_TOKEN"',
        '',
        'session = AiohttpSession(api=PROXY_URL.replace("/bot", ""))',
        'bot = Bot(token=BOT_TOKEN, session=session)',
        'dp  = Dispatcher()',
        '',
        '@dp.message()',
        'async def echo(message: types.Message):',
        '    await message.answer("Echo: " + message.text)',
        '',
        'async def main():',
        '    await dp.start_polling(bot)',
        '',
        'asyncio.run(main())'
    ].join('\n'));

    const html = '<!DOCTYPE html>\n' +
'<html lang="en">\n' +
'<head>\n' +
'<meta charset="UTF-8">\n' +
'<meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
'<title>Telegram API Proxy</title>\n' +
'<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">\n' +
'<style>\n' +
'*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}\n' +
':root{\n' +
'--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bg4:#010409;\n' +
'--border:#30363d;--text:#e6edf3;--text2:#c9d1d9;\n' +
'--muted:#8b949e;--accent:#58a6ff;--accent2:#1f6feb;\n' +
'--green:#3fb950;--green2:#238636;--red:#f85149;--orange:#f78166\n' +
'}\n' +
'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text2);min-height:100vh;padding:40px 16px;font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased}\n' +
'.wrap{max-width:860px;margin:0 auto;animation:fadeUp .4s ease}\n' +
'@keyframes fadeUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}\n' +
'.header{text-align:center;padding:48px 24px 36px}\n' +
'.badge{display:inline-flex;align-items:center;gap:8px;background:rgba(35,134,54,.12);border:1px solid var(--green2);border-radius:2em;padding:5px 16px;margin-bottom:20px;font-size:12px;font-weight:600;color:var(--green)}\n' +
'.dot{width:8px;height:8px;background:var(--green);border-radius:50%;animation:ping 2s infinite;flex-shrink:0}\n' +
'@keyframes ping{0%{box-shadow:0 0 0 0 rgba(63,185,80,.5)}70%{box-shadow:0 0 0 8px rgba(63,185,80,0)}100%{box-shadow:0 0 0 0 rgba(63,185,80,0)}}\n' +
'h1{font-size:26px;font-weight:600;color:var(--text);margin-bottom:8px;letter-spacing:-.3px}\n' +
'.sub{color:var(--muted);font-size:13px}\n' +
'.card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;margin-bottom:16px;overflow:hidden;transition:border-color .2s}\n' +
'.card:hover{border-color:#444c56}\n' +
'.ch{display:flex;align-items:center;gap:8px;padding:14px 20px;border-bottom:1px solid var(--border)}\n' +
'.ch h2{font-size:13px;font-weight:600;color:var(--text);margin:0}\n' +
'.ch svg{width:15px;height:15px;color:var(--muted);fill:currentColor;flex-shrink:0}\n' +
'.cb{padding:18px 20px}\n' +
'.url-box{display:flex;align-items:center;gap:10px;background:var(--bg4);border:1px solid var(--border);border-radius:6px;padding:12px 14px;direction:ltr;text-align:left;margin-bottom:12px}\n' +
'.url-txt{flex:1;font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;font-size:12px;color:var(--accent);word-break:break-all;user-select:all}\n' +
'.hint{font-size:12px;color:var(--muted);line-height:1.7}\n' +
'.hint code{font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;background:var(--bg3);border:1px solid var(--border);border-radius:3px;padding:1px 5px;color:var(--text2);font-size:11px}\n' +
'.btn{border:none;border-radius:6px;padding:5px 14px;font-size:12px;font-weight:600;cursor:pointer;transition:background .15s,transform .1s;white-space:nowrap;font-family:inherit}\n' +
'.btn:active{transform:scale(.97)}\n' +
'.btn-g{background:var(--green2);color:#fff}.btn-g:hover{background:#2ea043}.btn-g.ok{background:var(--accent2)}\n' +
'.btn-b{background:var(--accent2);color:#fff}.btn-b:hover{background:#388bfd}\n' +
'.btn-full{width:100%;padding:10px 14px;font-size:13px}\n' +
'.tabs{display:flex;border-bottom:1px solid var(--border);padding:0 20px}\n' +
'.tab{background:none;border:none;padding:10px 14px;font-size:12px;font-weight:500;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;transition:color .15s;font-family:inherit}\n' +
'.tab:hover{color:var(--text2)}.tab.on{color:var(--text);border-bottom-color:var(--orange)}\n' +
'.panel{display:none;direction:ltr;text-align:left}.panel.on{display:block}\n' +
'.panel pre{margin:0;padding:20px;overflow-x:auto;background:var(--bg)!important;border-radius:0;line-height:1.75}\n' +
'.panel code{font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;font-size:12px;background:none!important;border:none!important;padding:0!important;border-radius:0!important}\n' +
'.test-out{margin-top:14px;padding:12px 14px;border-radius:6px;font-size:13px;display:none;line-height:1.6}\n' +
'.test-out.ok{background:rgba(35,134,54,.12);border:1px solid var(--green2);color:var(--green)}\n' +
'.test-out.err{background:rgba(248,81,73,.12);border:1px solid var(--red);color:var(--red)}\n' +
'.spin{display:inline-block;width:12px;height:12px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle;margin-right:6px}\n' +
'@keyframes spin{to{transform:rotate(360deg)}}\n' +
'.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:14px}\n' +
'.stat-box{background:var(--bg4);border:1px solid var(--border);border-radius:6px;padding:14px;text-align:center}\n' +
'.stat-num{font-size:22px;font-weight:700;color:var(--text);font-variant-numeric:tabular-nums}\n' +
'.stat-lbl{font-size:11px;color:var(--muted);margin-top:3px}\n' +
'.features{display:grid;grid-template-columns:1fr 1fr;gap:10px 24px;padding:18px 20px}\n' +
'.feature{display:flex;align-items:flex-start;gap:8px;font-size:13px;color:var(--text2)}\n' +
'.check{color:var(--green);font-weight:700;font-size:12px;margin-top:1px;flex-shrink:0}\n' +
'footer{text-align:center;padding:32px 0 20px;border-top:1px solid var(--border);margin-top:8px;color:var(--muted);font-size:12px}\n' +
'footer strong{color:var(--text2)}\n' +
'@media(max-width:640px){\n' +
'body{padding:20px 12px}\n' +
'h1{font-size:20px}\n' +
'.header{padding:32px 16px 24px}\n' +
'.url-box{flex-direction:column;align-items:stretch}\n' +
'.btn-g{width:100%;text-align:center}\n' +
'.tabs{padding:0 12px;overflow-x:auto}\n' +
'.panel pre{padding:14px}\n' +
'.stats-row{grid-template-columns:repeat(2,1fr)}\n' +
'.features{grid-template-columns:1fr}\n' +
'.cb{padding:14px 16px}\n' +
'.ch{padding:12px 16px}\n' +
'}\n' +
'</style>\n' +
'</head>\n' +
'<body>\n' +
'<div class="wrap">\n' +
'\n' +
'<div class="header">\n' +
'  <div class="badge"><span class="dot"></span>Worker Active</div>\n' +
'  <h1>Telegram API Proxy</h1>\n' +
'  <p class="sub">Cloudflare Worker &mdash; Stable Telegram Bot API Relay</p>\n' +
'</div>\n' +
'\n' +
'<div class="card">\n' +
'  <div class="ch">\n' +
'    <svg viewBox="0 0 16 16"><path d="M1.5 1a.5.5 0 00-.5.5v4a.5.5 0 01-1 0v-4A1.5 1.5 0 011.5 0h4a.5.5 0 010 1zM10 .5a.5.5 0 01.5-.5h4A1.5 1.5 0 0116 1.5v4a.5.5 0 01-1 0v-4a.5.5 0 00-.5-.5h-4a.5.5 0 01-.5-.5zM.5 10a.5.5 0 01.5.5v4a.5.5 0 00.5.5h4a.5.5 0 010 1h-4A1.5 1.5 0 010 14.5v-4a.5.5 0 01.5-.5zm15 0a.5.5 0 01.5.5v4a1.5 1.5 0 01-1.5 1.5h-4a.5.5 0 010-1h4a.5.5 0 00.5-.5v-4a.5.5 0 01.5-.5z"/></svg>\n' +
'    <h2>API Endpoint</h2>\n' +
'  </div>\n' +
'  <div class="cb">\n' +
'    <div class="url-box">\n' +
'      <span class="url-txt">' + apiUrl + '</span>\n' +
'      <button class="btn btn-g" id="copyBtn">Copy</button>\n' +
'    </div>\n' +
'    <p class="hint">Replace <code>https://api.telegram.org</code> with the URL above in your bot code.</p>\n' +
'  </div>\n' +
'</div>\n' +
'\n' +
'<div class="card">\n' +
'  <div class="ch">\n' +
'    <svg viewBox="0 0 16 16"><path d="M0 1.75C0 .784.784 0 1.75 0h12.5C15.216 0 16 .784 16 1.75v9.5A1.75 1.75 0 0114.25 13H8.06l-2.573 2.573A1.457 1.457 0 013 14.543V13H1.75A1.75 1.75 0 010 11.25Zm1.75-.25a.25.25 0 00-.25.25v9.5c0 .138.112.25.25.25h2a.75.75 0 01.75.75v2.189l2.72-2.719a.749.749 0 01.53-.22h6.5a.25.25 0 00.25-.25v-9.5a.25.25 0 00-.25-.25Z"/></svg>\n' +
'    <h2>Code Examples</h2>\n' +
'  </div>\n' +
'  <div class="tabs">\n' +
'    <button class="tab on" data-tab="js">JavaScript</button>\n' +
'    <button class="tab" data-tab="py">Python</button>\n' +
'    <button class="tab" data-tab="nd">Node.js</button>\n' +
'    <button class="tab" data-tab="ai">aiogram</button>\n' +
'  </div>\n' +
'  <div class="panel on" id="p-js"><pre><code class="language-javascript">' + jsCode + '</code></pre></div>\n' +
'  <div class="panel" id="p-py"><pre><code class="language-python">' + pyCode + '</code></pre></div>\n' +
'  <div class="panel" id="p-nd"><pre><code class="language-javascript">' + nodeCode + '</code></pre></div>\n' +
'  <div class="panel" id="p-ai"><pre><code class="language-python">' + aiogramCode + '</code></pre></div>\n' +
'</div>\n' +
'\n' +
'<div class="card">\n' +
'  <div class="ch">\n' +
'    <svg viewBox="0 0 16 16"><path d="M8 0a8 8 0 100 16A8 8 0 008 0zM1.5 8a6.5 6.5 0 1113 0 6.5 6.5 0 01-13 0zm4.879-2.773 4.264 2.559a.25.25 0 010 .428l-4.264 2.559A.25.25 0 016 10.559V5.442a.25.25 0 01.379-.215z"/></svg>\n' +
'    <h2>Connection Test</h2>\n' +
'  </div>\n' +
'  <div class="cb">\n' +
'    <button class="btn btn-b btn-full" id="testBtn">Test API Connection</button>\n' +
'    <div class="test-out" id="testOut"></div>\n' +
'    <div class="stats-row" id="statsRow" style="display:none">\n' +
'      <div class="stat-box"><div class="stat-num" id="sUptime">-</div><div class="stat-lbl">Uptime (s)</div></div>\n' +
'      <div class="stat-box"><div class="stat-num" id="sTotal">-</div><div class="stat-lbl">Total Requests</div></div>\n' +
'      <div class="stat-box"><div class="stat-num" id="sLatency">-</div><div class="stat-lbl">Avg Latency (ms)</div></div>\n' +
'      <div class="stat-box"><div class="stat-num" id="sBlocked">-</div><div class="stat-lbl">Blocked</div></div>\n' +
'    </div>\n' +
'  </div>\n' +
'</div>\n' +
'\n' +
'<div class="card">\n' +
'  <div class="ch">\n' +
'    <svg viewBox="0 0 16 16"><path d="M8 0a8 8 0 100 16A8 8 0 008 0zm3.71 5.81L6.89 10.6a.75.75 0 01-1.06 0L4.3 9.07a.75.75 0 011.08-1.05l1.02 1.04 4.29-4.3a.75.75 0 011.06 1.05z"/></svg>\n' +
'    <h2>Features</h2>\n' +
'  </div>\n' +
'  <div class="features">\n' +
'    <div class="feature"><span class="check">&#10003;</span><span>Rate limiting per IP, token &amp; burst</span></div>\n' +
'    <div class="feature"><span class="check">&#10003;</span><span>Circuit breaker with auto-recovery</span></div>\n' +
'    <div class="feature"><span class="check">&#10003;</span><span>Retry with exponential backoff</span></div>\n' +
'    <div class="feature"><span class="check">&#10003;</span><span>Security headers (CSP, HSTS, Permissions-Policy)</span></div>\n' +
'    <div class="feature"><span class="check">&#10003;</span><span>Bot token format validation &amp; caching</span></div>\n' +
'    <div class="feature"><span class="check">&#10003;</span><span>File &amp; media upload support</span></div>\n' +
'    <div class="feature"><span class="check">&#10003;</span><span>XSS, SQLi &amp; path traversal detection</span></div>\n' +
'    <div class="feature"><span class="check">&#10003;</span><span>Edge caching per Telegram API method</span></div>\n' +
'  </div>\n' +
'</div>\n' +
'\n' +
'<footer>\n' +
'  <p>Powered by Cloudflare Workers &nbsp;&middot;&nbsp; Designed by <strong>Anonymous</strong></p>\n' +
'</footer>\n' +
'\n' +
'</div>\n' +
'<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>\n' +
'<script>\n' +
'document.addEventListener("DOMContentLoaded", function () {\n' +
'    hljs.highlightAll();\n' +
'\n' +
'    var copyBtn = document.getElementById("copyBtn");\n' +
'    copyBtn.addEventListener("click", function () {\n' +
'        var text = document.querySelector(".url-txt").textContent;\n' +
'        function done() {\n' +
'            copyBtn.textContent = "Copied!";\n' +
'            copyBtn.classList.add("ok");\n' +
'            setTimeout(function () { copyBtn.textContent = "Copy"; copyBtn.classList.remove("ok"); }, 2000);\n' +
'        }\n' +
'        if (navigator.clipboard && navigator.clipboard.writeText) {\n' +
'            navigator.clipboard.writeText(text).then(done);\n' +
'        } else {\n' +
'            var el = document.createElement("textarea");\n' +
'            el.value = text; el.style.position = "fixed"; el.style.opacity = "0";\n' +
'            document.body.appendChild(el); el.select();\n' +
'            document.execCommand("copy"); document.body.removeChild(el);\n' +
'            done();\n' +
'        }\n' +
'    });\n' +
'\n' +
'    document.querySelectorAll(".tab").forEach(function (tab) {\n' +
'        tab.addEventListener("click", function () {\n' +
'            document.querySelectorAll(".tab").forEach(function (t) { t.classList.remove("on"); });\n' +
'            document.querySelectorAll(".panel").forEach(function (p) { p.classList.remove("on"); });\n' +
'            this.classList.add("on");\n' +
'            document.getElementById("p-" + this.dataset.tab).classList.add("on");\n' +
'        });\n' +
'    });\n' +
'\n' +
'    var testBtn = document.getElementById("testBtn");\n' +
'    testBtn.addEventListener("click", async function () {\n' +
'        var out = document.getElementById("testOut");\n' +
'        var row = document.getElementById("statsRow");\n' +
'        testBtn.innerHTML = "<span class=\\"spin\\"></span>Testing\u2026";\n' +
'        testBtn.disabled = true;\n' +
'        out.style.display = "none";\n' +
'        row.style.display = "none";\n' +
'        try {\n' +
'            var t = Date.now();\n' +
'            var res = await fetch("/stats");\n' +
'            var ping = Date.now() - t;\n' +
'            var d = await res.json();\n' +
'            if (d.ok) {\n' +
'                out.className = "test-out ok";\n' +
'                out.textContent = "Connection successful \u2014 Ping: " + ping + "ms";\n' +
'                out.style.display = "block";\n' +
'                document.getElementById("sUptime").textContent  = d.uptime;\n' +
'                document.getElementById("sTotal").textContent   = d.totalRequests;\n' +
'                document.getElementById("sLatency").textContent = d.avgLatency;\n' +
'                document.getElementById("sBlocked").textContent = d.blocked;\n' +
'                row.style.display = "grid";\n' +
'            } else { throw new Error(""); }\n' +
'        } catch (e) {\n' +
'            out.className = "test-out err";\n' +
'            out.textContent = "Connection failed \u2014 Worker may not be fully deployed.";\n' +
'            out.style.display = "block";\n' +
'        }\n' +
'        testBtn.textContent = "Test API Connection";\n' +
'        testBtn.disabled = false;\n' +
'    });\n' +
'});\n' +
'</script>\n' +
'</body>\n' +
'</html>';

    return new Response(html, {
        status: 200,
        headers: {
            'Content-Type': 'text/html;charset=UTF-8',
            'Cache-Control': 'no-cache'
        }
    });
}

function handleStatsRequest() {
    const uptime = Math.floor((Date.now() - stats.startTime) / 1000);
    return new Response(JSON.stringify({
        ok:                 true,
        uptime,
        totalRequests:      stats.totalRequests,
        successfulRequests: stats.successfulRequests,
        failedRequests:     stats.failedRequests,
        rateLimited:        stats.rateLimited,
        blocked:            stats.blocked,
        retries:            stats.retries,
        avgLatency:         Math.floor(stats.avgResponseTime)
    }), {
        status: 200,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-store'
        }
    });
}

function handle404Request() {
    return new Response(JSON.stringify({
        ok:          false,
        error_code:  404,
        description: 'Invalid endpoint. Use /bot{TOKEN}/{METHOD} format.'
    }), {
        status: 404,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}

async function handleProxyRequest(request) {
    const startTime = Date.now();
    try {
        await cleanupExpiredData();

        const secCheck = await performSecurityChecks(request);
        if (secCheck.blocked) {
            stats.blocked++;
            return createErrorResponse(secCheck.reason, secCheck.status);
        }

        const info = parseRequest(request);
        if (!info.valid) {
            stats.blocked++;
            return createErrorResponse('Invalid request format', 400);
        }

        const circuitState = checkCircuitBreaker(info.clientIP);
        if (circuitState === 'OPEN') {
            return createErrorResponse('Service temporarily unavailable', 503);
        }

        const rl = checkRateLimit(info.clientIP, info.botToken);
        if (rl.limited) {
            stats.rateLimited++;
            return createRateLimitResponse(rl.retryAfter);
        }

        if (!validateBotToken(info.botToken)) {
            await recordSuspiciousActivity(info.clientIP, 'invalid_token');
            stats.blocked++;
            return createErrorResponse('Invalid bot token', 401);
        }

        const response = await proxyWithRetry(request, info);

        updateCircuitBreaker(info.clientIP, response.ok);
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
            breaker.state     = 'CLOSED';
            breaker.failureCount = 0;
        }
    }

    if (now - stats.lastReset > 3600000) {
        stats.totalRequests      = 0;
        stats.successfulRequests = 0;
        stats.failedRequests     = 0;
        stats.rateLimited        = 0;
        stats.blocked            = 0;
        stats.retries            = 0;
        stats.lastReset          = now;
        stats.avgResponseTime    = 0;
    }
}

async function performSecurityChecks(request) {
    const clientIP    = getClientIP(request);
    const userAgent   = request.headers.get('user-agent') || '';
    const country     = request.headers.get('cf-ipcountry');
    const referer     = request.headers.get('referer') || '';
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

    const url      = new URL(request.url);
    const fullPath = url.pathname + url.search;

    for (const pattern of MALICIOUS_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(fullPath) || pattern.test(referer)) {
            await recordSuspiciousActivity(clientIP, 'malicious_pattern');
            return { blocked: true, reason: 'Malicious request detected', status: 400 };
        }
    }

    if (request.method === 'POST' && contentType.includes('multipart/form-data')) {
        const m = contentType.match(/boundary=([^;]+)/);
        if (m && m[1].length > 200) {
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
    const now      = Date.now();
    const existing = suspiciousIPs.get(ip) || { count: 0, types: new Set(), expires: now + 3600000 };
    existing.count++;
    existing.types.add(type);
    existing.lastActivity = now;
    suspiciousIPs.set(ip, existing);
}

function parseRequest(request) {
    const url      = new URL(request.url);
    const path     = url.pathname;
    const clientIP = getClientIP(request);

    if (!URL_PATH_REGEX.test(path)) return { valid: false };

    const match     = path.match(URL_PATH_REGEX);
    const botToken  = match?.groups?.bot_token  || '';
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

    const bk = 'b_' + clientIP;
    if (getCount(requestCounters.burst, bk, now, RATE_LIMITS.BURST.window) >= RATE_LIMITS.BURST.max) {
        return { limited: true, retryAfter: 1 };
    }

    const ik = 'i_' + clientIP;
    if (getCount(requestCounters.ip, ik, now, RATE_LIMITS.IP.window) >= RATE_LIMITS.IP.max) {
        return { limited: true, retryAfter: 60 };
    }

    const tk = 't_' + botToken;
    if (getCount(requestCounters.token, tk, now, RATE_LIMITS.TOKEN.window) >= RATE_LIMITS.TOKEN.max) {
        return { limited: true, retryAfter: 60 };
    }

    incCount(requestCounters.burst, bk, now, RATE_LIMITS.BURST.window);
    incCount(requestCounters.ip,    ik, now, RATE_LIMITS.IP.window);
    incCount(requestCounters.token, tk, now, RATE_LIMITS.TOKEN.window);
    requestCounters.global.count++;

    return { limited: false };
}

function cleanupCounters(now) {
    if (now >= requestCounters.global.resetTime) {
        requestCounters.global.count     = 0;
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
        if (b.state === 'HALF_OPEN')   { b.state = 'CLOSED'; b.failureCount = 0; }
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

async function proxyWithRetry(request, info) {
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

            const response = await proxyToTelegram(request, info);
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

async function proxyToTelegram(request, info) {
    const { apiMethod, path } = info;

    const newUrl = new URL(request.url);
    newUrl.hostname = TELEGRAM_API_HOST;
    newUrl.port     = '';
    newUrl.pathname = path;

    const requestHeaders = new Headers(request.headers);
    sanitizeHeaders(requestHeaders);
    requestHeaders.set('Connection',    'keep-alive');
    requestHeaders.set('User-Agent',    'Cloudflare-Worker-Proxy/2.0');
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

    const controller  = new AbortController();
    const isUpload    = FILE_UPLOAD_METHODS.has(apiMethod);
    const timer       = setTimeout(() => controller.abort(), isUpload ? 120000 : 30000);

    try {
        const cacheConfig = CACHE_CONFIGS[apiMethod] || { ttl: 0, edge: false };

        const response = await fetch(new Request(newUrl.toString(), {
            method:   request.method,
            headers:  requestHeaders,
            body:     requestBody,
            redirect: 'follow',
            signal:   controller.signal
        }), {
            cf: {
                cacheTtl:        cacheConfig.ttl,
                cacheEverything: cacheConfig.edge && request.method === 'GET',
                polish:          'off',
                minify:          { javascript: false, css: false, html: false },
                timeout:         isUpload ? 100000 : 25000
            }
        });

        if (!response.ok && response.status >= 500) {
            throw new Error('Server error: ' + response.status);
        }

        const responseHeaders = new Headers(response.headers);
        addSecurityHeaders(responseHeaders);

        return new Response(await response.arrayBuffer(), {
            status:     response.status,
            statusText: response.statusText,
            headers:    getCorsHeaders(responseHeaders)
        });

    } finally {
        clearTimeout(timer);
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
    headers.set('X-Content-Type-Options',           'nosniff');
    headers.set('X-Frame-Options',                  'DENY');
    headers.set('X-XSS-Protection',                 '1; mode=block');
    headers.set('Referrer-Policy',                  'strict-origin-when-cross-origin');
    headers.set('Content-Security-Policy',          "default-src 'none'; script-src 'none'; object-src 'none'");
    headers.set('Strict-Transport-Security',        'max-age=31536000; includeSubDomains');
    headers.set('X-Permitted-Cross-Domain-Policies','none');
    headers.set('X-Download-Options',               'noopen');
    headers.set('X-DNS-Prefetch-Control',           'off');
    headers.set('Permissions-Policy',               'geolocation=(), microphone=(), camera=()');
}

function getCorsHeaders(headers) {
    const h = new Headers(headers || {});
    h.set('Access-Control-Allow-Origin',   '*');
    h.set('Access-Control-Allow-Methods',  'GET, POST, PUT, DELETE, OPTIONS');
    h.set('Access-Control-Allow-Headers',  'Content-Type, Authorization, X-Requested-With');
    h.set('Access-Control-Expose-Headers', 'X-RateLimit-Remaining, X-RateLimit-Reset');
    h.set('Access-Control-Max-Age',        '86400');
    h.set('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers');
    return h;
}

function handleCorsPreflightRequest() {
    return new Response(null, { status: 204, headers: getCorsHeaders() });
}

function createErrorResponse(message, status) {
    if (!status) status = 400;
    const headers = getCorsHeaders();
    headers.set('Content-Type',  'application/json');
    headers.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    return new Response(JSON.stringify({
        ok:         false,
        error:      message,
        error_code: status,
        timestamp:  new Date().toISOString(),
        request_id: generateId()
    }), { status, headers });
}

function createRateLimitResponse(retryAfter) {
    const headers = getCorsHeaders();
    headers.set('Content-Type',         'application/json');
    headers.set('Retry-After',          retryAfter.toString());
    headers.set('X-RateLimit-Remaining','0');
    headers.set('X-RateLimit-Reset',    (Date.now() + retryAfter * 1000).toString());
    headers.set('Cache-Control',        'no-store, no-cache, must-revalidate');
    return new Response(JSON.stringify({
        ok:          false,
        error:       'Rate limit exceeded. Please try again later.',
        retry_after: retryAfter,
        timestamp:   new Date().toISOString(),
        request_id:  generateId()
    }), { status: 429, headers });
}

function handleProxyError(error) {
    const msg       = error.message || 'Unknown error';
    const isTimeout = error.name === 'AbortError' || msg.includes('timeout');
    const headers   = getCorsHeaders();
    headers.set('Content-Type', 'application/json');
    return new Response(JSON.stringify({
        ok:         false,
        error:      isTimeout ? 'Gateway timeout' : 'Proxy service temporarily unavailable',
        details:    msg.substring(0, 200),
        timestamp:  new Date().toISOString(),
        request_id: generateId()
    }), { status: isTimeout ? 504 : 500, headers });
}

function updateStats(startTime, success) {
    const responseTime = Date.now() - startTime;
    stats.totalRequests++;
    if (success) stats.successfulRequests++;
    else         stats.failedRequests++;
    stats.avgResponseTime = stats.totalRequests === 1
        ? responseTime
        : ((stats.avgResponseTime * (stats.totalRequests - 1)) + responseTime) / stats.totalRequests;
}

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substring(2, 7);
}
