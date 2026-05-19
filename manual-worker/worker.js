// Telegram API Proxy - Workers Version (ES Module)
// Author: Anonymous (Modded by Antigravity)

const URL_PATH_REGEX = /^\/bot(?<bot_token>[^/]+)\/(?<api_method>[a-zA-Z0-9_]+)/i;
const FILE_PATH_REGEX = /^\/file\/bot(?<bot_token>[^/]+)\/(?<file_id>.+)$/i;

const RATE_LIMITS = {
    IP: { max: 100, window: 60000 },
    TOKEN: { max: 200, window: 60000 },
    GLOBAL: { max: 5000, window: 60000 },
    BURST: { max: 10, window: 1000 }
};

const ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];

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

const requestCounters = {
    global: { count: 0, resetTime: Date.now() + RATE_LIMITS.GLOBAL.window }
};

export default {
    async fetch(request, env, ctx) {
        return handleRequest(request, env);
    }
};

async function handleRequest(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname.toLowerCase().replace(/\/$/, "");

    if (pathname === '/stats') {
        return handleStatsRequest();
    }

    if (pathname === '' || pathname === '/') {
        return handleRootRequest(request);
    }

    // 管理页面
    if (pathname === '/admin') {
        return new Response(ADMIN_HTML, {
            status: 200,
            headers: { 'content-type': 'text/html;charset=UTF-8' }
        });
    }

    // 管理 API
    if (pathname.startsWith('/api/admin/')) {
        return handleAdminApiRequest(request, pathname, env);
    }

    if (request.method === 'OPTIONS') {
        return handleCorsPreflightRequest();
    }

    // 文件代理路径匹配
    const rawPathname = url.pathname;
    if (FILE_PATH_REGEX.test(rawPathname)) {
        const startTime = Date.now();
        try {
            await cleanupExpiredData();

            // 安全检查
            const securityCheck = performAdvancedSecurityChecks(request);
            if (securityCheck.blocked) {
                stats.blocked++;
                return createErrorResponse(securityCheck.reason, securityCheck.status);
            }

            const fileInfo = parseFileRequest(request);
            if (!fileInfo.valid) {
                stats.blocked++;
                return createErrorResponse('Invalid file request format', 400);
            }

            // Token 验证
            const tokenValid = await validateBotToken(fileInfo.botToken, env);
            if (!tokenValid) {
                stats.blocked++;
                return createErrorResponse('Invalid or unauthorized bot token', 401);
            }

            const response = await proxyFileFromTelegram(fileInfo);
            updateStats(startTime, response.ok);
            return response;

        } catch (error) {
            console.error('File proxy error:', error);
            stats.failedRequests++;
            return createErrorResponse(error.message, 500);
        }
    }

    // 原始路径匹配 (不转小写，因为 Token 大小写敏感)
    if (URL_PATH_REGEX.test(rawPathname)) {
        const startTime = Date.now();
        try {
            await cleanupExpiredData();

            // 安全检查
            const securityCheck = performAdvancedSecurityChecks(request);
            if (securityCheck.blocked) {
                stats.blocked++;
                return createErrorResponse(securityCheck.reason, securityCheck.status);
            }

            const requestInfo = parseRequest(request);
            if (!requestInfo.valid) {
                stats.blocked++;
                return createErrorResponse('Invalid request format', 400);
            }

            // 频率限制
            if (checkGlobalRateLimit()) {
                stats.rateLimited++;
                return createRateLimitResponse(60);
            }

            // Token 验证
            const tokenValid = await validateBotToken(requestInfo.botToken, env);
            if (!tokenValid) {
                stats.blocked++;
                return createErrorResponse('Invalid or unauthorized bot token', 401);
            }

            const response = await proxyToTelegram(request, requestInfo);
            updateStats(startTime, response.ok);
            return response;

        } catch (error) {
            console.error('Proxy error:', error);
            stats.failedRequests++;
            return createErrorResponse(error.message, 500);
        }
    }

    return handle404Request();
}

// ==========================================
// 核心业务函数
// ==========================================

async function validateBotToken(token, env) {
    const allowedTokens = env.ALLOWED_BOT_TOKENS;
    if (!allowedTokens) {
        console.error('[Security] ALLOWED_BOT_TOKENS not configured.');
        return false;
    }

    const allowedList = allowedTokens.split(',').map(t => t.trim()).filter(t => t.length > 0);
    if (!allowedList.includes(token)) {
        return false;
    }

    if (!token.includes(':') || token.length < 30) return false;
    return true;
}

function parseFileRequest(request) {
    const url = new URL(request.url);
    const match = url.pathname.match(FILE_PATH_REGEX);
    if (!match) return { valid: false };
    return {
        valid: true,
        botToken: match.groups.bot_token,
        fileId: match.groups.file_id
    };
}

async function proxyFileFromTelegram(fileInfo) {
    const fileUrl = `https://api.telegram.org/file/bot${fileInfo.botToken}/${fileInfo.fileId}`;
    
    const headers = new Headers();
    headers.set('User-Agent', 'Cloudflare-Worker-Proxy/2.0');
    
    try {
        const response = await fetch(fileUrl, {
            method: 'GET',
            headers: headers,
            redirect: 'follow'
        });
        
        const respHeaders = new Headers(response.headers);
        respHeaders.set('Access-Control-Allow-Origin', '*');
        respHeaders.set('Cache-Control', 'public, max-age=3600'); // 1 小时缓存
        
        return new Response(response.body, {
            status: response.status,
            headers: respHeaders
        });
    } catch (error) {
        console.error('File download error:', error);
        throw error;
    }
}

function performAdvancedSecurityChecks(request) {
    if (!ALLOWED_METHODS.includes(request.method)) {
        return { blocked: true, reason: 'Method Forbidden', status: 405 };
    }
    const url = new URL(request.url);
    const MALICIOUS_PATTERNS = [/(\.\.|\/\.\/|\\\.\\|%2e%2e|%252e%252e)/i, /<script[^>]*>/i];
    for (const pattern of MALICIOUS_PATTERNS) {
        if (pattern.test(url.pathname) || pattern.test(url.search)) {
            return { blocked: true, reason: 'Security violation', status: 400 };
        }
    }
    return { blocked: false };
}

function parseRequest(request) {
    const url = new URL(request.url);
    const match = url.pathname.match(URL_PATH_REGEX);
    if (!match) return { valid: false };
    return {
        valid: true,
        botToken: match.groups.bot_token,
        apiMethod: match.groups.api_method,
        path: url.pathname + url.search
    };
}

async function proxyToTelegram(request, info) {
    const newUrl = "https://api.telegram.org" + info.path;
    const headers = new Headers(request.headers);
    headers.delete('host');
    headers.set('User-Agent', 'Cloudflare-Worker-Proxy/2.0');

    let body = null;
    if (request.method !== 'GET' && request.method !== 'HEAD') {
        const contentType = request.headers.get('content-type') || '';
        if (info.apiMethod === 'setWebhook') {
            if (contentType.includes('multipart/form-data')) {
                const formData = await request.formData();
                // 处理 setWebhook 方法，确保 proxy_url 正确设置
                if (formData.has('proxy_url')) {
                    // 移除 proxy_url 参数，让 Telegram 直接使用我们的代理地址
                    formData.delete('proxy_url');
                }
                body = formData;
                headers.delete('content-type');
            } else {
                // 处理 JSON 格式的 setWebhook 请求
                const bodyText = await request.text();
                try {
                    const bodyJson = JSON.parse(bodyText);
                    // 移除 proxy_url 参数
                    if (bodyJson.proxy_url) {
                        delete bodyJson.proxy_url;
                    }
                    body = JSON.stringify(bodyJson);
                    headers.set('Content-Type', 'application/json');
                } catch {
                    // 如果不是有效的 JSON，直接使用原始请求体
                    body = bodyText;
                }
            }
        } else {
            body = await request.clone().arrayBuffer();
        }
    }

    const response = await fetch(newUrl, {
        method: request.method,
        headers: headers,
        body: body,
        redirect: 'follow'
    });

    const respHeaders = new Headers(response.headers);
    respHeaders.set('Access-Control-Allow-Origin', '*');

    return new Response(response.body, {
        status: response.status,
        headers: respHeaders
    });
}

// ==========================================
// 管理后台逻辑
// ==========================================

async function handleAdminApiRequest(request, pathname, env) {
    const auth = request.headers.get('Authorization');
    const pwd = env.ADMIN_PASSWORD;
    if (!pwd || auth !== `Bearer ${pwd}`) {
        return new Response(JSON.stringify({ success: false, error: 'Unauthorized' }), { status: 401 });
    }

    if (request.method === 'GET' && pathname === '/api/admin/tokens') {
        const t = env.ALLOWED_BOT_TOKENS || '';
        return new Response(JSON.stringify({ tokens: t }), { headers: { 'content-type': 'application/json' } });
    }

    if (request.method === 'POST' && pathname === '/api/admin/tokens') {
        try {
            const { tokens } = await request.json();
            const result = await updateCloudflareEnv('ALLOWED_BOT_TOKENS', tokens, env);
            return new Response(JSON.stringify(result), {
                status: result.success ? 200 : 400,
                headers: { 'content-type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ success: false, error: e.message }), { status: 500 });
        }
    }
    return new Response('Not Found', { status: 404 });
}

async function updateCloudflareEnv(key, value, env) {
    const accId = env.CF_ACCOUNT_ID;
    const scName = env.CF_SCRIPT_NAME;
    const apiTok = env.CF_API_TOKEN;

    if (!accId || !scName || !apiTok) {
        return { success: false, error: '未配置 CF_ACCOUNT_ID/CF_SCRIPT_NAME/CF_API_TOKEN' };
    }

    try {
        // 尝试使用 Secrets API 进行更新，这样既可以更新普通变量也可以更新 Secret，且不干扰其他绑定
        const url = `https://api.cloudflare.com/client/v4/accounts/${accId}/workers/scripts/${scName}/secrets`;
        const res = await fetch(url, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${apiTok}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: key,
                text: value,
                type: 'secret_text'
            })
        });

        const data = await res.json();
        if (data.success) {
            return { success: true };
        } else {
            const err = data.errors?.[0]?.message || '更新失败';
            // 如果 Secrets API 不适用（例如脚本不存在或其他原因），返回详细错误
            return { success: false, error: `CF API 报错: ${err}` };
        }
    } catch (e) {
        return { success: false, error: '网络或系统异常: ' + e.message };
    }
}

// ==========================================
// 基础工具函数
// ==========================================

function handleStatsRequest() {
    return new Response(JSON.stringify(stats), { headers: { 'content-type': 'application/json' } });
}

function handle404Request() {
    return new Response(JSON.stringify({ ok: false, error: 'Endpoint not found' }), { status: 404 });
}

function handleRootRequest(request) {
    const workerUrl = new URL(request.url).origin;
    return new Response(`<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>Telegram Proxy</title><style>body{background:#121212;color:white;font-family:sans-serif;text-align:center;padding:50px}a{color:#61dafb}</style></head>
<body><h1>Telegram API 代理服务</h1><p>系统运行中...</p><p>管理入口: <a href="/admin">/admin</a></p></body></html>`, {
        headers: { 'content-type': 'text/html;charset=UTF-8' }
    });
}

function checkGlobalRateLimit() {
    const now = Date.now();
    if (now > requestCounters.global.resetTime) {
        requestCounters.global.count = 0;
        requestCounters.global.resetTime = now + RATE_LIMITS.GLOBAL.window;
    }
    requestCounters.global.count++;
    return requestCounters.global.count > RATE_LIMITS.GLOBAL.max;
}

async function cleanupExpiredData() { }
function updateStats(startTime, ok) {
    stats.totalRequests++;
    if (!ok) stats.failedRequests++;
    stats.avgResponseTime = (stats.avgResponseTime + (Date.now() - startTime)) / 2;
}

function createErrorResponse(err, status) {
    return new Response(JSON.stringify({ ok: false, error: err }), { status, headers: { 'content-type': 'application/json' } });
}

function createRateLimitResponse(retry) {
    return new Response(JSON.stringify({ ok: false, error: 'Rate limit' }), { status: 429, headers: { 'Retry-After': retry, 'content-type': 'application/json' } });
}

function handleCorsPreflightRequest() {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': '*', 'Access-Control-Allow-Headers': '*' } });
}

const ADMIN_HTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>Token 管理后台</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #f3f4f6; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .box { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 100%; max-width: 500px; }
        textarea { width: 100%; height: 100px; margin: 10px 0; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        input { width: 100%; padding: 10px; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; background: #007bff; color: white; border: none; padding: 12px; border-radius: 4px; cursor: pointer; font-weight: bold; }
        #msg { margin-top: 10px; padding: 10px; border-radius: 4px; display: none; word-break: break-all; white-space: pre-wrap; }
    </style>
</head>
<body>
    <div class="box">
        <h1>Token 管理后台</h1>
        <input type="password" id="pw" placeholder="管理员密码">
        <button onclick="load()">连接并获取配置</button>
        <div id="editor" style="display:none; margin-top: 20px;">
            <label>Bot Tokens (逗号分隔):</label>
            <textarea id="tk"></textarea>
            <button onclick="save()">保存并应用</button>
        </div>
        <div id="msg"></div>
    </div>
    <script>
        const msg = document.getElementById('msg');
        function show(txt, err) {
            msg.innerText = txt;
            msg.style.display = 'block';
            msg.style.background = err ? '#fee' : '#efe';
            msg.style.color = err ? '#c33' : '#3c3';
        }
        async function load() {
            const p = document.getElementById('pw').value;
            show('正在获取...', false);
            try {
                const res = await fetch('/api/admin/tokens', { headers: { 'Authorization': 'Bearer '+p } });
                const text = await res.text();
                try {
                    const d = JSON.parse(text);
                    if (res.ok) {
                        document.getElementById('tk').value = d.tokens || '';
                        document.getElementById('editor').style.display = 'block';
                        show('获取成功', false);
                    } else {
                        show('失败: ' + (d.error || '认证失败'), true);
                    }
                } catch(e) {
                    show('服务端返回异常格式 (非 JSON):\\n' + text, true);
                }
            } catch (e) { show('网络错误: ' + e.message, true); }
        }
        async function save() {
            const p = document.getElementById('pw').value;
            const t = document.getElementById('tk').value;
            show('正在保存...', false);
            try {
                const res = await fetch('/api/admin/tokens', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer '+p, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ tokens: t })
                });
                const text = await res.text();
                try {
                    const d = JSON.parse(text);
                    if (res.ok && d.success) {
                        show('保存成功！需约 10 秒生效。', false);
                    } else {
                        show('保存失败: ' + (d.error || '接口报错'), true);
                    }
                } catch(e) {
                    show('保存接口返回异常 (非 JSON):\\n' + text, true);
                }
            } catch (e) { show('系统错误: ' + e.message, true); }
        }
    </script>
</body>
</html>
`;
