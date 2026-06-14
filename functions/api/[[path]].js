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

let requestStats = {
    total: 0,
    errors: 0,
    rateLimited: 0,
    blocked: 0,
    retries: 0,
    lastReset: Date.now(),
    avgResponseTime: 0
};

export async function onRequest(context) {
    const startTime = Date.now();
    const { request } = context;
    const url = new URL(request.url);
    const path = url.pathname.replace('/api', '');

    if (path === '/stats' || path === '/health') {
        return handleStatsRequest();
    }

    try {
        await cleanupExpiredData();

        const securityCheck = await performSecurityChecks(request);
        if (securityCheck.blocked) {
            requestStats.blocked++;
            return createErrorResponse(securityCheck.reason, securityCheck.status);
        }

        if (request.method === 'OPTIONS') {
            return handleCorsPreflightRequest();
        }

        const requestInfo = parseRequest(request);
        if (!requestInfo.valid) {
            return createErrorResponse('Invalid request format', 400);
        }

        const circuitState = checkCircuitBreaker(requestInfo.clientIP);
        if (circuitState === 'OPEN') {
            return createErrorResponse('Service temporarily unavailable', 503);
        }

        const rateLimitResult = checkRateLimit(requestInfo.clientIP, requestInfo.botToken);
        if (rateLimitResult.limited) {
            requestStats.rateLimited++;
            return createRateLimitResponse(rateLimitResult.retryAfter);
        }

        if (!validateBotToken(requestInfo.botToken)) {
            await recordSuspiciousActivity(requestInfo.clientIP, 'invalid_token');
            return createErrorResponse('Invalid bot token', 401);
        }

        const response = await proxyWithRetry(request, requestInfo);

        updateCircuitBreaker(requestInfo.clientIP, response.ok);
        updateStats(startTime, response.ok);

        return response;

    } catch (error) {
        console.error('Proxy error:', error);
        requestStats.errors++;
        updateCircuitBreaker(getClientIP(request), false);
        return handleProxyError(error);
    }
}

function handleStatsRequest() {
    const uptime = Math.floor((Date.now() - requestStats.lastReset) / 1000);
    return new Response(JSON.stringify({
        ok: true,
        uptime,
        totalRequests: requestStats.total,
        errors: requestStats.errors,
        rateLimited: requestStats.rateLimited,
        blocked: requestStats.blocked,
        avgLatency: Math.floor(requestStats.avgResponseTime)
    }), {
        status: 200,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-store'
        }
    });
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

    if (now - requestStats.lastReset > 3600000) {
        requestStats = {
            total: 0,
            errors: 0,
            rateLimited: 0,
            blocked: 0,
            retries: 0,
            lastReset: now,
            avgResponseTime: 0
        };
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

    const xForwardedFor = request.headers.get('x-forwarded-for');
    if (xForwardedFor && xForwardedFor.split(',').length > 10) {
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
    const path = url.pathname.replace('/api', '');
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

    const burstKey = `b_${clientIP}`;
    if (getCount(requestCounters.burst, burstKey, now, RATE_LIMITS.BURST.window) >= RATE_LIMITS.BURST.max) {
        return { limited: true, retryAfter: 1 };
    }

    const ipKey = `i_${clientIP}`;
    if (getCount(requestCounters.ip, ipKey, now, RATE_LIMITS.IP.window) >= RATE_LIMITS.IP.max) {
        return { limited: true, retryAfter: 60 };
    }

    const tokenKey = `t_${botToken}`;
    if (getCount(requestCounters.token, tokenKey, now, RATE_LIMITS.TOKEN.window) >= RATE_LIMITS.TOKEN.max) {
        return { limited: true, retryAfter: 60 };
    }

    incCount(requestCounters.burst, burstKey, now, RATE_LIMITS.BURST.window);
    incCount(requestCounters.ip, ipKey, now, RATE_LIMITS.IP.window);
    incCount(requestCounters.token, tokenKey, now, RATE_LIMITS.TOKEN.window);
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

function getCount(map, key, now, window) {
    const data = map.get(key);
    return (!data || now >= data.resetTime) ? 0 : data.count;
}

function incCount(map, key, now, window) {
    const existing = map.get(key);
    if (!existing || now >= existing.resetTime) {
        map.set(key, { count: 1, resetTime: now + window });
    } else {
        existing.count++;
    }
}

function checkCircuitBreaker(clientIP) {
    const breaker = circuitBreakers.get(clientIP);
    if (!breaker) return 'CLOSED';

    const now = Date.now();

    if (breaker.state === 'OPEN') {
        if (now - breaker.lastFailureTime >= CIRCUIT_BREAKER.TIMEOUT) {
            breaker.state = 'HALF_OPEN';
            breaker.halfOpenAttempts = 0;
            return 'HALF_OPEN';
        }
        return 'OPEN';
    }

    if (breaker.state === 'HALF_OPEN') {
        if (breaker.halfOpenAttempts >= CIRCUIT_BREAKER.HALF_OPEN_MAX_CALLS) return 'OPEN';
        breaker.halfOpenAttempts++;
    }

    return breaker.state;
}

function updateCircuitBreaker(clientIP, success) {
    let breaker = circuitBreakers.get(clientIP);
    if (!breaker) {
        breaker = { state: 'CLOSED', failureCount: 0, lastFailureTime: 0, halfOpenAttempts: 0 };
        circuitBreakers.set(clientIP, breaker);
    }

    if (success) {
        if (breaker.state === 'HALF_OPEN') { breaker.state = 'CLOSED'; breaker.failureCount = 0; }
        else if (breaker.state === 'CLOSED') breaker.failureCount = Math.max(0, breaker.failureCount - 1);
    } else {
        breaker.failureCount++;
        breaker.lastFailureTime = Date.now();
        if (breaker.failureCount >= CIRCUIT_BREAKER.FAILURE_THRESHOLD) breaker.state = 'OPEN';
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
            botId.length >= 5 &&
            botHash.length >= 25 &&
            /^\d+$/.test(botId) &&
            /^[A-Za-z0-9_-]+$/.test(botHash)
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
                requestStats.retries++;
                const delay = Math.min(
                    RETRY_CONFIG.INITIAL_DELAY * Math.pow(RETRY_CONFIG.BACKOFF_FACTOR, attempt - 1),
                    RETRY_CONFIG.MAX_DELAY
                );
                await new Promise(r => setTimeout(r, delay));
            }

            const response = await proxyToTelegram(request, requestInfo);

            if (response.ok || response.status < 500) return response;

            lastError = new Error(`HTTP ${response.status}`);

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
    requestHeaders.set('User-Agent', 'Cloudflare-Pages-Proxy/2.0');
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
            throw new Error(`Server error: ${response.status}`);
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

function getCorsHeaders(headers = new Headers()) {
    const h = new Headers(headers);
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

function createErrorResponse(message, status = 400) {
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
    requestStats.total++;
    if (!success) requestStats.errors++;
    requestStats.avgResponseTime = requestStats.total === 1
        ? responseTime
        : ((requestStats.avgResponseTime * (requestStats.total - 1)) + responseTime) / requestStats.total;
}

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substring(2, 7);
}