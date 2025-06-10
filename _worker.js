// 完整2FA管理系统 - OAuth授权登录版本（支持2FAuth v5.5.2格式 ）
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// ===== 安全配置 =====
const SECURITY_CONFIG = {
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_TIME: 15 * 60 * 1000,
    JWT_EXPIRY: 2 * 60 * 60,
    MAX_INPUT_LENGTH: 100,
    MIN_EXPORT_PASSWORD_LENGTH: 12,
    OAUTH_TIMEOUT: 30 * 1000,
    MAX_OAUTH_ATTEMPTS: 3,
    OAUTH_LOCKOUT_TIME: 10 * 60 * 1000,
    SESSION_TIMEOUT: 2 * 60 * 60 * 1000,
    MAX_FILE_SIZE: 10 * 1024 * 1024,
    ALLOWED_FILE_TYPES: ['application/json', 'text/plain', 'image/jpeg', 'image/png', 'image/gif', 'image/webp']
};

// ===== 工具函数 =====
function sanitizeInput(input, maxLength = SECURITY_CONFIG.MAX_INPUT_LENGTH) {
    if (typeof input !== 'string') return '';
    return input.replace(/[<>"'&\x00-\x1F\x7F]/g, '').trim().substring(0, maxLength);
}

function validateBase32Secret(secret) {
    if (!secret || typeof secret !== 'string') return false;
    const cleaned = secret.replace(/\s/g, '').toUpperCase();
    return /^[A-Z2-7]+=*$/.test(cleaned) && cleaned.length >= 16;
}

function validateServiceName(service) {
    if (!service || typeof service !== 'string') return false;
    const cleaned = sanitizeInput(service, 50);
    return cleaned.length >= 1 && cleaned.length <= 50;
}

function validateAccountName(account) {
    if (!account || typeof account !== 'string') return false;
    const cleaned = sanitizeInput(account, 100);
    return cleaned.length >= 1 && cleaned.length <= 100;
}

// ===== 错误类定义 =====
class WebDAVError extends Error {
    constructor(message, statusCode, details) {
        super(message);
        this.name = 'WebDAVError';
        this.statusCode = statusCode;
        this.details = details;
    }
}

class ValidationError extends Error {
    constructor(message, field) {
        super(message);
        this.name = 'ValidationError';
        this.field = field;
    }
}

class OAuthError extends Error {
    constructor(message, code) {
        super(message);
        this.name = 'OAuthError';
        this.code = code;
    }
}

// ===== WebDAV XML 解析器 =====
function parseWebDAVXML(xmlText) {
    if (!xmlText || xmlText.length === 0) return [];
    
    try {
        const results = [];
        const cleanXml = xmlText.replace(/xmlns[^=]*="[^"]*"/g, '').replace(/\s+/g, ' ').trim();
        
        // 正则表达式解析
        const responsePattern = /<(?:d:)?response[^>]*?>([\s\S]*?)<\/(?:d:)?response>/gi;
        let match;
        
        while ((match = responsePattern.exec(cleanXml)) !== null) {
            const responseContent = match[1];
            const result = parseResponseContent(responseContent);
            if (result && isBackupFile(result.href)) {
                results.push(result);
            }
        }
        
        return results;
    } catch (error) {
        console.error('XML解析失败:', error);
        return [];
    }
}

function parseResponseContent(responseContent) {
    try {
        // 提取 href
        const hrefMatch = responseContent.match(/<(?:d:)?href[^>]*?>(.*?)<\/(?:d:)?href>/i);
        if (!hrefMatch) return null;
        
        let href;
        try {
            href = decodeURIComponent(hrefMatch[1].trim());
        } catch (e) {
            href = hrefMatch[1].trim();
        }
        
        // 检查是否为目录
        if (responseContent.includes('<collection/>') || href.endsWith('/')) return null;
        
        // 提取修改时间
        let lastModified = null;
        const modifiedMatch = responseContent.match(/<(?:d:)?getlastmodified[^>]*?>(.*?)<\/(?:d:)?getlastmodified>/i);
        if (modifiedMatch) {
            try {
                lastModified = new Date(modifiedMatch[1].trim());
                if (isNaN(lastModified.getTime())) lastModified = null;
            } catch (e) {
                lastModified = null;
            }
        }
        
        // 提取文件大小
        let contentLength = 0;
        const lengthMatch = responseContent.match(/<(?:d:)?getcontentlength[^>]*?>(.*?)<\/(?:d:)?getcontentlength>/i);
        if (lengthMatch) {
            const size = parseInt(lengthMatch[1].trim());
            if (!isNaN(size)) contentLength = size;
        }
        
        return { href, lastModified, contentLength };
    } catch (error) {
        console.error('解析response内容错误:', error);
        return null;
    }
}

function isBackupFile(href) {
    if (!href || typeof href !== 'string') return false;
    const filename = href.split('/').pop() || '';
    const patterns = [
        /^2fa-backup-encrypted-\d{4}-\d{2}-\d{2}.*\.json$/i,
        /2fa.*\.json$/i,
        /backup.*\.json$/i,
        /encrypted.*\.json$/i
    ];
    return patterns.some(pattern => pattern.test(filename));
}

// ===== WebDAV配置验证 =====
function validateWebDAVConfig(config) {
    const errors = [];
    
    if (!config.url) {
        errors.push('WebDAV URL is required');
    } else {
        try {
            const url = new URL(config.url);
            if (!['http:', 'https:'].includes(url.protocol)) {
                errors.push('WebDAV URL must use HTTP or HTTPS protocol');
            }
        } catch (e) {
            errors.push('Invalid WebDAV URL format');
        }
    }
    
    if (!config.username || config.username.length < 1) errors.push('Username is required');
    if (!config.password || config.password.length < 1) errors.push('Password is required');
    if (config.saveDir && !config.saveDir.startsWith('/')) errors.push('Save directory must start with /');
    
    return { isValid: errors.length === 0, errors };
}

// ===== WebDAV相关函数 =====
async function uploadToWebDAV(data, filename, webdavConfig) {
    try {
        const auth = btoa(`${webdavConfig.username}:${webdavConfig.password}`);
        const today = new Date();
        const dateFolder = `${today.getFullYear()}/${String(today.getMonth() + 1).padStart(2, '0')}/${String(today.getDate()).padStart(2, '0')}`;
        
        let saveDir = webdavConfig.saveDir || '/2fa-backups';
        if (!saveDir.endsWith('/')) saveDir += '/';
        
        const fullPath = `${saveDir}${dateFolder}/${filename}`;
        const webdavUrl = webdavConfig.url.replace(/\/$/, '') + fullPath;
        
        // 创建目录结构
        const dirParts = fullPath.split('/').slice(0, -1);
        let currentPath = '';
        
        for (const part of dirParts) {
            if (part) {
                currentPath += '/' + part;
                const dirUrl = webdavConfig.url.replace(/\/$/, '') + currentPath;
                
                try {
                    await fetch(dirUrl, {
                        method: 'MKCOL',
                        headers: {
                            'Authorization': `Basic ${auth}`,
                            'Content-Type': 'application/xml',
                            'User-Agent': '2FA-Manager/1.0'
                        }
                    });
                } catch (e) {
                    // 目录可能已存在，忽略错误
                }
            }
        }
        
        // 上传文件
        const response = await fetch(webdavUrl, {
            method: 'PUT',
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json',
                'User-Agent': '2FA-Manager/1.0'
            },
            body: data
        });
        
        if (response.ok || response.status === 201) {
            return { success: true, url: webdavUrl, path: fullPath };
        } else {
            const errorText = await response.text();
            throw new WebDAVError(`WebDAV upload failed: ${response.status} ${response.statusText}`, response.status, errorText);
        }
    } catch (error) {
        if (error instanceof WebDAVError) throw error;
        throw new WebDAVError(`WebDAV upload error: ${error.message}`, 500, error.message);
    }
}

async function listWebDAVBackups(webdavConfig) {
    try {
        const auth = btoa(`${webdavConfig.username}:${webdavConfig.password}`);
        let saveDir = webdavConfig.saveDir || '/2fa-backups';
        if (!saveDir.endsWith('/')) saveDir += '/';
        
        const webdavUrl = webdavConfig.url.replace(/\/$/, '') + saveDir;
        
        const response = await fetch(webdavUrl, {
            method: 'PROPFIND',
            headers: {
                'Authorization': `Basic ${auth}`,
                'Depth': 'infinity',
                'Content-Type': 'application/xml; charset=utf-8',
                'User-Agent': '2FA-Manager/1.0'
            },
            body: `<?xml version="1.0" encoding="utf-8"?>
<propfind xmlns="DAV:">
    <allprop/>
</propfind>`
        });
        
        if (!response.ok && response.status !== 207) {
            const errorText = await response.text();
            throw new WebDAVError(`WebDAV PROPFIND failed: ${response.status} ${response.statusText}`, response.status, errorText);
        }
        
        const xmlText = await response.text();
        if (!xmlText || xmlText.length === 0) return [];
        
        const parsedResponses = parseWebDAVXML(xmlText);
        const backups = [];
        
        const urlObj = new URL(webdavConfig.url);
        const baseUrl = `${urlObj.protocol}//${urlObj.host}`;
        
        for (const item of parsedResponses) {
            if (!isBackupFile(item.href)) continue;
            
            const filename = item.href.split('/').pop();
            let relativePath = item.href;
            
            if (item.href.startsWith(baseUrl)) {
                relativePath = item.href.substring(baseUrl.length);
            } else if (!item.href.startsWith('/')) {
                relativePath = '/' + item.href;
            }
            
            backups.push({
                filename,
                path: relativePath,
                fullUrl: baseUrl + relativePath,
                lastModified: item.lastModified,
                size: item.contentLength || 0
            });
        }
        
        // 按修改时间排序
        backups.sort((a, b) => {
            if (!a.lastModified && !b.lastModified) return 0;
            if (!a.lastModified) return 1;
            if (!b.lastModified) return -1;
            return b.lastModified.getTime() - a.lastModified.getTime();
        });
        
        return backups;
    } catch (error) {
        if (error instanceof WebDAVError) throw error;
        throw new WebDAVError(`Failed to list WebDAV backups: ${error.message}`, 500, error.message);
    }
}

async function downloadFromWebDAV(path, webdavConfig) {
    try {
        const auth = btoa(`${webdavConfig.username}:${webdavConfig.password}`);
        const urlObj = new URL(webdavConfig.url);
        const baseUrl = `${urlObj.protocol}//${urlObj.host}`;
        const webdavUrl = baseUrl + path;
        
        const response = await fetch(webdavUrl, {
            method: 'GET',
            headers: {
                'Authorization': `Basic ${auth}`,
                'User-Agent': '2FA-Manager/1.0'
            }
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new WebDAVError(`WebDAV download failed: ${response.status} ${response.statusText}`, response.status, errorText);
        }
        
        return await response.text();
    } catch (error) {
        if (error instanceof WebDAVError) throw error;
        throw new WebDAVError(`WebDAV download error: ${error.message}`, 500, error.message);
    }
}

// ===== 加密解密功能 =====
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
    
    return await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptData(data, masterKey) {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    const key = await deriveKey(masterKey, salt);
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(JSON.stringify(data)));
    
    return {
        encrypted: Array.from(new Uint8Array(encrypted)),
        iv: Array.from(iv),
        salt: Array.from(salt)
    };
}

async function decryptData(encryptedData, masterKey) {
    const decoder = new TextDecoder();
    const salt = new Uint8Array(encryptedData.salt);
    const iv = new Uint8Array(encryptedData.iv);
    const encrypted = new Uint8Array(encryptedData.encrypted);
    
    const key = await deriveKey(masterKey, salt);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);
    
    return JSON.parse(decoder.decode(decrypted));
}

// ===== 登录失败追踪（内存实现） =====
const loginAttemptsMap = new Map();
const oauthAttemptsMap = new Map();

async function checkLoginAttempts(identifier) {
    const now = Date.now();
    if (loginAttemptsMap.has(identifier)) {
        const attempts = loginAttemptsMap.get(identifier);
        if (attempts.count >= SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS) {
            const timeLeft = attempts.lockedUntil - now;
            if (timeLeft > 0) {
                throw new Error(`Account locked. Try again in ${Math.ceil(timeLeft / 60000)} minutes.`);
            }
        }
    }
    return true;
}

async function recordLoginAttempt(identifier, success) {
    const now = Date.now();
    if (success) {
        loginAttemptsMap.delete(identifier);
    } else {
        const attempts = loginAttemptsMap.get(identifier) || { count: 0, lockedUntil: 0 };
        attempts.count += 1;
        if (attempts.count >= SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS) {
            attempts.lockedUntil = now + SECURITY_CONFIG.LOCKOUT_TIME;
        }
        loginAttemptsMap.set(identifier, attempts);
    }
}

async function checkOAuthAttempts(identifier) {
    const now = Date.now();
    if (oauthAttemptsMap.has(identifier)) {
        const attempts = oauthAttemptsMap.get(identifier);
        if (attempts.count >= SECURITY_CONFIG.MAX_OAUTH_ATTEMPTS) {
            const timeLeft = attempts.lockedUntil - now;
            if (timeLeft > 0) {
                throw new OAuthError(`OAuth verification locked. Try again in ${Math.ceil(timeLeft / 60000)} minutes.`, 'LOCKED');
            }
        }
    }
    return true;
}

async function recordOAuthAttempt(identifier, success) {
    const now = Date.now();
    if (success) {
        oauthAttemptsMap.delete(identifier);
    } else {
        const attempts = oauthAttemptsMap.get(identifier) || { count: 0, lockedUntil: 0 };
        attempts.count += 1;
        if (attempts.count >= SECURITY_CONFIG.MAX_OAUTH_ATTEMPTS) {
            attempts.lockedUntil = now + SECURITY_CONFIG.OAUTH_LOCKOUT_TIME;
        }
        oauthAttemptsMap.set(identifier, attempts);
    }
}

// ===== 安全日志 =====
async function logSecurityEvent(event, details, request) {
    try {
        const log = {
            timestamp: new Date().toISOString(),
            event,
            details,
            ip: request.headers.get('CF-Connecting-IP') || 'unknown',
            userAgent: request.headers.get('User-Agent')?.substring(0, 200) || 'unknown',
            country: request.cf?.country || 'unknown'
        };
        console.log('SECURITY_LOG:', JSON.stringify(log));
    } catch (error) {
        console.error('Failed to log security event:', error);
    }
}

// ===== WebDAV配置管理 =====
async function saveWebDAVConfigToKV(configs, env) {
    try {
        await env.USER_DATA.put('webdav_configs', JSON.stringify(configs));
        return true;
    } catch (error) {
        console.error('Failed to save WebDAV configs:', error);
        return false;
    }
}

async function loadWebDAVConfigsFromKV(env) {
    try {
        const configs = await env.USER_DATA.get('webdav_configs');
        return configs ? JSON.parse(configs) : [];
    } catch (error) {
        console.error('Failed to load WebDAV configs:', error);
        return [];
    }
}

async function loadWebDAVConfigFromKV(env) {
    try {
        // 向后兼容：先尝试加载单个配置
        const singleConfig = await env.USER_DATA.get('webdav_config');
        if (singleConfig) {
            const config = JSON.parse(singleConfig);
            const configs = [{
                id: 'default',
                name: 'Default WebDAV',
                ...config,
                isActive: true
            }];
            await saveWebDAVConfigToKV(configs, env);
            await env.USER_DATA.delete('webdav_config');
            return config;
        }
        
        const configs = await loadWebDAVConfigsFromKV(env);
        const activeConfig = configs.find(c => c.isActive);
        return activeConfig || null;
    } catch (error) {
        console.error('Failed to load WebDAV config:', error);
        return null;
    }
}

// ===== Base32编解码 =====
function base32Encode(buffer) {
    let result = '';
    let bits = 0;
    let value = 0;
    
    for (let i = 0; i < buffer.length; i++) {
        value = (value << 8) | buffer[i];
        bits += 8;
        
        while (bits >= 5) {
            result += BASE32_CHARS[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    
    if (bits > 0) {
        result += BASE32_CHARS[(value << (5 - bits)) & 31];
    }
    
    return result;
}

function base32Decode(encoded) {
    const cleanInput = encoded.toUpperCase().replace(/[^A-Z2-7]/g, '');
    const buffer = new Uint8Array(Math.floor(cleanInput.length * 5 / 8));
    let bits = 0;
    let value = 0;
    let index = 0;
    
    for (let i = 0; i < cleanInput.length; i++) {
        const char = cleanInput[i];
        const charValue = BASE32_CHARS.indexOf(char);
        
        if (charValue === -1) continue;
        
        value = (value << 5) | charValue;
        bits += 5;
        
        if (bits >= 8) {
            buffer[index++] = (value >>> (bits - 8)) & 255;
            bits -= 8;
        }
    }
    
    return buffer;
}

async function hmacSHA1(key, data) {
    const keyBuffer = typeof key === 'string' ? new TextEncoder().encode(key) : key;
    const dataBuffer = new ArrayBuffer(8);
    const view = new DataView(dataBuffer);
    view.setBigUint64(0, BigInt(data), false);
    
    const cryptoKey = await crypto.subtle.importKey('raw', keyBuffer, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, dataBuffer);
    return new Uint8Array(signature);
}

async function generateTOTP(secret, timeStep = 30, digits = 6) {
    const time = Math.floor(Date.now() / 1000 / timeStep);
    const secretBytes = typeof secret === 'string' ? base32Decode(secret) : secret;
    
    const hmac = await hmacSHA1(secretBytes, time);
    const offset = hmac[hmac.length - 1] & 0xf;
    
    const code = (
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff)
    ) % Math.pow(10, digits);
    
    return code.toString().padStart(digits, '0');
}

// ===== JWT 功能 =====
async function generateSecureJWT(payload, secret) {
    const header = { alg: 'HS256', typ: 'JWT', iat: Math.floor(Date.now() / 1000) };
    const enhancedPayload = {
        ...payload,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + SECURITY_CONFIG.JWT_EXPIRY,
        jti: crypto.randomUUID()
    };
    
    const headerB64 = btoa(JSON.stringify(header)).replace(/[+/=]/g, (m) => ({'+':'-','/':'_','=':''}[m]));
    const payloadB64 = btoa(JSON.stringify(enhancedPayload)).replace(/[+/=]/g, (m) => ({'+':'-','/':'_','=':''}[m]));
    
    const data = `${headerB64}.${payloadB64}`;
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    
    const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(data));
    const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/[+/=]/g, (m) => ({'+':'-','/':'_','=':''}[m]));
    
    return `${data}.${signatureB64}`;
}

async function verifySecureJWT(token, secret) {
    try {
        const [headerB64, payloadB64, signatureB64] = token.split('.');
        const data = `${headerB64}.${payloadB64}`;
        
        const encoder = new TextEncoder();
        const keyData = encoder.encode(secret);
        
        const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
        const signature = Uint8Array.from(atob(signatureB64.replace(/[-_]/g, (m) => ({'-':'+','_':'/'}[m]))), c => c.charCodeAt(0));
        const isValid = await crypto.subtle.verify('HMAC', cryptoKey, signature, encoder.encode(data));
        
        if (isValid) {
            const payload = JSON.parse(atob(payloadB64.replace(/[-_]/g, (m) => ({'-':'+','_':'/'}[m]))));
            if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
            return payload;
        }
        return null;
    } catch {
        return null;
    }
}

async function getAuthenticatedUser(request, env) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
    
    const token = authHeader.substring(7);
    const payload = await verifySecureJWT(token, env.JWT_SECRET);
    
    return payload?.userInfo || null;
}

// ===== OAuth相关函数 =====
async function fetchOAuthUser(accessToken, oauthBaseUrl) {
    try {
        const response = await fetch(`${oauthBaseUrl}/api/user`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/json',
                'User-Agent': '2FA-Manager/1.0'
            },
            timeout: SECURITY_CONFIG.OAUTH_TIMEOUT
        });
        
        if (!response.ok) {
            throw new OAuthError(`Failed to fetch user info: ${response.status}`, 'FETCH_USER_FAILED');
        }
        
        return await response.json();
    } catch (error) {
        if (error instanceof OAuthError) throw error;
        throw new OAuthError(`OAuth user fetch error: ${error.message}`, 'NETWORK_ERROR');
    }
}

// ===== 解析 TOTP URI =====
function parseOTPAuthURI(uri) {
    try {
        if (!uri || typeof uri !== 'string' || uri.length > 1000) return null;
        
        const url = new URL(uri);
        if (url.protocol !== 'otpauth:') return null;
        
        const type = url.hostname;
        if (type !== 'totp' && type !== 'hotp') return null;
        
        const label = decodeURIComponent(url.pathname.substring(1));
        const params = new URLSearchParams(url.search);
        
        const secret = params.get('secret');
        if (!validateBase32Secret(secret)) return null;
        
        const [issuer, account] = label.includes(':') ? label.split(':', 2) : ['', label];
        const digits = parseInt(params.get('digits')) || 6;
        const period = parseInt(params.get('period')) || 30;
        
        if (digits < 6 || digits > 8 || period < 15 || period > 300) return null;
        
        return {
            type,
            label: sanitizeInput(label, 100),
            issuer: sanitizeInput(params.get('issuer') || issuer, 50),
            account: sanitizeInput(account || label, 100),
            secret: secret,
            algorithm: (params.get('algorithm') || 'SHA1').toUpperCase(),
            digits,
            period,
            counter: parseInt(params.get('counter')) || 0
        };
    } catch {
        return null;
    }
}

// ===== CORS 配置 =====
function getCorsHeaders(request, env) {
    const origin = request.headers.get('Origin');
    const allowedOrigins = env.ALLOWED_ORIGINS ? env.ALLOWED_ORIGINS.split(',') : ['*'];
    
    if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
        return {
            'Access-Control-Allow-Origin': origin || '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Max-Age': '86400',
            'Vary': 'Origin'
        };
    }
    
    return {
        'Access-Control-Allow-Origin': 'null',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    };
}

// ===== OAuth授权URL构建 =====
async function handleOAuthAuthorize(request, env) {
    if (request.method !== 'GET') {
        return new Response('Method not allowed', { status: 405 });
    }
    
    try {
        const state = crypto.randomUUID();
        const params = new URLSearchParams({
            response_type: 'code',
            client_id: env.OAUTH_CLIENT_ID,
            redirect_uri: env.OAUTH_REDIRECT_URI,
            state: state
        });
        
        const authUrl = `${env.OAUTH_BASE_URL}/oauth2/authorize?${params}`;
        
        return new Response(null, {
            status: 302,
            headers: {
                'Location': authUrl,
                'Set-Cookie': `oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
            }
        });
    } catch (error) {
        console.error('OAuth authorize error:', error);
        return new Response(`OAuth configuration error: ${error.message}`, { status: 500 });
    }
}

// ===== OAuth回调处理 =====
async function handleOAuthCallback(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    
    if (!['GET', 'POST'].includes(request.method)) {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    
    try {
        await checkOAuthAttempts(clientIP);
        
        let code, state;
        
        if (request.method === 'GET') {
            const url = new URL(request.url);
            code = url.searchParams.get('code');
            state = url.searchParams.get('state');
            
            if (code && state) {
                return new Response(getOAuthCallbackPage(code, state), {
                    status: 200,
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            }

            const error = url.searchParams.get('error');
            if (error) {
                return new Response(getOAuthErrorPage(error, url.searchParams.get('error_description')), {
                    status: 400,
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            }

            return new Response(getOAuthInvalidPage(), {
                status: 400,
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
        } else if (request.method === 'POST') {
            const body = await request.json();
            code = body.code;
            state = body.state;
            
            if (!code || !state) {
                await recordOAuthAttempt(clientIP, false);
                await logSecurityEvent('OAUTH_FAILED', 'Missing code or state in POST request', request);
                
                return new Response(JSON.stringify({ error: 'Missing code or state parameters' }), {
                    status: 400,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            return await processOAuthCode(code, state, clientIP, request, env, corsHeaders);
        }
    } catch (error) {
        console.error('OAuth callback error:', error);
        await recordOAuthAttempt(clientIP, false);
        await logSecurityEvent('OAUTH_ERROR', { error: error.message }, request);
        
        if (error instanceof OAuthError && error.code === 'LOCKED') {
            return new Response(JSON.stringify({ error: error.message }), {
                status: 429,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        return new Response(JSON.stringify({ 
            error: 'OAuth authentication failed',
            message: 'Internal server error',
            details: error.message
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// OAuth页面模板
function getOAuthCallbackPage(code, state) {
    return `<!DOCTYPE html>
<html><head><title>OAuth授权处理中</title><meta charset="UTF-8">
<style>body{font-family:Arial,sans-serif;text-align:center;padding:50px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;min-height:100vh;margin:0;display:flex;flex-direction:column;justify-content:center;align-items:center}.container{background:rgba(255,255,255,0.95);color:#333;padding:2rem;border-radius:16px;box-shadow:0 20px 40px rgba(0,0,0,0.1);max-width:400px;width:100%}.loading{margin:20px 0;font-size:1.1rem}.spinner{width:40px;height:40px;border:4px solid #f3f3f3;border-top:4px solid #667eea;border-radius:50%;animation:spin 1s linear infinite;margin:20px auto}@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}.error{color:#dc3545;margin:20px 0;padding:1rem;background:rgba(220,53,69,0.1);border-radius:8px;border:1px solid rgba(220,53,69,0.3)}</style>
</head><body><div class="container"><h1>🔐 OAuth授权处理中</h1><div class="spinner"></div><div class="loading">正在验证授权信息...</div><div id="errorMsg" class="error" style="display:none;"></div></div>
<script>async function processOAuthCallback(){try{const response=await fetch('/api/oauth/callback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:'${code}',state:'${state}'})});const data=await response.json();if(response.ok&&data.success){localStorage.setItem('authToken',data.token);localStorage.setItem('userInfo',JSON.stringify(data.userInfo));localStorage.setItem('loginTime',Date.now().toString());document.querySelector('.loading').innerHTML='✅ 授权成功！正在跳转...';document.querySelector('.spinner').style.display='none';setTimeout(()=>{window.location.href='/'},1000)}else{throw new Error(data.error||'授权验证失败')}}catch(error){console.error('OAuth callback error:',error);document.querySelector('.spinner').style.display='none';document.querySelector('.loading').style.display='none';const errorDiv=document.getElementById('errorMsg');errorDiv.textContent='❌ 授权失败：'+error.message;errorDiv.style.display='block';setTimeout(()=>{window.location.href='/?error='+encodeURIComponent(error.message)},3000)}}document.addEventListener('DOMContentLoaded',processOAuthCallback)</script>
</body></html>`;
}

function getOAuthErrorPage(error, errorDescription) {
    return `<!DOCTYPE html>
<html><head><title>OAuth授权失败</title><meta charset="UTF-8">
<style>body{font-family:Arial,sans-serif;text-align:center;padding:50px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;min-height:100vh;margin:0;display:flex;flex-direction:column;justify-content:center;align-items:center}.container{background:rgba(255,255,255,0.95);color:#333;padding:2rem;border-radius:16px;box-shadow:0 20px 40px rgba(0,0,0,0.1);max-width:400px;width:100%}.error{color:#dc3545;margin:20px 0;padding:1rem;background:rgba(220,53,69,0.1);border-radius:8px;border:1px solid rgba(220,53,69,0.3)}.btn{background:#007bff;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;display:inline-block;margin-top:1rem}</style>
</head><body><div class="container"><h1>❌ OAuth授权失败</h1><div class="error">错误: ${error}</div>${errorDescription ? `<div class="error">详情: ${errorDescription}</div>` : ''}<a href="/" class="btn">返回首页</a></div>
<script>setTimeout(()=>{window.location.href='/?error='+encodeURIComponent('${error}')},5000)</script>
</body></html>`;
}

function getOAuthInvalidPage() {
    return `<!DOCTYPE html>
<html><head><title>无效的OAuth回调</title><meta charset="UTF-8">
<style>body{font-family:Arial,sans-serif;text-align:center;padding:50px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;min-height:100vh;margin:0;display:flex;flex-direction:column;justify-content:center;align-items:center}.container{background:rgba(255,255,255,0.95);color:#333;padding:2rem;border-radius:16px;box-shadow:0 20px 40px rgba(0,0,0,0.1);max-width:400px;width:100%}.btn{background:#007bff;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;display:inline-block;margin-top:1rem}</style>
</head><body><div class="container"><h1>⚠️ 无效的OAuth回调</h1><p>缺少必要的授权参数</p><a href="/" class="btn">返回首页</a></div>
<script>setTimeout(()=>{window.location.href='/'},3000)</script>
</body></html>`;
}

// OAuth代码处理逻辑
async function processOAuthCode(code, state, clientIP, request, env, corsHeaders) {
    try {
        if (!code || !state || typeof code !== 'string' || typeof state !== 'string') {
            await recordOAuthAttempt(clientIP, false);
            await logSecurityEvent('OAUTH_FAILED', 'Invalid parameters', request);
            
            return new Response(JSON.stringify({ error: 'Invalid OAuth parameters' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        // 验证state参数
        const cookies = request.headers.get('Cookie') || '';
        const stateCookie = cookies.split(';').find(c => c.trim().startsWith('oauth_state='))?.split('=')[1];
        
        if (state !== stateCookie) {
            await recordOAuthAttempt(clientIP, false);
            await logSecurityEvent('OAUTH_FAILED', 'State mismatch', request);
            
            return new Response(JSON.stringify({ error: 'Invalid state parameter' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        // 获取访问令牌
        const tokenResponse = await fetch(`${env.OAUTH_BASE_URL}/oauth2/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json',
                'User-Agent': '2FA-Manager/1.0'
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: env.OAUTH_CLIENT_ID,
                client_secret: env.OAUTH_CLIENT_SECRET,
                code: code,
                redirect_uri: env.OAUTH_REDIRECT_URI
            })
        });
        
        if (!tokenResponse.ok) {
            const errorText = await tokenResponse.text();
            throw new OAuthError(`Token exchange failed: ${tokenResponse.status} - ${errorText}`, 'TOKEN_EXCHANGE_FAILED');
        }
        
        const tokenData = await tokenResponse.json();
        if (!tokenData.access_token) {
            throw new OAuthError('No access token received', 'NO_ACCESS_TOKEN');
        }
        
        // 获取用户信息
        const userData = await fetchOAuthUser(tokenData.access_token, env.OAUTH_BASE_URL);
        
        // 验证用户ID
        if (!userData.id || userData.id.toString() !== env.OAUTH_ID) {
            await recordOAuthAttempt(clientIP, false);
            await logSecurityEvent('OAUTH_UNAUTHORIZED', { 
                userId: userData.id, 
                username: userData.username,
                expectedId: env.OAUTH_ID
            }, request);
            
            return new Response(JSON.stringify({ error: 'Unauthorized user' }), {
                status: 403,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        // 生成JWT令牌
        const payload = {
            userInfo: {
                id: userData.id,
                username: userData.username,
                nickname: userData.nickname,
                email: userData.email,
                avatar_template: userData.avatar_template
            },
            ip: clientIP,
            loginMethod: 'oauth',
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + SECURITY_CONFIG.JWT_EXPIRY
        };
        
        const token = await generateSecureJWT(payload, env.JWT_SECRET);
        
        await recordOAuthAttempt(clientIP, true);
        await logSecurityEvent('OAUTH_SUCCESS', { 
            userId: userData.id, 
            username: userData.username 
        }, request);
        
        return new Response(JSON.stringify({
            success: true,
            token,
            userInfo: payload.userInfo,
            message: 'OAuth login successful'
        }), {
            status: 200,
            headers: { 
                ...corsHeaders, 
                'Content-Type': 'application/json',
                'Set-Cookie': 'oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
            }
        });
    } catch (error) {
        console.error('Process OAuth code error:', error);
        throw error;
    }
}

// ===== HTML 页面（压缩版） =====
function getMainHTML() {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://jsdelivr.b-cdn.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self';">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">

    <title>🔐 2FA 安全管理系统</title>
<style>
/* 基础重置和全局样式 */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    line-height: 1.6;
    color: #1a1a1a;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}

/* 容器和布局 */
.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

/* 头部样式 */
header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    color: white;
    flex-wrap: wrap;
    gap: 1rem;
}

header h1 {
    font-size: 2.5rem;
    font-weight: 700;
    text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
    letter-spacing: -0.5px;
}

/* 安全指示器 */
.security-indicator {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    background: rgba(255, 255, 255, 0.15);
    padding: 0.5rem 1rem;
    border-radius: 25px;
    font-size: 0.875rem;
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.2);
}

.security-indicator.secure {
    background: rgba(72, 187, 120, 0.25);
    border: 1px solid rgba(72, 187, 120, 0.4);
}

/* 用户信息 */
.user-info {
    display: flex;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
}

.user-profile {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    background: rgba(255, 255, 255, 0.15);
    padding: 0.5rem 1rem;
    border-radius: 25px;
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.2);
}

.user-avatar {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    border: 2px solid rgba(255, 255, 255, 0.3);
    object-fit: cover;
}

.user-details {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
}

.user-name {
    font-weight: 600;
    font-size: 0.9rem;
    color: white;
}

.user-email {
    font-size: 0.75rem;
    color: rgba(255, 255, 255, 0.8);
}

/* 卡片样式 */
.card {
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(20px);
    border-radius: 16px;
    padding: 2rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1), 0 8px 16px rgba(0, 0, 0, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.2);
    animation: fadeIn 0.6s ease-out;
}

/* 标签页 */
.nav-tabs {
    display: flex;
    margin-bottom: 1rem;
    background: rgba(255, 255, 255, 0.9);
    backdrop-filter: blur(20px);
    border-radius: 16px;
    padding: 0.5rem;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
    flex-wrap: wrap;
    gap: 0.25rem;
}

.tab-btn {
    flex: 1;
    min-width: 120px;
    padding: 0.875rem 1.25rem;
    border: none;
    background: transparent;
    cursor: pointer;
    border-radius: 12px;
    font-weight: 600;
    font-size: 0.9rem;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    color: #64748b;
    position: relative;
    overflow: hidden;
}

.tab-btn::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    opacity: 0;
    transition: opacity 0.3s ease;
    z-index: -1;
}

.tab-btn.active {
    color: white;
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
}

.tab-btn.active::before {
    opacity: 1;
}

.tab-btn:hover:not(.active) {
    background: rgba(102, 126, 234, 0.1);
    color: #667eea;
}

.tab-content {
    display: none;
}

.tab-content.active {
    display: block;
}

/* 按钮样式 */
.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 0.875rem 1.5rem;
    border: none;
    border-radius: 12px;
    font-size: 1rem;
    font-weight: 600;
    text-decoration: none;
    cursor: pointer;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    text-align: center;
    margin: 0.25rem;
    position: relative;
    overflow: hidden;
    min-height: 44px;
}

.btn::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(45deg, rgba(255, 255, 255, 0.1), rgba(255, 255, 255, 0.05));
    opacity: 0;
    transition: opacity 0.3s ease;
}

.btn:hover::before {
    opacity: 1;
}

.btn-primary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(102, 126, 234, 0.4);
}

.btn-secondary {
    background: linear-gradient(135deg, #64748b 0%, #475569 100%);
    color: white;
}

.btn-success {
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    color: white;
}

.btn-danger {
    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
    color: white;
}

.btn-warning {
    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
    color: white;
}

.btn-small {
    padding: 0.625rem 1rem;
    font-size: 0.875rem;
    min-height: 36px;
}

/* OAuth 登录 */
.oauth-login-card {
    text-align: center;
    max-width: 400px;
    margin: 0 auto;
}

.oauth-login-btn {
    width: 100%;
    padding: 1rem 1.5rem;
    font-size: 1.1rem;
    margin: 1rem 0;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.75rem;
    background: linear-gradient(135deg, #4285f4 0%, #34a853 100%);
    color: white;
    border: none;
    border-radius: 12px;
    cursor: pointer;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    box-shadow: 0 4px 15px rgba(66, 133, 244, 0.3);
}

.oauth-login-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(66, 133, 244, 0.4);
}

.oauth-icon {
    font-size: 1.5rem;
}

/* GitHub 链接 */
.github-link {
    margin-top: 15px;
    text-align: center;
}

.github-link a {
    color: #666;
    text-decoration: none;
    font-size: 14px;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    transition: color 0.3s ease;
}

.github-link a:hover {
    color: #333;
}

/* 表单样式 */
.form-group {
    margin-bottom: 1.5rem;
}

.form-group label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 600;
    color: #374151;
    font-size: 0.95rem;
}

.form-group input,
.form-group select,
.form-group textarea {
    width: 100%;
    padding: 0.875rem 1rem;
    border: 2px solid #e5e7eb;
    border-radius: 12px;
    font-size: 1rem;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    background: rgba(255, 255, 255, 0.8);
    backdrop-filter: blur(10px);
}

.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.1);
    background: rgba(255, 255, 255, 0.95);
}

/* 搜索部分 */
.search-section {
    display: flex;
    gap: 1rem;
    align-items: center;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
}

.search-input {
    flex: 1;
    min-width: 250px;
    padding: 0.875rem 1rem;
    border: 2px solid #e5e7eb;
    border-radius: 12px;
    font-size: 1rem;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    background: rgba(255, 255, 255, 0.9);
    backdrop-filter: blur(10px);
}

.search-input:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.1);
}

/* 账户网格 */
.accounts-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1.5rem;
    margin-top: 1rem;
}

.account-card {
    background: rgba(255, 255, 255, 0.9);
    backdrop-filter: blur(20px);
    border: 1px solid rgba(255, 255, 255, 0.3);
    border-radius: 16px;
    padding: 1.5rem;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    position: relative;
    overflow: hidden;
}

.account-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(135deg, rgba(102, 126, 234, 0.05) 0%, rgba(118, 75, 162, 0.05) 100%);
    opacity: 0;
    transition: opacity 0.3s ease;
    pointer-events: none;
}

.account-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.15);
    border-color: rgba(102, 126, 234, 0.3);
}

.account-card:hover::before {
    opacity: 1;
}

.account-card.filtered {
    display: none;
}

.account-header {
    margin-bottom: 1rem;
}

.service-name {
    color: #1f2937;
    font-size: 1.1rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.5rem;
}

.category-tag {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 0.25rem 0.75rem;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}

.account-info-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
}

.account-identifier {
    color: #6b7280;
    font-size: 0.875rem;
    flex: 1;
    word-break: break-all;
    font-weight: 500;
}

.account-actions {
    display: flex;
    gap: 0.5rem;
    flex-shrink: 0;
}

.action-btn {
    padding: 0.5rem;
    border: none;
    border-radius: 8px;
    font-size: 0.875rem;
    cursor: pointer;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    min-width: 36px;
    height: 36px;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
    overflow: hidden;
}

.action-btn::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(255, 255, 255, 0.2);
    opacity: 0;
    transition: opacity 0.3s ease;
}

.action-btn:hover::before {
    opacity: 1;
}

.action-btn:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.action-btn.copy {
    background: linear-gradient(135deg, #64748b 0%, #475569 100%);
    color: white;
}

.action-btn.edit {
    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
    color: white;
}

.action-btn.delete {
    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
    color: white;
}

/* TOTP 验证码 */
.totp-code {
    font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
    font-size: 2rem;
    font-weight: 700;
    color: #1f2937;
    text-align: center;
    margin: 1rem 0;
    letter-spacing: 0.25em;
    cursor: pointer;
    padding: 1rem;
    border-radius: 12px;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    background: linear-gradient(135deg, #f8fafc, #e2e8f0);
    border: 2px solid transparent;
    position: relative;
    overflow: hidden;
}

.totp-code::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
    opacity: 0;
    transition: opacity 0.3s ease;
}

.totp-code:hover {
    background: linear-gradient(135deg, #e2e8f0, #cbd5e0);
    border-color: #667eea;
    transform: scale(1.02);
}

.totp-code:hover::before {
    opacity: 1;
}

.totp-code.hidden-code {
    color: #9ca3af;
    font-size: 1.25rem;
}

.totp-code.hidden-code:before {
    content: "点击显示验证码";
    position: static;
    background: none;
}

/* 浮动消息 */
.floating-message {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    padding: 1rem 1.5rem;
    z-index: 10000;
    transform: translateY(-100%);
    opacity: 0;
    transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
    backdrop-filter: blur(20px);
    font-weight: 600;
    text-align: center;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
    border-bottom: 3px solid;
}

.floating-message.show {
    transform: translateY(0);
    opacity: 1;
}

.floating-message.success {
    background: rgba(240, 253, 244, 0.95);
    border-color: #10b981;
    color: #065f46;
}

.floating-message.error {
    background: rgba(254, 242, 242, 0.95);
    border-color: #ef4444;
    color: #991b1b;
}

.floating-message.warning {
    background: rgba(255, 251, 235, 0.95);
    border-color: #f59e0b;
    color: #92400e;
}

/* 模态框 */
.modal {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 1000;
    backdrop-filter: blur(8px);
    padding: 1rem;
}

.modal-content {
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(20px);
    border-radius: 20px;
    padding: 2rem;
    max-width: 500px;
    width: 100%;
    max-height: 80vh;
    overflow-y: auto;
    box-shadow: 0 25px 50px rgba(0, 0, 0, 0.25);
    border: 1px solid rgba(255, 255, 255, 0.2);
    animation: modalSlideIn 0.4s cubic-bezier(0.4, 0, 0.2, 1);
}

.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
}

.modal-close {
    background: none;
    border: none;
    font-size: 1.5rem;
    cursor: pointer;
    color: #6b7280;
    padding: 0.5rem;
    border-radius: 50%;
    transition: all 0.3s ease;
    width: 40px;
    height: 40px;
    display: flex;
    align-items: center;
    justify-content: center;
}

.modal-close:hover {
    background: rgba(107, 114, 128, 0.1);
    color: #374151;
    transform: scale(1.1);
}

/* 工具类 */
.hidden {
    display: none !important;
}

.session-timer {
    background: rgba(0, 0, 0, 0.8);
    color: white;
    padding: 0.5rem 1rem;
    border-radius: 20px;
    font-size: 0.875rem;
    white-space: nowrap;
    font-weight: 600;
    backdrop-filter: blur(10px);
}

.session-timer.warning {
    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
    animation: pulse 2s infinite;
}

/* 导入选项 */
.import-options {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1rem;
    margin-top: 1rem;
}

.import-card {
    border: 2px solid #e5e7eb;
    border-radius: 16px;
    padding: 1.5rem;
    text-align: center;
    cursor: pointer;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    background: rgba(255, 255, 255, 0.5);
    backdrop-filter: blur(10px);
    position: relative;
    overflow: hidden;
}

.import-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
    opacity: 0;
    transition: opacity 0.3s ease;
}

.import-card:hover {
    border-color: #667eea;
    background: rgba(255, 255, 255, 0.8);
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
}

.import-card:hover::before {
    opacity: 1;
}

.import-card h4 {
    margin-bottom: 0.5rem;
    color: #1f2937;
    font-weight: 700;
}

.import-card p {
    color: #6b7280;
    font-size: 0.875rem;
    line-height: 1.5;
}

/* 安全提示 */
.security-notice {
    background: rgba(255, 243, 205, 0.8);
    border: 1px solid #fbbf24;
    border-radius: 12px;
    padding: 1rem;
    margin-bottom: 1rem;
    backdrop-filter: blur(10px);
}

.security-notice.info {
    background: rgba(219, 234, 254, 0.8);
    border-color: #60a5fa;
}

/* 密码输入组 */
.password-input-group {
    position: relative;
}

.password-toggle {
    position: absolute;
    right: 12px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    cursor: pointer;
    color: #6b7280;
    padding: 0.5rem;
    border-radius: 6px;
    transition: all 0.3s ease;
}

.password-toggle:hover {
    color: #374151;
    background: rgba(107, 114, 128, 0.1);
}

/* 文件上传 */
.file-upload {
    border: 2px dashed #d1d5db;
    border-radius: 12px;
    padding: 2rem;
    text-align: center;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    cursor: pointer;
    margin: 1rem 0;
    background: rgba(255, 255, 255, 0.5);
    backdrop-filter: blur(10px);
}

.file-upload:hover {
    border-color: #667eea;
    background: rgba(102, 126, 234, 0.05);
}

.file-upload.dragover {
    border-color: #667eea;
    background: rgba(102, 126, 234, 0.1);
}

/* QR 扫描器 */
.qr-scanner {
    position: relative;
    width: 100%;
    max-width: 400px;
    margin: 0 auto;
}

#qr-video {
    width: 100%;
    border-radius: 12px;
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
}

.scanner-overlay {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 200px;
    height: 200px;
    border: 3px solid #667eea;
    border-radius: 12px;
    pointer-events: none;
    box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.2);
}

.scanner-overlay::before {
    content: '';
    position: absolute;
    top: -3px;
    left: -3px;
    right: -3px;
    bottom: -3px;
    border: 3px solid rgba(102, 126, 234, 0.5);
    border-radius: 12px;
    animation: pulse 2s infinite;
}

/* WebDAV 配置 */
.webdav-config {
    background: rgba(248, 250, 252, 0.8);
    border: 1px solid #e5e7eb;
    border-radius: 16px;
    padding: 1.5rem;
    margin-top: 1rem;
    backdrop-filter: blur(10px);
}

.webdav-accounts {
    margin-bottom: 1.5rem;
}

.webdav-account-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    margin-bottom: 0.5rem;
    background: rgba(255, 255, 255, 0.8);
    backdrop-filter: blur(10px);
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.webdav-account-item:hover {
    border-color: #667eea;
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.webdav-account-item.active {
    border-color: #10b981;
    background: rgba(240, 253, 244, 0.8);
}

.webdav-account-info {
    flex: 1;
}

.webdav-account-name {
    font-weight: 700;
    color: #1f2937;
    margin-bottom: 0.25rem;
}

.webdav-account-url {
    font-size: 0.875rem;
    color: #6b7280;
}

.webdav-account-actions {
    display: flex;
    gap: 0.5rem;
}

/* 表单行 */
.form-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
}

/* 备份列表 */
.backup-list {
    margin-top: 1rem;
}

.backup-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    margin-bottom: 0.5rem;
    background: rgba(255, 255, 255, 0.8);
    backdrop-filter: blur(10px);
    transition: all 0.3s ease;
}

.backup-item:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.backup-info {
    flex: 1;
}

.backup-filename {
    font-weight: 700;
    color: #1f2937;
}

.backup-meta {
    font-size: 0.875rem;
    color: #6b7280;
    margin-top: 0.25rem;
}

.backup-actions {
    display: flex;
    gap: 0.5rem;
}

/* 代码模态框 */
.code-modal {
    text-align: center;
}

.code-display {
    font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
    font-size: 3rem;
    font-weight: 700;
    color: #1f2937;
    margin: 2rem 0;
    letter-spacing: 0.3em;
    padding: 1.5rem;
    background: linear-gradient(135deg, #f8fafc, #e2e8f0);
    border-radius: 16px;
    border: 3px solid #667eea;
    position: relative;
    overflow: hidden;
}

.code-display::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
    animation: shimmer 2s infinite;
}

.code-info {
    color: #6b7280;
    font-size: 0.875rem;
    margin-bottom: 1rem;
    font-weight: 500;
}

.auto-copy-notice {
    color: #10b981;
    font-size: 0.875rem;
    margin-top: 1rem;
    font-weight: 600;
}

/* 调试信息 */
.debug-info {
    background: rgba(248, 250, 252, 0.9);
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    padding: 1rem;
    margin-top: 1rem;
    font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
    font-size: 0.875rem;
    max-height: 400px;
    overflow-y: auto;
    backdrop-filter: blur(10px);
}

/* 进度条 */
.progress-container {
    margin-top: 1rem;
    padding: 0.75rem;
    background: rgba(248, 250, 252, 0.8);
    border-radius: 12px;
    backdrop-filter: blur(10px);
}

.progress-label {
    font-size: 0.875rem;
    color: #6b7280;
    margin-bottom: 0.5rem;
    font-weight: 600;
}

.progress-bar {
    width: 100%;
    height: 6px;
    background: #e5e7eb;
    border-radius: 3px;
    overflow: hidden;
    position: relative;
}

.progress-fill {
    height: 100%;
    background: linear-gradient(90deg, #10b981, #059669);
    transition: width 1s linear;
    border-radius: 3px;
}

.progress-fill.warning {
    background: linear-gradient(90deg, #f59e0b, #d97706);
}

.progress-fill.danger {
    background: linear-gradient(90deg, #ef4444, #dc2626);
}

/* 响应式设计 - 平板 */
@media (max-width: 768px) {
    .container {
        padding: 15px;
    }

    header {
        flex-direction: column;
        gap: 1rem;
        text-align: center;
    }

    header h1 {
        font-size: 2rem;
    }

    .card {
        padding: 1.5rem;
        margin-bottom: 1rem;
    }

    .nav-tabs {
        flex-direction: column;
        gap: 0.5rem;
        padding: 0.75rem;
    }

    .tab-btn {
        min-width: auto;
        width: 100%;
        padding: 1rem 1.25rem;
        font-size: 1rem;
        border-radius: 14px;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 0.5rem;
    }

    .tab-btn::after {
        content: '';
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: currentColor;
        opacity: 0;
        transition: opacity 0.3s ease;
    }

    .tab-btn.active::after {
        opacity: 1;
    }

    .accounts-grid {
        grid-template-columns: 1fr;
        gap: 1rem;
    }

    .totp-code {
        font-size: 1.5rem;
        letter-spacing: 0.2em;
        padding: 0.75rem;
    }

    .search-section {
        flex-direction: column;
        align-items: stretch;
    }

    .search-input {
        min-width: auto;
    }

    .account-info-row {
        flex-direction: column;
        align-items: stretch;
        gap: 0.75rem;
    }

    .account-actions {
        justify-content: center;
        flex-wrap: wrap;
    }

    .form-row {
        grid-template-columns: 1fr;
    }

    .user-info {
        justify-content: center;
        text-align: center;
        flex-wrap: wrap;
    }

    .user-profile {
        flex-direction: column;
        text-align: center;
        padding: 0.75rem 1rem;
    }

    .user-details {
        align-items: center;
    }

    .backup-item {
        flex-direction: column;
        align-items: stretch;
        gap: 1rem;
    }

    .backup-actions {
        justify-content: center;
    }

    .code-display {
        font-size: 2rem;
        letter-spacing: 0.2em;
    }

    .webdav-account-item {
        flex-direction: column;
        align-items: stretch;
        gap: 1rem;
    }

    .webdav-account-actions {
        justify-content: center;
    }

    .modal {
        padding: 0.5rem;
    }

    .modal-content {
        padding: 1.5rem;
        margin: 0.5rem;
    }

    .import-options {
        grid-template-columns: 1fr;
    }

    .btn {
        padding: 0.75rem 1.25rem;
        font-size: 0.9rem;
    }

    .btn-small {
        padding: 0.5rem 0.875rem;
        font-size: 0.8rem;
    }

    .oauth-login-btn {
        padding: 1.25rem 1.5rem;
        font-size: 1rem;
    }
}

/* 响应式设计 - 手机 */
@media (max-width: 480px) {
    .container {
        padding: 10px;
    }

    header h1 {
        font-size: 1.75rem;
    }

    .card {
        padding: 1rem;
    }

    .nav-tabs {
        padding: 0.5rem;
        gap: 0.375rem;
    }

    .tab-btn {
        padding: 0.875rem 1rem;
        font-size: 0.9rem;
    }

    .totp-code {
        font-size: 1.25rem;
    }

    .code-display {
        font-size: 1.75rem;
    }

    .account-card {
        padding: 1rem;
    }

    .action-btn {
        min-width: 32px;
        height: 32px;
        font-size: 0.8rem;
    }

    .user-avatar {
        width: 28px;
        height: 28px;
    }
}

/* 动画效果 */
@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@keyframes modalSlideIn {
    from {
        opacity: 0;
        transform: scale(0.9) translateY(-20px);
    }
    to {
        opacity: 1;
        transform: scale(1) translateY(0);
    }
}

@keyframes pulse {
    0%, 100% {
        opacity: 1;
        transform: scale(1);
    }
    50% {
        opacity: 0.7;
        transform: scale(1.05);
    }
}

@keyframes shimmer {
    0% {
        transform: translateX(-100%);
    }
    100% {
        transform: translateX(100%);
    }
}

/* 滚动条样式 */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

::-webkit-scrollbar-track {
    background: rgba(0, 0, 0, 0.1);
    border-radius: 4px;
}

::-webkit-scrollbar-thumb {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
    background: linear-gradient(135deg, #5a6fd8 0%, #6d4193 100%);
}
</style>


</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 2FA 安全管理系统</h1>
            <div id="userInfo" class="user-info hidden">
                <div class="security-indicator secure">
                    <span>🛡️</span>
                    <span>安全连接</span>
                </div>
                <div class="session-timer" id="sessionTimer">
                    会话剩余: <span id="sessionTimeLeft">2:00:00</span>
                </div>
                <div class="user-profile" id="userProfile">
                    <img id="userAvatar" class="user-avatar" src="" alt="用户头像">
                    <div class="user-details">
                        <div class="user-name" id="userName"></div>
                        <div class="user-email" id="userEmail"></div>
                    </div>
                </div>
                <button onclick="clearAllAccounts()" class="btn btn-danger btn-small">清空账号</button>
                <button onclick="logout()" class="btn btn-small">安全退出</button>
            </div>
        </header>
        
        <main>
            <div id="loginSection" class="card">
                <div class="oauth-login-card">
                    <h2>🔐 安全登录</h2>
                    <p style="color: #6b7280; margin: 1rem 0;">使用第三方授权登录系统</p>
                    
		<button onclick="startOAuthLogin()" class="oauth-login-btn">
		    <span class="oauth-icon">
		        <img src="https://linux.do/logo-256.svg" 
		             alt="Logo" 
		             style="width: 40px; height: 40px; object-fit: contain;">
		    </span>
		    <span>使用Linux.do账号登录</span>
		</button>
		
		<!-- GitHub 开源仓库链接 -->
		<div class="github-link">
		    <a href="https://github.com/ilikeeu/2fauth" target="_blank" rel="noopener noreferrer">
		        <i class="fab fa-github"></i>
		        2fauth - 现代化双因素认证(2FA)管理系统
		    </a>
		</div>


                    
                    <div style="margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid #e5e7eb; font-size: 0.875rem; color: #6b7280;">
                        <h4 style="margin-bottom: 0.5rem; color: #374151;">🛡️ 安全说明：</h4>
                        <ul style="padding-left: 1.5rem; line-height: 1.6; text-align: left;">
                            <li>使用OAuth 2.0标准授权协议</li>
                            <li>仅授权用户可以访问系统</li>
                            <li>会话2小时后自动过期</li>
                            <li>所有操作都有安全日志记录</li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <div id="mainSection" class="hidden">
                <div class="nav-tabs">
                    <button class="tab-btn active" data-tab="accounts" onclick="showTabByButton(this, 'accounts')">📱 我的账户</button>
                    <button class="tab-btn" data-tab="add" onclick="showTabByButton(this, 'add')">➕ 添加账户</button>
                    <button class="tab-btn" data-tab="scan" onclick="showTabByButton(this, 'scan')">📷 扫描二维码</button>
                    <button class="tab-btn" data-tab="import" onclick="showTabByButton(this, 'import')">📥 导入数据</button>
                    <button class="tab-btn" data-tab="export" onclick="showTabByButton(this, 'export')">📤 导出数据</button>
                    <button class="tab-btn" data-tab="webdav" onclick="showTabByButton(this, 'webdav')">☁️ WebDAV备份</button>
                </div>
                
                <div id="accountsTab" class="tab-content active">
                    <div class="card">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; gap: 1rem;">
                            <h2>我的2FA账户</h2>
                            <button onclick="refreshAccounts()" class="btn btn-secondary btn-small">刷新</button>
                        </div>
                        
                        <div class="search-section">
                            <input type="text" 
                                   id="searchInput" 
                                   class="search-input" 
                                   placeholder="🔍 搜索账户（服务名称、分类或账户名）..." 
                                   oninput="filterAccounts()"
                                   maxlength="100">
                            <div class="search-results" id="searchResults">
                                显示所有账户
                            </div>
                        </div>
                        
                        <div id="accountsGrid" class="accounts-grid"></div>
                    </div>
                </div>
                
                <div id="addTab" class="tab-content">
                    <div class="card">
                        <h2>手动添加账户</h2>
                        <form id="addAccountForm">
                            <div class="form-group">
                                <label for="accountService">服务名称：</label>
                                <input type="text" id="accountService" required placeholder="例如：Google、GitHub、Microsoft" maxlength="50">
                            </div>
                            
                            <div class="form-group">
                                <label for="accountCategory">分类（可选）：</label>
                                <input type="text" id="accountCategory" placeholder="例如：工作、个人、社交" maxlength="30">
                            </div>
                            
                            <div class="form-group">
                                <label for="accountUser">账户标识：</label>
                                <input type="text" id="accountUser" required placeholder="例如：用户名或邮箱" maxlength="100">
                            </div>
                            
                            <div class="form-group">
                                <label for="accountSecret">密钥：</label>
                                <input type="text" id="accountSecret" required placeholder="Base32编码的密钥" maxlength="256">
                                <small style="color: #6b7280;">从服务提供商获取的Base32格式密钥</small>
                            </div>
                            
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="accountDigits">代码位数：</label>
                                    <select id="accountDigits">
                                        <option value="6">6位</option>
                                        <option value="8">8位</option>
                                    </select>
                                </div>
                                
                                <div class="form-group">
                                    <label for="accountPeriod">更新周期（秒）：</label>
                                    <select id="accountPeriod">
                                        <option value="30">30秒</option>
                                        <option value="60">60秒</option>
                                    </select>
                                </div>
                            </div>
                            
                            <button type="submit" class="btn btn-primary">添加账户</button>
                        </form>
                    </div>
                </div>
                
                <div id="scanTab" class="tab-content">
                    <div class="card">
                        <h2>扫描二维码</h2>
                        
                        <div class="import-options">
                            <div class="import-card" onclick="startCamera()">
                                <h4>📷 摄像头扫描</h4>
                                <p>使用设备摄像头扫描二维码</p>
                            </div>
                            
                            <div class="import-card" onclick="uploadQRImage()">
                                <h4>🖼️ 上传图片</h4>
                                <p>上传包含二维码的图片文件</p>
                            </div>
                        </div>
                        
                        <div id="cameraSection" class="hidden" style="margin-top: 2rem;">
                            <div class="qr-scanner">
                                <video id="qr-video" autoplay muted playsinline></video>
                                <div class="scanner-overlay"></div>
                            </div>
                            <div style="text-align: center; margin-top: 1rem;">
                                <button onclick="stopCamera()" class="btn btn-secondary">停止扫描</button>
                            </div>
                        </div>
                        
                        <input type="file" id="qrImageInput" accept="image/*" style="display: none;" onchange="processQRImage(this)">
                    </div>
                </div>
                
                <div id="importTab" class="tab-content">
                    <div class="card">
                        <h2>导入数据</h2>
                        <div class="security-notice">
                            <strong>⚠️ 安全提醒：</strong> 请仅导入来源可信的备份文件。支持加密导入以保护数据安全。
                        </div>
                        
                        <div class="import-options">
                            <div class="import-card" onclick="importEncrypted()">
                                <h4>🔒 加密文件导入</h4>
                                <p>导入本系统导出的加密备份文件</p>
                            </div>
                            
                            <div class="import-card" onclick="importJSON()">
                                <h4>📄 JSON 格式</h4>
                                <p>导入标准JSON格式或2FAuth备份文件</p>
                            </div>
                            
                            <div class="import-card" onclick="import2FAS()">
                                <h4>📱 2FAS 格式</h4>
                                <p>导入2FAS应用的备份文件</p>
                            </div>
                            
                            <div class="import-card" onclick="importText()">
                                <h4>📝 纯文本格式</h4>
                                <p>导入纯文本格式的TOTP URI</p>
                            </div>
                        </div>
                        
                        <input type="file" id="importFileInput" style="display: none;" onchange="processImportFile(this)">
                    </div>
                </div>
                
                <div id="exportTab" class="tab-content">
                    <div class="card">
                        <h2>导出数据</h2>
                        <div class="security-notice info">
                            <strong>🛡️ 安全提醒：</strong> 为保护您的2FA密钥安全，仅支持加密导出。导出的文件请妥善保管。
                        </div>
                        
                        <div class="import-options">
                            <div class="import-card" onclick="exportEncrypted()">
                                <h4>🔒 加密导出</h4>
                                <p>导出为密码保护的加密文件</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div id="webdavTab" class="tab-content">
                    <div class="card">
                        <h2>WebDAV 自动备份</h2>
                        <div class="security-notice info">
                            <strong>☁️ 功能说明：</strong> 配置WebDAV服务器信息，可将加密备份自动上传到云存储。备份文件按年/月/日目录结构保存。支持多个WebDAV账号管理。
                        </div>
                        
                        <div class="webdav-accounts">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; gap: 1rem;">
                                <h3>WebDAV 账号</h3>
                                <button onclick="addWebDAVAccount()" class="btn btn-primary btn-small">添加账号</button>
                            </div>
                            <div id="webdavAccountsList"></div>
                        </div>
                        
                        <div class="webdav-config">
                            <h3 style="margin-bottom: 1rem;">WebDAV 配置</h3>
                            <form id="webdavConfigForm">
                                <div class="form-group">
                                    <label for="webdavName">配置名称：</label>
                                    <input type="text" id="webdavName" placeholder="例如：Nextcloud、TeraCloud" required>
                                </div>
                                
                                <div class="form-group">
                                    <label for="webdavUrl">WebDAV 地址：</label>
                                    <input type="url" id="webdavUrl" placeholder="https://your-webdav-server.com/remote.php/dav/files/username/" required>
                                    <small style="color: #6b7280;">支持Nextcloud、ownCloud、TeraCloud等WebDAV服务</small>
                                </div>
                                
                                <div class="form-row">
                                    <div class="form-group">
                                        <label for="webdavUsername">用户名：</label>
                                        <input type="text" id="webdavUsername" placeholder="WebDAV用户名" required>
                                    </div>
                                    
                                    <div class="form-group">
                                        <label for="webdavPassword">密码：</label>
                                        <div class="password-input-group">
                                            <input type="password" id="webdavPassword" placeholder="WebDAV密码或应用专用密码" required>
                                            <button type="button" class="password-toggle" onclick="togglePassword('webdavPassword')">👁️</button>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="form-group">
                                    <label for="webdavSaveDir">保存目录：</label>
                                    <input type="text" id="webdavSaveDir" placeholder="/2fa-backups" value="/2fa-backups">
                                    <small style="color: #6b7280;">备份文件保存的根目录，会自动创建年/月/日子目录</small>
                                </div>
                                
                                <div style="display: flex; gap: 1rem; margin-top: 1.5rem; flex-wrap: wrap;">
                                    <button type="button" onclick="testWebDAVConnection()" class="btn btn-secondary">测试连接</button>
                                    <button type="button" onclick="saveWebDAVConfig()" class="btn btn-primary">保存配置</button>
                                    <button type="button" onclick="exportToWebDAV()" class="btn btn-success">立即备份</button>
                                    <button type="button" onclick="loadWebDAVBackups()" class="btn btn-warning">查看备份</button>
                                </div>
                            </form>
                        </div>
                        
                        <div id="webdavStatus" class="hidden" style="margin-top: 1rem; padding: 1rem; border-radius: 12px;">
                            <div id="webdavStatusContent"></div>
                        </div>
                        
                        <div id="webdavBackupList" class="backup-list hidden">
                            <h3 style="margin: 2rem 0 1rem 0;">📁 WebDAV 备份列表</h3>
                            <div id="backupItems"></div>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>
    
    <div id="modal" class="modal hidden">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modalTitle">标题</h3>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>
            <div id="modalBody">内容</div>
        </div>
    </div>
    
    <script src="https://jsdelivr.b-cdn.net/npm/jsqr@1.4.0/dist/jsQR.min.js"></script>
    <script>
        let authToken = localStorage.getItem('authToken');
        let loginTime = localStorage.getItem('loginTime');
        let userInfo = JSON.parse(localStorage.getItem('userInfo') || 'null');
        let accounts = [];
        let sessionTimer = null;
        let currentImportType = null;
        let cameraStream = null;
        let scanInterval = null;
        let webdavConfigs = [];
        let currentWebdavConfig = null;
        
        const SECURITY_CONFIG = {
            SESSION_TIMEOUT: 2 * 60 * 60 * 1000,
            MAX_FILE_SIZE: 10 * 1024 * 1024,
            ALLOWED_FILE_TYPES: ['application/json', 'text/plain', 'image/jpeg', 'image/png', 'image/gif', 'image/webp']
        };
        
        document.addEventListener('DOMContentLoaded', () => {
            initializeApp();
            loadWebDAVConfigs();
            checkOAuthCallback();
        });
        
        function initializeApp() {
            if (authToken && userInfo && isTokenValid()) {
                showMainSection();
                refreshAccounts();
                startSessionTimer();
            } else {
                logout();
            }
            setupEventListeners();
        }
        
        function isTokenValid() {
            if (!authToken || !loginTime) return false;
            try {
                const payload = JSON.parse(atob(authToken.split('.')[1]));
                const now = Math.floor(Date.now() / 1000);
                return payload.exp > now;
            } catch {
                return false;
            }
        }
        
        function startSessionTimer() {
            if (sessionTimer) clearInterval(sessionTimer);
            if (!loginTime) {
                loginTime = Date.now();
                localStorage.setItem('loginTime', loginTime);
            }
            
            sessionTimer = setInterval(() => {
                const now = Date.now();
                const elapsed = now - parseInt(loginTime);
                const timeLeft = SECURITY_CONFIG.SESSION_TIMEOUT - elapsed;
                
                if (timeLeft <= 0) {
                    showFloatingMessage('🔒 会话已过期，请重新登录', 'warning');
                    logout();
                    return;
                }
                
                const hours = Math.floor(timeLeft / 3600000);
                const minutes = Math.floor((timeLeft % 3600000) / 60000);
                const seconds = Math.floor((timeLeft % 60000) / 1000);
                const timerElement = document.getElementById('sessionTimeLeft');
                if (timerElement) {
                    timerElement.textContent = \`\${hours}:\${minutes.toString().padStart(2, '0')}:\${seconds.toString().padStart(2, '0')}\`;
                }
                
                const sessionTimerElement = document.getElementById('sessionTimer');
                if (timeLeft <= 10 * 60 * 1000) {
                    sessionTimerElement.classList.add('warning');
                } else {
                    sessionTimerElement.classList.remove('warning');
                }
            }, 1000);
        }
        
        function setupEventListeners() {
            document.getElementById('addAccountForm').addEventListener('submit', handleAddAccount);
            document.getElementById('modal').addEventListener('click', (e) => {
                if (e.target.id === 'modal') closeModal();
            });
        }
        
        function togglePassword(inputId) {
            const input = document.getElementById(inputId);
            const button = input.nextElementSibling;
            if (input.type === 'password') {
                input.type = 'text';
                button.textContent = '🙈';
            } else {
                input.type = 'password';
                button.textContent = '👁️';
            }
        }
        
        function startOAuthLogin() {
            showFloatingMessage('🔄 正在跳转到授权页面...', 'warning');
            window.location.href = '/api/oauth/authorize';
        }
        
        function checkOAuthCallback() {
            const urlParams = new URLSearchParams(window.location.search);
            const code = urlParams.get('code');
            const state = urlParams.get('state');
            const error = urlParams.get('error');
            
            if (error) {
                showFloatingMessage('❌ OAuth授权失败：' + error, 'error');
                window.history.replaceState({}, document.title, window.location.pathname);
                return;
            }
            
            if (code && state) {
                handleOAuthCallbackSuccess(code, state);
            }
        }
        
        async function handleOAuthCallbackSuccess(code, state) {
            try {
                showFloatingMessage('🔄 正在验证授权信息...', 'warning');
                
                const response = await fetch('/api/oauth/callback', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code, state })
                });
                
                const data = await response.json();
                
                if (response.ok && data.success) {
                    authToken = data.token;
                    userInfo = data.userInfo;
                    loginTime = Date.now();
                    
                    localStorage.setItem('authToken', authToken);
                    localStorage.setItem('userInfo', JSON.stringify(userInfo));
                    localStorage.setItem('loginTime', loginTime);
                    
                    window.history.replaceState({}, document.title, window.location.pathname);
                    
                    showMainSection();
                    refreshAccounts();
                    startSessionTimer();
                    showFloatingMessage('✅ OAuth授权登录成功！', 'success');
                } else {
                    showFloatingMessage('❌ OAuth授权验证失败：' + (data.error || '未知错误'), 'error');
                    window.history.replaceState({}, document.title, window.location.pathname);
                }
            } catch (error) {
                showFloatingMessage('❌ OAuth授权处理失败：' + error.message, 'error');
                window.history.replaceState({}, document.title, window.location.pathname);
            }
        }
        
        function logout() {
            authToken = null;
            loginTime = null;
            userInfo = null;
            localStorage.removeItem('authToken');
            localStorage.removeItem('loginTime');
            localStorage.removeItem('userInfo');
            localStorage.removeItem('oauth_state');
            accounts = [];
            
            if (sessionTimer) {
                clearInterval(sessionTimer);
                sessionTimer = null;
            }
            
            stopCamera();
            showLoginSection();
            showFloatingMessage('✅ 已安全退出', 'success');
        }
        
        function handleUnauthorized() {
            authToken = null;
            loginTime = null;
            userInfo = null;
            localStorage.removeItem('authToken');
            localStorage.removeItem('loginTime');
            localStorage.removeItem('userInfo');
            accounts = [];
            
            if (sessionTimer) {
                clearInterval(sessionTimer);
                sessionTimer = null;
            }
            
            stopCamera();
            showLoginSection();
            showFloatingMessage('❌ 登录已过期，请重新登录', 'error');
        }
        
        function showFloatingMessage(message, type = 'success') {
            const existingMessage = document.querySelector('.floating-message');
            if (existingMessage) existingMessage.remove();
            
            const messageDiv = document.createElement('div');
            messageDiv.className = \`floating-message \${type}\`;
            messageDiv.innerHTML = \`<p>\${escapeHtml(message)}</p>\`;
            
            document.body.appendChild(messageDiv);
            
            requestAnimationFrame(() => {
                messageDiv.classList.add('show');
            });
            
            setTimeout(() => {
                messageDiv.classList.remove('show');
                setTimeout(() => {
                    if (messageDiv.parentNode) {
                        messageDiv.parentNode.removeChild(messageDiv);
                    }
                }, 400);
            }, type === 'success' ? 3000 : 5000);
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        async function clearAllAccounts() {
            if (!confirm('⚠️ 确定要清空所有账号吗？\\n\\n此操作不可撤销，将删除所有已保存的2FA账户！\\n\\n请确认您已备份重要数据。')) return;
            if (!confirm('🚨 最后确认：您真的要删除所有账号吗？\\n\\n删除后无法恢复！')) return;
            
            try {
                const response = await fetch('/api/accounts/clear-all', {
                    method: 'DELETE',
                    headers: { 'Authorization': \`Bearer \${authToken}\` }
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showFloatingMessage('✅ 所有账号已清空！', 'success');
                    refreshAccounts();
                } else {
                    if (response.status === 401) {
                        handleUnauthorized();
                    } else {
                        showFloatingMessage('❌ 清空失败：' + data.error, 'error');
                    }
                }
            } catch (error) {
                showFloatingMessage('❌ 网络请求失败：' + error.message, 'error');
            }
        }
        
        function deleteAccount(accountId) {
            const account = accounts.find(acc => acc.id === accountId);
            if (!account) return;
            
            if (!confirm(\`确定要删除账户 "\${account.service} - \${account.account}" 吗？\\n\\n此操作不可撤销，请确认您已备份相关信息。\`)) return;
            
            performDeleteAccount(accountId);
        }
        
        async function performDeleteAccount(accountId) {
            try {
                const response = await fetch(\`/api/accounts/\${encodeURIComponent(accountId)}\`, {
                    method: 'DELETE',
                    headers: { 'Authorization': \`Bearer \${authToken}\` }
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showFloatingMessage('✅ 账户删除成功！', 'success');
                    refreshAccounts();
                } else {
                    if (response.status === 401) {
                        handleUnauthorized();
                    } else {
                        showFloatingMessage('❌ 删除账户失败：' + data.error, 'error');
                    }
                }
            } catch (error) {
                showFloatingMessage('❌ 网络请求失败：' + error.message, 'error');
            }
        }
        
        function editAccount(accountId) {
            const account = accounts.find(acc => acc.id === accountId);
            if (!account) return;
            
            const modalContent = \`
                <form id="editAccountForm">
                    <div class="form-group">
                        <label for="editService">服务名称：</label>
                        <input type="text" id="editService" value="\${escapeHtml(account.service)}" required maxlength="50">
                    </div>
                    
                    <div class="form-group">
                        <label for="editCategory">分类：</label>
                        <input type="text" id="editCategory" value="\${escapeHtml(account.category || '')}" placeholder="例如：工作、个人、社交" maxlength="30">
                    </div>
                    
                    <div class="form-group">
                        <label for="editAccount">账户标识：</label>
                        <input type="text" id="editAccount" value="\${escapeHtml(account.account)}" required maxlength="100">
                    </div>
                    
                    <div style="display: flex; gap: 1rem; margin-top: 1.5rem; flex-wrap: wrap;">
                        <button type="submit" class="btn btn-primary">保存修改</button>
                        <button type="button" onclick="closeModal()" class="btn btn-secondary">取消</button>
                    </div>
                </form>
            \`;
            
            showModal('✏️ 编辑账户', modalContent);
            
            document.getElementById('editAccountForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const service = sanitizeInput(document.getElementById('editService').value);
                const category = sanitizeInput(document.getElementById('editCategory').value);
                const accountName = sanitizeInput(document.getElementById('editAccount').value);
                
                if (!service || service.length < 1 || service.length > 50) {
                    showFloatingMessage('❌ 服务名称格式不正确（1-50个字符）', 'error');
                    return;
                }
                
                if (!accountName || accountName.length < 1 || accountName.length > 100) {
                    showFloatingMessage('❌ 账户标识格式不正确（1-100个字符）', 'error');
                    return;
                }
                
                try {
                    const response = await fetch(\`/api/accounts/\${encodeURIComponent(accountId)}\`, {
                        method: 'PUT',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': \`Bearer \${authToken}\`
                        },
                        body: JSON.stringify({ service, category, account: accountName })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        closeModal();
                        showFloatingMessage('✅ 账户修改成功！', 'success');
                        refreshAccounts();
                    } else {
                        if (response.status === 401) {
                            handleUnauthorized();
                        } else {
                            showFloatingMessage('❌ 修改账户失败：' + data.error, 'error');
                        }
                    }
                } catch (error) {
                    showFloatingMessage('❌ 网络请求失败：' + error.message, 'error');
                }
            });
        }
        
        function showLoginSection() {
            document.getElementById('loginSection').classList.remove('hidden');
            document.getElementById('mainSection').classList.add('hidden');
            document.getElementById('userInfo').classList.add('hidden');
        }
        
        function showMainSection() {
            document.getElementById('loginSection').classList.add('hidden');
            document.getElementById('mainSection').classList.remove('hidden');
            document.getElementById('userInfo').classList.remove('hidden');
            
            if (userInfo) {
                document.getElementById('userName').textContent = userInfo.username || userInfo.nickname || '未知用户';
                document.getElementById('userEmail').textContent = userInfo.email || '';
                
                const avatarImg = document.getElementById('userAvatar');
                if (userInfo.avatar_template) {
                    avatarImg.src = userInfo.avatar_template;
                    avatarImg.style.display = 'block';
                } else {
                    avatarImg.style.display = 'none';
                }
            }
        }
        
        function showTabByButton(buttonElement, tabName) {
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            
            document.getElementById(tabName + 'Tab').classList.add('active');
            buttonElement.classList.add('active');
            
            if (tabName === 'accounts') {
                refreshAccounts();
            } else if (tabName === 'webdav') {
                loadWebDAVConfigs();
            }
        }
        
        function showModal(title, content) {
            document.getElementById('modalTitle').textContent = title;
            document.getElementById('modalBody').innerHTML = content;
            document.getElementById('modal').classList.remove('hidden');
        }
        
        function closeModal() {
            document.getElementById('modal').classList.add('hidden');
        }
        
        function sanitizeInput(input) {
            if (typeof input !== 'string') return '';
            return input.replace(/[<>"'&\\x00-\\x1F\\x7F]/g, '').trim();
        }
        
        async function loadWebDAVConfigs() {
            try {
                const response = await fetch('/api/get-webdav-configs', {
                    headers: { 'Authorization': \`Bearer \${authToken}\` }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    webdavConfigs = data.configs || [];
                    currentWebdavConfig = webdavConfigs.find(c => c.isActive) || null;
                    displayWebDAVAccounts();
                    
                    if (currentWebdavConfig) {
                        loadWebDAVConfigToForm(currentWebdavConfig);
                    } else {
                        clearWebDAVConfigForm();
                    }
                }
            } catch (error) {
                console.error('Failed to load WebDAV configs:', error);
            }
        }
        
        function displayWebDAVAccounts() {
            const container = document.getElementById('webdavAccountsList');
            
            if (webdavConfigs.length === 0) {
                container.innerHTML = '<p style="text-align: center; color: #6b7280;">暂无WebDAV账号，请添加新账号</p>';
                return;
            }
            
            container.innerHTML = webdavConfigs.map(config => \`
                <div class="webdav-account-item \${config.isActive ? 'active' : ''}" data-id="\${config.id}">
                    <div class="webdav-account-info">
                        <div class="webdav-account-name">\${escapeHtml(config.name)}</div>
                        <div class="webdav-account-url">\${escapeHtml(config.url)}</div>
                    </div>
                    <div class="webdav-account-actions">
                        <button onclick="setActiveWebDAVAccount('\${config.id}')" class="btn btn-small \${config.isActive ? 'btn-success' : 'btn-secondary'}">\${config.isActive ? '当前' : '切换'}</button>
                        <button onclick="editWebDAVAccount('\${config.id}')" class="btn btn-warning btn-small">编辑</button>
                        <button onclick="deleteWebDAVAccount('\${config.id}')" class="btn btn-danger btn-small">删除</button>
                    </div>
                </div>
            \`).join('');
        }
        
        function addWebDAVAccount() {
            clearWebDAVConfigForm();
            document.getElementById('webdavConfigForm').scrollIntoView({ behavior: 'smooth' });
            document.getElementById('webdavName').focus();
        }
        
        function clearWebDAVConfigForm() {
            document.getElementById('webdavConfigForm').reset();
            document.getElementById('webdavName').value = '';
            document.getElementById('webdavUrl').value = '';
            document.getElementById('webdavUsername').value = '';
            document.getElementById('webdavPassword').value = '';
            document.getElementById('webdavSaveDir').value = '/2fa-backups';
            delete document.getElementById('webdavConfigForm').dataset.editingId;
        }
        
        function editWebDAVAccount(configId) {
            const config = webdavConfigs.find(c => c.id === configId);
            if (config) {
                loadWebDAVConfigToForm(config);
                document.getElementById('webdavConfigForm').scrollIntoView({ behavior: 'smooth' });
                document.getElementById('webdavName').focus();
            }
        }
        
        function loadWebDAVConfigToForm(config) {
            document.getElementById('webdavName').value = config.name || '';
            document.getElementById('webdavUrl').value = config.url || '';
            document.getElementById('webdavUsername').value = config.username || '';
            document.getElementById('webdavPassword').value = config.password || '';
            document.getElementById('webdavSaveDir').value = config.saveDir || '/2fa-backups';
            document.getElementById('webdavConfigForm').dataset.editingId = config.id;
        }
        
        async function setActiveWebDAVAccount(configId) {
            try {
                const updatedConfigs = webdavConfigs.map(config => ({
                    ...config,
                    isActive: config.id === configId
                }));
                
                const response = await fetch('/api/save-webdav-configs', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${authToken}\`
                    },
                    body: JSON.stringify({ configs: updatedConfigs })
                });
                
                if (response.ok) {
                    webdavConfigs = updatedConfigs;
                    currentWebdavConfig = webdavConfigs.find(c => c.isActive);
                    displayWebDAVAccounts();
                    if (currentWebdavConfig) {
                        loadWebDAVConfigToForm(currentWebdavConfig);
                    }
                    showFloatingMessage('✅ WebDAV账号已切换', 'success');
                } else {
                    showFloatingMessage('❌ 切换失败', 'error');
                }
            } catch (error) {
                showFloatingMessage('❌ 切换失败：' + error.message, 'error');
            }
        }
        
        async function deleteWebDAVAccount(configId) {
            const config = webdavConfigs.find(c => c.id === configId);
            if (!config) return;
            
            if (!confirm(\`确定要删除WebDAV账号 "\${config.name}" 吗？\`)) return;
            
            try {
                const updatedConfigs = webdavConfigs.filter(c => c.id !== configId);
                
                if (config.isActive && updatedConfigs.length > 0) {
                    updatedConfigs[0].isActive = true;
                }
                
                const response = await fetch('/api/save-webdav-configs', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${authToken}\`
                    },
                    body: JSON.stringify({ configs: updatedConfigs })
                });
                
                if (response.ok) {
                    webdavConfigs = updatedConfigs;
                    currentWebdavConfig = webdavConfigs.find(c => c.isActive) || null;
                    displayWebDAVAccounts();
                    
                    if (currentWebdavConfig) {
                        loadWebDAVConfigToForm(currentWebdavConfig);
                    } else {
                        clearWebDAVConfigForm();
                    }
                    
                    showFloatingMessage('✅ WebDAV账号已删除', 'success');
                } else {
                    showFloatingMessage('❌ 删除失败', 'error');
                }
            } catch (error) {
                showFloatingMessage('❌ 删除失败：' + error.message, 'error');
            }
        }
        
        async function saveWebDAVConfig() {
            const name = document.getElementById('webdavName').value.trim();
            const url = document.getElementById('webdavUrl').value.trim();
            const username = document.getElementById('webdavUsername').value.trim();
            const password = document.getElementById('webdavPassword').value;
            const saveDir = document.getElementById('webdavSaveDir').value.trim() || '/2fa-backups';
            
            if (!name || !url || !username || !password) {
                showFloatingMessage('❌ 请填写完整的WebDAV配置信息', 'error');
                return;
            }
            
            try {
                new URL(url);
            } catch {
                showFloatingMessage('❌ WebDAV地址格式不正确', 'error');
                return;
            }
            
            const editingId = document.getElementById('webdavConfigForm').dataset.editingId;
            let updatedConfigs;
            
            if (editingId) {
                updatedConfigs = webdavConfigs.map(config => 
                    config.id === editingId 
                        ? { ...config, name, url, username, password, saveDir }
                        : config
                );
            } else {
                const newConfig = {
                    id: 'webdav_' + Date.now(),
                    name,
                    url,
                    username,
                    password,
                    saveDir,
                    isActive: webdavConfigs.length === 0
                };
                
                if (webdavConfigs.length === 0) {
                    updatedConfigs = [newConfig];
                } else {
                    updatedConfigs = [...webdavConfigs, newConfig];
                }
            }
            
            try {
                const response = await fetch('/api/save-webdav-configs', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${authToken}\`
                    },
                    body: JSON.stringify({ configs: updatedConfigs })
                });
                
                if (response.ok) {
                    webdavConfigs = updatedConfigs;
                    currentWebdavConfig = webdavConfigs.find(c => c.isActive);
                    displayWebDAVAccounts();
                    clearWebDAVConfigForm();
                    showFloatingMessage('✅ WebDAV配置已保存', 'success');
                } else {
                    const data = await response.json();
                    showFloatingMessage('❌ 保存配置失败：' + data.error, 'error');
                }
            } catch (error) {
                showFloatingMessage('❌ 保存配置失败：' + error.message, 'error');
            }
        }
        
        async function testWebDAVConnection() {
            if (!currentWebdavConfig) {
                showFloatingMessage('❌ 请先选择一个WebDAV账号', 'error');
                return;
            }
            
            showWebDAVStatus('🔄 正在测试WebDAV连接...', 'info');
            
            try {
                const response = await fetch('/api/test-webdav', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${authToken}\`
                    },
                    body: JSON.stringify(currentWebdavConfig)
                });
                
                const data = await response.json();
                
                if (response.ok && data.success) {
                    showWebDAVStatus('✅ WebDAV连接测试成功！', 'success');
                } else {
                    showWebDAVStatus('❌ WebDAV连接失败：' + data.error, 'error');
                }
            } catch (error) {
                showWebDAVStatus('❌ 连接测试失败：' + error.message, 'error');
            }
        }
        
        function showWebDAVStatus(message, type) {
            const statusDiv = document.getElementById('webdavStatus');
            const contentDiv = document.getElementById('webdavStatusContent');
            
            statusDiv.className = \`security-notice \${type === 'success' ? 'info' : type === 'error' ? '' : 'info'}\`;
            contentDiv.textContent = message;
            statusDiv.classList.remove('hidden');
            
            if (type === 'success' || type === 'error') {
                setTimeout(() => {
                    statusDiv.classList.add('hidden');
                }, 5000);
            }
        }
        
        async function loadWebDAVBackups() {
            if (!currentWebdavConfig) {
                showFloatingMessage('❌ 请先选择一个WebDAV账号', 'error');
                return;
            }
            
            try {
                showWebDAVStatus('🔄 正在加载备份列表...', 'info');
                
                const response = await fetch('/api/list-webdav-backups', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${authToken}\`
                    },
                    body: JSON.stringify(currentWebdavConfig)
                });
                
                const data = await response.json();
                
                if (response.ok && data.success) {
                    showWebDAVStatus('✅ 备份列表加载成功！', 'success');
                    displayBackupList(data.backups);
                } else {
                    showWebDAVStatus('❌ 加载备份列表失败：' + data.error, 'error');
                    
                    if (data.error.includes('404')) {
                        showFloatingMessage('❌ WebDAV路径不存在，请检查保存目录设置', 'error');
                    } else if (data.error.includes('401')) {
                        showFloatingMessage('❌ WebDAV认证失败，请检查用户名和密码', 'error');
                    } else if (data.error.includes('403')) {
                        showFloatingMessage('❌ WebDAV访问被拒绝，请检查权限设置', 'error');
                    } else {
                        showFloatingMessage('❌ 加载备份列表失败：' + data.error, 'error');
                    }
                }
            } catch (error) {
                showWebDAVStatus('❌ 加载备份列表失败：' + error.message, 'error');
                showFloatingMessage('❌ 网络请求失败：' + error.message, 'error');
            }
        }
        
        function displayBackupList(backups) {
            const backupListDiv = document.getElementById('webdavBackupList');
            const backupItemsDiv = document.getElementById('backupItems');
            
            if (!backups || backups.length === 0) {
                backupItemsDiv.innerHTML = '<p style="text-align: center; color: #6b7280;">暂无备份文件</p>';
            } else {
                backupItemsDiv.innerHTML = backups.map(backup => \`
                    <div class="backup-item">
                        <div class="backup-info">
                            <div class="backup-filename">\${escapeHtml(backup.filename)}</div>
                            <div class="backup-meta">
                                \${backup.lastModified ? '修改时间: ' + new Date(backup.lastModified).toLocaleString() : ''}
                                \${backup.size ? ' | 大小: ' + formatFileSize(backup.size) : ''}
                            </div>
                        </div>
                        <div class="backup-actions">
                            <button onclick="restoreFromWebDAV('\${escapeHtml(backup.path)}')" class="btn btn-success btn-small">恢复</button>
                            <button onclick="downloadWebDAVBackup('\${escapeHtml(backup.path)}', '\${escapeHtml(backup.filename)}')" class="btn btn-secondary btn-small">下载</button>
                        </div>
                    </div>
                \`).join('');
            }
            
            backupListDiv.classList.remove('hidden');
        }
        
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        async function restoreFromWebDAV(path) {
            if (!confirm('⚠️ 确定要从WebDAV恢复备份吗？\\n\\n这将替换当前所有账户数据！\\n\\n请确认您要恢复的备份文件是正确的。')) return;
            
            const modalContent = \`
                <form id="restoreForm">
                    <div class="security-notice">
                        <strong>🔓 恢复备份：</strong> 请输入备份文件的加密密码。
                    </div>
                    <div class="form-group">
                        <label for="restorePassword">备份密码：</label>
                        <div class="password-input-group">
                            <input type="password" id="restorePassword" required placeholder="输入备份时设置的密码">
                            <button type="button" class="password-toggle" onclick="togglePassword('restorePassword')">👁️</button>
                        </div>
                        <small style="color: #6b7280;">请输入创建此备份时设置的密码</small>
                    </div>
                    
                    <div style="display: flex; gap: 1rem; margin-top: 1.5rem; flex-wrap: wrap;">
                        <button type="submit" class="btn btn-primary">恢复备份</button>
                        <button type="button" onclick="closeModal()" class="btn btn-secondary">取消</button>
                    </div>
                </form>
            \`;
            
            showModal('📥 恢复WebDAV备份', modalContent);
            
            document.getElementById('restoreForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const password = document.getElementById('restorePassword').value;
                
                if (!password) {
                    showFloatingMessage('❌ 请输入备份密码', 'error');
                    return;
                }
                
                closeModal();
                showFloatingMessage('🔄 正在从WebDAV恢复备份...', 'warning');
                
                try {
                    const response = await fetch('/api/restore-webdav', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': \`Bearer \${authToken}\`
                        },
                        body: JSON.stringify({
                            path: path,
                            password: password,
                            webdavConfig: currentWebdavConfig
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok && data.success) {
                        showFloatingMessage(\`✅ 成功恢复 \${data.count} 个账户！\`, 'success');
                        refreshAccounts();
                        showTabByButton(document.querySelector('[data-tab="accounts"]'), 'accounts');
                    } else {
                        showFloatingMessage('❌ 恢复失败：' + data.error, 'error');
                    }
                } catch (error) {
                    showFloatingMessage('❌ 恢复失败：' + error.message, 'error');
                }
            });
        }
        
        async function downloadWebDAVBackup(path, filename) {
            showFloatingMessage('🔄 正在下载备份文件...', 'warning');
            
            try {
                const response = await fetch('/api/download-webdav', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${authToken}\`
                    },
                    body: JSON.stringify({
                        path: path,
                        webdavConfig: currentWebdavConfig
                    })
                });
                
                if (response.ok) {
                    const content = await response.text();
                    downloadFile(content, filename, 'application/json');
                    showFloatingMessage('✅ 备份文件下载成功！', 'success');
                } else {
                    const data = await response.json();
                    showFloatingMessage('❌ 下载失败：' + data.error, 'error');
                }
            } catch (error) {
                showFloatingMessage('❌ 下载失败：' + error.message, 'error');
            }
        }
        
        async function exportToWebDAV() {
            if (!currentWebdavConfig) {
                showFloatingMessage('❌ 请先选择一个WebDAV账号', 'error');
                return;
            }
            
            const modalContent = \`
                <form id="webdavExportForm">
                    <div class="form-group">
                        <label for="webdavExportPassword">设置备份加密密码：</label>
                        <div class="password-input-group">
                            <input type="password" id="webdavExportPassword" required minlength="12" maxlength="128" placeholder="至少12个字符">
                            <button type="button" class="password-toggle" onclick="togglePassword('webdavExportPassword')">👁️</button>
                        </div>
                        <small style="color: #6b7280;">此密码用于加密备份文件，请妥善保管</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="webdavConfirmPassword">确认密码：</label>
                        <div class="password-input-group">
                            <input type="password" id="webdavConfirmPassword" required minlength="12" maxlength="128" placeholder="再次输入密码">
                            <button type="button" class="password-toggle" onclick="togglePassword('webdavConfirmPassword')">👁️</button>
                        </div>
                    </div>
                    
                    <div style="display: flex; gap: 1rem; margin-top: 1.5rem; flex-wrap: wrap;">
                        <button type="submit" class="btn btn-primary">上传到WebDAV</button>
                        <button type="button" onclick="closeModal()" class="btn btn-secondary">取消</button>
                    </div>
                </form>
            \`;
            
            showModal('☁️ WebDAV备份', modalContent);
            
            document.getElementById('webdavExportForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const password = document.getElementById('webdavExportPassword').value;
                const confirmPassword = document.getElementById('webdavConfirmPassword').value;
                
                if (password !== confirmPassword) {
                    showFloatingMessage('❌ 两次输入的密码不一致', 'error');
                    return;
                }
                
                if (password.length < 12) {
                    showFloatingMessage('❌ 备份密码至少需要12个字符', 'error');
                    return;
                }
                
                closeModal();
                showFloatingMessage('🔄 正在生成加密备份并上传到WebDAV...', 'warning');
                
                try {
                    const response = await fetch('/api/export-webdav', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': \`Bearer \${authToken}\`
                        },
                        body: JSON.stringify({
                            password: password,
                            webdavConfig: currentWebdavConfig
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok && data.success) {
                        showFloatingMessage(\`✅ 备份成功上传到WebDAV！\\n文件路径：\${data.path}\`, 'success');
                    } else {
                        showFloatingMessage('❌ WebDAV备份失败：' + data.error, 'error');
                    }
                } catch (error) {
                    showFloatingMessage('❌ 备份失败：' + error.message, 'error');
                }
            });
        }
        
        function filterAccounts() {
            const searchTerm = sanitizeInput(document.getElementById('searchInput').value).toLowerCase();
            const accountCards = document.querySelectorAll('.account-card');
            let visibleCount = 0;
            
            accountCards.forEach(card => {
                const service = card.querySelector('.service-name').textContent.toLowerCase();
                const account = card.querySelector('.account-identifier').textContent.toLowerCase();
                const category = card.querySelector('.category-tag')?.textContent.toLowerCase() || '';
                
                const isMatch = searchTerm === '' || 
                               service.includes(searchTerm) || 
                               account.includes(searchTerm) ||
                               category.includes(searchTerm);
                
                if (isMatch) {
                    card.classList.remove('filtered');
                    visibleCount++;
                } else {
                    card.classList.add('filtered');
                }
            });
            
            const resultsElement = document.getElementById('searchResults');
            if (searchTerm === '') {
                resultsElement.textContent = \`显示所有账户 (\${accounts.length})\`;
            } else {
                resultsElement.textContent = \`找到 \${visibleCount} 个匹配账户\`;
            }
        }
        
        async function refreshAccounts() {
            try {
                const response = await fetch('/api/accounts', {
                    headers: { 'Authorization': \`Bearer \${authToken}\` }
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    accounts = data.accounts || [];
                    displayAccounts();
                    filterAccounts();
                } else {
                    if (response.status === 401) {
                        handleUnauthorized();
                    } else {
                        showFloatingMessage('❌ 加载账户失败：' + data.error, 'error');
                    }
                }
            } catch (error) {
                showFloatingMessage('❌ 网络请求失败：' + error.message, 'error');
            }
        }
        
        function displayAccounts() {
            const grid = document.getElementById('accountsGrid');
            
            if (accounts.length === 0) {
                grid.innerHTML = '<p style="text-align: center; color: #6b7280; grid-column: 1 / -1;">暂无账户，请添加新的2FA账户</p>';
                return;
            }
            
            grid.innerHTML = accounts.map(account => \`
                <div class="account-card" data-id="\${escapeHtml(account.id)}">
                    <div class="account-header">
                        <div class="service-name">
                            \${escapeHtml(account.service)}
                            \${account.category ? \`<span class="category-tag">\${escapeHtml(account.category)}</span>\` : ''}
                        </div>
                        <div class="account-info-row">
                            <div class="account-identifier">\${escapeHtml(account.account)}</div>
                            <div class="account-actions">
                                <button onclick="copyTOTP('\${escapeHtml(account.id)}')" class="action-btn copy" title="复制代码">📋</button>
                                <button onclick="editAccount('\${escapeHtml(account.id)}')" class="action-btn edit" title="编辑">✏️</button>
                                <button onclick="deleteAccount('\${escapeHtml(account.id)}')" class="action-btn delete" title="删除">🗑️</button>
                            </div>
                        </div>
                    </div>
                    <div class="totp-code hidden-code" onclick="showTOTPCodeModal('\${escapeHtml(account.id)}')" id="totp-\${escapeHtml(account.id)}"></div>
                </div>
            \`).join('');
        }
        
        async function handleAddAccount(e) {
            e.preventDefault();
            
            const service = sanitizeInput(document.getElementById('accountService').value);
            const category = sanitizeInput(document.getElementById('accountCategory').value);
            const account = sanitizeInput(document.getElementById('accountUser').value);
            const secret = document.getElementById('accountSecret').value.replace(/\\s/g, '').toUpperCase();
            const digits = parseInt(document.getElementById('accountDigits').value);
            const period = parseInt(document.getElementById('accountPeriod').value);
            
            if (!service || service.length < 1 || service.length > 50) {
                showFloatingMessage('❌ 服务名称格式不正确（1-50个字符）', 'error');
                return;
            }
            
            if (!account || account.length < 1 || account.length > 100) {
                showFloatingMessage('❌ 账户标识格式不正确（1-100个字符）', 'error');
                return;
            }
            
            if (!secret || !/^[A-Z2-7]+=*$/.test(secret) || secret.length < 16) {
                showFloatingMessage('❌ 密钥格式不正确（16+个字符的Base32编码）', 'error');
                return;
            }
            
            if (![6, 8].includes(digits) || ![30, 60].includes(period)) {
                showFloatingMessage('❌ 验证码位数或更新周期参数不正确', 'error');
                return;
            }
            
            try {
                const response = await fetch('/api/accounts', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${authToken}\`
                    },
                    body: JSON.stringify({ service, category, account, secret, digits, period })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showFloatingMessage('✅ 账户添加成功！', 'success');
                    document.getElementById('addAccountForm').reset();
                    refreshAccounts();
                    showTabByButton(document.querySelector('[data-tab="accounts"]'), 'accounts');
                } else {
                    if (response.status === 401) {
                        handleUnauthorized();
                    } else {
                        showFloatingMessage('❌ 添加账户失败：' + data.error, 'error');
                    }
                }
            } catch (error) {
                showFloatingMessage('❌ 网络请求失败：' + error.message, 'error');
            }
        }
        
        async function showTOTPCodeModal(accountId) {
            const account = accounts.find(acc => acc.id === accountId);
            if (!account) return;
            
            try {
                const code = await generateTOTPCode(account.secret, account.period || 30, account.digits || 6);
                
                if (code && code !== '------') {
                    const modalContent = \`
                        <div class="code-modal">
                            <div class="code-info">
                                <strong>\${escapeHtml(account.service)}</strong><br>
                                \${escapeHtml(account.account)}
                            </div>
                            <div class="code-display" id="modalCodeDisplay">\${code}</div>
                            <div class="progress-container">
                                <div class="progress-label">验证码有效时间</div>
                                <div class="progress-bar">
                                    <div class="progress-fill" id="modalProgressFill"></div>
                                </div>
                            </div>
                            <div class="auto-copy-notice">✅ 验证码已自动复制到剪贴板</div>
                            <div style="margin-top: 1.5rem;">
                                <button onclick="closeModal()" class="btn btn-primary">关闭</button>
                            </div>
                        </div>
                    \`;
                    
                    showModal('🔑 验证码', modalContent);
                    
                    try {
                        await navigator.clipboard.writeText(code);
                    } catch (clipboardError) {
                        console.error('Failed to copy to clipboard:', clipboardError);
                        const notice = document.querySelector('.auto-copy-notice');
                        if (notice) {
                            notice.textContent = '请手动复制验证码';
                            notice.style.color = '#f59e0b';
                        }
                    }
                    
                    startModalProgressUpdate(account.period || 30);
                    
                    setTimeout(() => {
                        closeModal();
                    }, 6000);
                } else {
                    showFloatingMessage('❌ 无法生成验证码', 'error');
                }
            } catch (error) {
                showFloatingMessage('❌ 生成验证码失败：' + error.message, 'error');
            }
        }
        
        function startModalProgressUpdate(period) {
            const progressFill = document.getElementById('modalProgressFill');
            if (!progressFill) return;
            
            const updateProgress = () => {
                const now = Math.floor(Date.now() / 1000);
                const timeLeft = period - (now % period);
                const progress = (timeLeft / period) * 100;
                
                progressFill.style.width = progress + '%';
                
                if (timeLeft <= 5) {
                    progressFill.className = 'progress-fill danger';
                } else if (timeLeft <= 10) {
                    progressFill.className = 'progress-fill warning';
                } else {
                    progressFill.className = 'progress-fill';
                }
            };
            
            updateProgress();
            
            const intervalId = setInterval(() => {
                if (document.getElementById('modalProgressFill')) {
                    updateProgress();
                } else {
                    clearInterval(intervalId);
                }
            }, 1000);
        }
        
        async function copyTOTP(accountId) {
            const account = accounts.find(acc => acc.id === accountId);
            if (!account) return;
            
            try {
                const code = await generateTOTPCode(account.secret, account.period || 30, account.digits || 6);
                if (code && code !== '------') {
                    await navigator.clipboard.writeText(code);
                    showFloatingMessage('✅ 验证码已复制到剪贴板', 'success');
                } else {
                    showFloatingMessage('❌ 无法生成验证码', 'error');
                }
            } catch (error) {
                showFloatingMessage('❌ 复制失败：' + error.message, 'error');
            }
        }
        
        async function generateTOTPCode(secret, period = 30, digits = 6) {
            try {
                const response = await fetch('/api/generate-totp', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${authToken}\`
                    },
                    body: JSON.stringify({ secret, period, digits })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    return data.code;
                } else {
                    throw new Error(data.error);
                }
            } catch (error) {
                console.error('Failed to generate TOTP:', error);
                return '------';
            }
        }
        
        async function startCamera() {
            try {
                if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                    showFloatingMessage('❌ 您的浏览器不支持摄像头功能', 'error');
                    return;
                }
                
                cameraStream = await navigator.mediaDevices.getUserMedia({
                    video: { 
                        facingMode: 'environment',
                        width: { ideal: 640 },
                        height: { ideal: 480 }
                    }
                });
                
                const video = document.getElementById('qr-video');
                video.srcObject = cameraStream;
                
                video.addEventListener('loadedmetadata', () => {
                    video.play();
                    document.getElementById('cameraSection').classList.remove('hidden');
                    scanInterval = setInterval(scanQRCode, 500);
                    showFloatingMessage('📷 摄像头已启动，请将二维码对准扫描框', 'success');
                });
            } catch (error) {
                console.error('Camera error:', error);
                showFloatingMessage('❌ 无法访问摄像头：' + error.message, 'error');
            }
        }
        
        function stopCamera() {
            if (cameraStream) {
                cameraStream.getTracks().forEach(track => track.stop());
                cameraStream = null;
            }
            
            if (scanInterval) {
                clearInterval(scanInterval);
                scanInterval = null;
            }
            
            document.getElementById('cameraSection').classList.add('hidden');
            showFloatingMessage('📷 摄像头已关闭', 'success');
        }
        
        function scanQRCode() {
            const video = document.getElementById('qr-video');
            
            if (video.readyState !== video.HAVE_ENOUGH_DATA) return;
            
            try {
                const canvas = document.createElement('canvas');
                const context = canvas.getContext('2d');
                
                canvas.width = video.videoWidth;
                canvas.height = video.videoHeight;
                
                if (canvas.width === 0 || canvas.height === 0) return;
                
                context.drawImage(video, 0, 0, canvas.width, canvas.height);
                const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
                
                if (typeof jsQR === 'undefined') {
                    console.error('jsQR library not loaded');
                    return;
                }
                
                const code = jsQR(imageData.data, imageData.width, imageData.height);
                
                if (code && code.data.startsWith('otpauth://')) {
                    stopCamera();
                    showFloatingMessage('✅ 二维码识别成功！', 'success');
                    processOTPAuthURI(code.data);
                }
            } catch (error) {
                console.error('QR scan error:', error);
            }
        }
        
        function uploadQRImage() {
            document.getElementById('qrImageInput').click();
        }
        
        function processQRImage(input) {
            const file = input.files[0];
            if (!file) return;
            
            if (file.size > SECURITY_CONFIG.MAX_FILE_SIZE) {
                showFloatingMessage('❌ 文件大小不能超过10MB', 'error');
                return;
            }
            
            if (!file.type.startsWith('image/')) {
                showFloatingMessage('❌ 请选择图片文件', 'error');
                return;
            }
            
            showFloatingMessage('🔄 正在识别二维码...', 'warning');
            
            const reader = new FileReader();
            reader.onload = function(e) {
                const img = new Image();
                img.onload = function() {
                    try {
                        const canvas = document.createElement('canvas');
                        const context = canvas.getContext('2d');
                        
                        canvas.width = img.width;
                        canvas.height = img.height;
                        context.drawImage(img, 0, 0);
                        
                        const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
                        
                        if (typeof jsQR === 'undefined') {
                            showFloatingMessage('❌ 二维码识别库未加载，请刷新页面重试', 'error');
                            return;
                        }
                        
                        const code = jsQR(imageData.data, imageData.width, imageData.height);
                        
                        if (code && code.data.startsWith('otpauth://')) {
                            showFloatingMessage('✅ 二维码识别成功！', 'success');
                            processOTPAuthURI(code.data);
                        } else {
                            showFloatingMessage('❌ 未能识别二维码，请确保图片清晰且包含有效的2FA二维码', 'error');
                        }
                    } catch (error) {
                        console.error('Image processing error:', error);
                        showFloatingMessage('❌ 图片处理失败：' + error.message, 'error');
                    }
                };
                
                img.onerror = function() {
                    showFloatingMessage('❌ 图片加载失败，请检查文件格式', 'error');
                };
                
                img.src = e.target.result;
            };
            
            reader.onerror = function() {
                showFloatingMessage('❌ 文件读取失败', 'error');
            };
            
            reader.readAsDataURL(file);
            input.value = '';
        }
        
        async function processOTPAuthURI(uri) {
            try {
                console.log('Processing OTP URI:', uri.substring(0, 50) + '...');
                
                const response = await fetch('/api/parse-uri', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${authToken}\`
                    },
                    body: JSON.stringify({ uri })
                });
                
                const data = await response.json();
                
                if (response.ok && data.account) {
                    const account = data.account;
                    
                    const modalContent = \`
                        <div style="margin-bottom: 1rem;">
                            <h4 style="margin-bottom: 1rem; color: #374151;">📋 确认账户信息</h4>
                            <div style="background: rgba(248, 250, 252, 0.8); padding: 1rem; border-radius: 12px; margin-bottom: 1rem; backdrop-filter: blur(10px);">
                                <p><strong>服务：</strong>\${escapeHtml(account.issuer || '未知')}</p>
                                <p><strong>账户：</strong>\${escapeHtml(account.account || '未知')}</p>
                                <p><strong>类型：</strong>\${account.type.toUpperCase()}</p>
                                <p><strong>位数：</strong>\${account.digits}位</p>
                                <p><strong>周期：</strong>\${account.period}秒</p>
                            </div>
                            
                            <div class="form-group">
                                <label for="qrCategory">分类（可选）：</label>
                                <input type="text" id="qrCategory" placeholder="例如：工作、个人、社交" maxlength="30">
                            </div>
                        </div>
                        <div style="display: flex; gap: 1rem; flex-wrap: wrap;">
                            <button onclick="confirmAddFromURI('\${escapeHtml(uri)}')" class="btn btn-primary">确认添加</button>
                            <button onclick="closeModal()" class="btn btn-secondary">取消</button>
                        </div>
                    \`;
                    
                    showModal('✅ 二维码识别成功', modalContent);
                } else {
                    console.error('Parse URI failed:', data);
                    showFloatingMessage('❌ 解析二维码失败：' + (data.error || '未知错误'), 'error');
                }
            } catch (error) {
                console.error('Process OTP URI error:', error);
                showFloatingMessage('❌ 处理二维码失败：' + error.message, 'error');
            }
        }
        
        async function confirmAddFromURI(uri) {
            try {
                const category = sanitizeInput(document.getElementById('qrCategory').value);
                
                const response = await fetch('/api/add-from-uri', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${authToken}\`
                    },
                    body: JSON.stringify({ uri, category })
                });
                
                const data = await response.json();
                
                if (response.ok && data.success) {
                    closeModal();
                    showFloatingMessage('✅ 账户添加成功！', 'success');
                    refreshAccounts();
                    showTabByButton(document.querySelector('[data-tab="accounts"]'), 'accounts');
                } else {
                    console.error('Add from URI failed:', data);
                    showFloatingMessage('❌ 添加账户失败：' + (data.error || '未知错误'), 'error');
                }
            } catch (error) {
                console.error('Confirm add from URI error:', error);
                showFloatingMessage('❌ 请求失败：' + error.message, 'error');
            }
        }
        
        async function exportEncrypted() {
            const modalContent = \`
                <form id="exportForm">
                    <div class="form-group">
                        <label for="exportPassword">设置导出密码：</label>
                        <div class="password-input-group">
                            <input type="password" id="exportPassword" required minlength="12" maxlength="128" placeholder="至少12个字符">
                            <button type="button" class="password-toggle" onclick="togglePassword('exportPassword')">👁️</button>
                        </div>
                        <small style="color: #6b7280;">此密码用于加密备份文件，请妥善保管</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="confirmPassword">确认密码：</label>
                        <div class="password-input-group">
                            <input type="password" id="confirmPassword" required minlength="12" maxlength="128" placeholder="再次输入密码">
                            <button type="button" class="password-toggle" onclick="togglePassword('confirmPassword')">👁️</button>
                        </div>
                    </div>
                    
                    <div style="display: flex; gap: 1rem; margin-top: 1.5rem; flex-wrap: wrap;">
                        <button type="submit" class="btn btn-primary">导出加密文件</button>
                        <button type="button" onclick="closeModal()" class="btn btn-secondary">取消</button>
                    </div>
                </form>
            \`;
            
            showModal('🔒 加密导出', modalContent);
            
            document.getElementById('exportForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const password = document.getElementById('exportPassword').value;
                const confirmPassword = document.getElementById('confirmPassword').value;
                
                if (password !== confirmPassword) {
                    showFloatingMessage('❌ 两次输入的密码不一致', 'error');
                    return;
                }
                
                if (password.length < 12) {
                    showFloatingMessage('❌ 导出密码至少需要12个字符', 'error');
                    return;
                }
                
                try {
                    const response = await fetch(\`/api/export-secure?password=\${encodeURIComponent(password)}\`, {
                        headers: { 'Authorization': \`Bearer \${authToken}\` }
                    });
                    
                    if (response.ok) {
                        const data = await response.json();
                        const filename = \`2fa-backup-encrypted-\${new Date().toISOString().split('T')[0]}.json\`;
                        downloadFile(JSON.stringify(data, null, 2), filename, 'application/json');
                        
                        closeModal();
                        showFloatingMessage('✅ 加密备份导出成功！请妥善保管密码', 'success');
                    } else {
                        const data = await response.json();
                        showFloatingMessage('❌ 导出失败：' + data.error, 'error');
                    }
                } catch (error) {
                    showFloatingMessage('❌ 导出失败：' + error.message, 'error');
                }
            });
        }
        
        function importEncrypted() {
            currentImportType = 'encrypted';
            document.getElementById('importFileInput').accept = '.json';
            document.getElementById('importFileInput').click();
        }
        
        function importJSON() {
            currentImportType = 'json';
            document.getElementById('importFileInput').accept = '.json';
            document.getElementById('importFileInput').click();
        }
        
        function import2FAS() {
            currentImportType = '2fas';
            document.getElementById('importFileInput').accept = '.2fas,.json';
            document.getElementById('importFileInput').click();
        }
        
        function importText() {
            currentImportType = 'text';
            document.getElementById('importFileInput').accept = '.txt';
            document.getElementById('importFileInput').click();
        }
        
        function processImportFile(input) {
            const file = input.files[0];
            if (!file) return;
            
            if (file.size > SECURITY_CONFIG.MAX_FILE_SIZE) {
                showFloatingMessage('❌ 文件大小不能超过10MB', 'error');
                return;
            }
            
            if (!SECURITY_CONFIG.ALLOWED_FILE_TYPES.includes(file.type)) {
                showFloatingMessage('❌ 不支持的文件类型', 'error');
                return;
            }
            
            showFloatingMessage('🔄 正在处理文件...', 'warning');
            
            const reader = new FileReader();
            reader.onload = function(e) {
                try {
                    const content = e.target.result;
                    
                    if (currentImportType === 'encrypted') {
                        handleEncryptedImport(content);
                    } else {
                        processImportData(content, currentImportType);
                    }
                } catch (error) {
                    showFloatingMessage('❌ 文件处理失败：' + error.message, 'error');
                }
            };
            
            reader.onerror = function() {
                showFloatingMessage('❌ 文件读取失败', 'error');
            };
            
            reader.readAsText(file);
            input.value = '';
        }
        
        function handleEncryptedImport(content) {
            try {
                const encryptedFile = JSON.parse(content);
                
                if (!encryptedFile.encrypted || !encryptedFile.data) {
                    showFloatingMessage('❌ 这不是有效的加密备份文件', 'error');
                    return;
                }
                
                const modalContent = \`
                    <form id="importForm">
                        <div class="form-group">
                            <label for="importPassword">输入导入密码：</label>
                            <div class="password-input-group">
                                <input type="password" id="importPassword" required placeholder="输入导出时设置的密码">
                                <button type="button" class="password-toggle" onclick="togglePassword('importPassword')">👁️</button>
                            </div>
                            <small style="color: #6b7280;">请输入导出此文件时设置的密码</small>
                        </div>
                        
                        <div style="display: flex; gap: 1rem; margin-top: 1.5rem; flex-wrap: wrap;">
                            <button type="submit" class="btn btn-primary">解密并导入</button>
                            <button type="button" onclick="closeModal()" class="btn btn-secondary">取消</button>
                        </div>
                    </form>
                \`;
                
                showModal('🔓 解密导入', modalContent);
                
                document.getElementById('importForm').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    
                    const password = document.getElementById('importPassword').value;
                    
                    if (!password) {
                        showFloatingMessage('❌ 请输入密码', 'error');
                        return;
                    }
                    
                    try {
                        const response = await fetch('/api/import-secure', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': \`Bearer \${authToken}\`
                            },
                            body: JSON.stringify({
                                content: content,
                                password: password,
                                type: 'encrypted'
                            })
                        });
                        
                        const data = await response.json();
                        
                        if (data.success) {
                            closeModal();
                            showFloatingMessage(\`✅ 成功导入 \${data.count} 个账户！\`, 'success');
                            refreshAccounts();
                            showTabByButton(document.querySelector('[data-tab="accounts"]'), 'accounts');
                        } else {
                            showFloatingMessage('❌ 导入失败：' + data.error, 'error');
                        }
                    } catch (error) {
                        showFloatingMessage('❌ 导入失败：' + error.message, 'error');
                    }
                });
            } catch (error) {
                showFloatingMessage('❌ 文件格式错误：' + error.message, 'error');
            }
        }
        
        async function processImportData(content, type) {
            try {
                const response = await fetch('/api/import', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${authToken}\`
                    },
                    body: JSON.stringify({ content, type })
                });
                
                const data = await response.json();
                
                if (response.ok && data.success) {
                    let message = \`✅ 成功导入 \${data.count} 个账户！\`;
                    if (data.duplicates > 0) {
                        message += \`\\n(跳过了 \${data.duplicates} 个重复账户)\`;
                    }
                    showFloatingMessage(message, 'success');
                    refreshAccounts();
                    showTabByButton(document.querySelector('[data-tab="accounts"]'), 'accounts');
                } else {
                    if (response.status === 401) {
                        handleUnauthorized();
                    } else {
                        let errorMessage = '❌ 导入失败：' + (data.error || '未知错误');
                        if (data.message && data.message !== data.error) {
                            errorMessage += '\\n详情：' + data.message;
                        }
                        showFloatingMessage(errorMessage, 'error');
                    }
                }
            } catch (error) {
                showFloatingMessage('❌ 导入失败：' + error.message, 'error');
            }
        }
        
        function downloadFile(content, filename, type) {
            const blob = new Blob([content], { type });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
    </script>
</body>
</html>`;
}

// ===== 修正的导入处理函数（支持2FAuth v5.5.2格式） =====
async function handleImport(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    try {
        const { content, type } = await request.json();
        
        if (!content || !type) {
            return new Response(JSON.stringify({ error: 'Content and type are required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        let importedAccounts = [];
        
        if (type === 'json') {
            try {
                const data = JSON.parse(content);
                console.log('解析JSON数据:', Object.keys(data));
                
                // 检测 2FAuth v5.5.2 格式
                if (data.app && data.app.includes('2fauth') && data.data && Array.isArray(data.data)) {
                    console.log('检测到 2FAuth v5.5.2 格式，账户数量:', data.data.length);
                    importedAccounts = data.data.map(item => {
                        console.log('处理2FAuth账户:', item.service, item.account);
                        return {
                            service: item.service || 'Unknown Service',
                            account: item.account || 'Unknown Account',
                            secret: item.secret,
                            digits: item.digits || 6,
                            period: item.period || 30,
                            category: '', // 2FAuth v5.5.2 格式中没有分类字段
                            algorithm: item.algorithm || 'sha1'
                        };
                    });
                }
                // 标准格式
                else if (data.accounts) {
                    console.log('检测到标准格式，账户数量:', data.accounts.length);
                    importedAccounts = data.accounts;
                } 
                // 数组格式
                else if (Array.isArray(data)) {
                    console.log('检测到数组格式，账户数量:', data.length);
                    importedAccounts = data;
                } 
                // 2FAuth 旧版本格式
                else if (data.services) {
                    console.log('检测到2FAuth旧版本格式，账户数量:', data.services.length);
                    importedAccounts = data.services.map(service => ({
                        service: service.service || service.name || 'Unknown',
                        account: service.account || service.login || 'Unknown',
                        secret: service.secret,
                        digits: service.digits || 6,
                        period: service.period || 30,
                        category: service.group || ''
                    }));
                }
            } catch (error) {
                console.error('JSON解析错误:', error);
                throw new Error('Invalid JSON format');
            }
        } else if (type === '2fas') {
            try {
                const data = JSON.parse(content);
                
                if (data.services) {
                    importedAccounts = data.services.map(service => ({
                        service: service.name || 'Unknown',
                        account: service.account || service.username || 'Unknown',
                        secret: service.secret,
                        digits: service.digits || 6,
                        period: service.period || 30,
                        category: service.category || service.group || ''
                    }));
                } else {
                    throw new Error('Invalid 2FAS format');
                }
            } catch (error) {
                throw new Error('Invalid 2FAS format');
            }
        } else if (type === 'text') {
            const lines = content.split('\n').filter(line => line.trim());
            
            for (const line of lines) {
                const trimmedLine = line.trim();
                if (trimmedLine.startsWith('otpauth://')) {
                    const parsed = parseOTPAuthURI(trimmedLine);
                    if (parsed) {
                        importedAccounts.push({
                            service: parsed.issuer || 'Unknown',
                            account: parsed.account || 'Unknown',
                            secret: parsed.secret,
                            digits: parsed.digits,
                            period: parsed.period,
                            category: ''
                        });
                    }
                }
            }
        }
        
        console.log('解析到的账户数量:', importedAccounts.length);
        
        if (importedAccounts.length === 0) {
            return new Response(JSON.stringify({ error: 'No valid accounts found in import data' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        const validAccounts = [];
        for (const acc of importedAccounts) {
            // 验证必要字段
            if (!acc.service || !acc.account || !acc.secret) {
                console.log('跳过无效账户:', acc);
                continue;
            }
            
            // 验证密钥格式
            if (!validateBase32Secret(acc.secret)) {
                console.log('跳过无效密钥的账户:', acc.service, acc.account);
                continue;
            }
            
            // 验证服务名和账户名
            if (validateServiceName(acc.service) && validateAccountName(acc.account)) {
                validAccounts.push({
                    id: crypto.randomUUID(),
                    service: sanitizeInput(acc.service, 50),
                    category: acc.category ? sanitizeInput(acc.category, 30) : '',
                    account: sanitizeInput(acc.account, 100),
                    secret: acc.secret.replace(/\s/g, '').toUpperCase(),
                    digits: acc.digits || 6,
                    period: acc.period || 30,
                    createdAt: Date.now(),
                    createdBy: authenticatedUser.username || authenticatedUser.id,
                    importedAt: Date.now(),
                    importType: type
                });
                console.log('添加有效账户:', acc.service, acc.account);
            } else {
                console.log('跳过验证失败的账户:', acc.service, acc.account);
            }
        }
        
        console.log('有效账户数量:', validAccounts.length);
        
        if (validAccounts.length === 0) {
            return new Response(JSON.stringify({ error: 'No valid accounts found after validation' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        const encryptedData = await env.USER_DATA.get('accounts_encrypted');
        let existingAccounts = [];
        
        if (encryptedData) {
            try {
                const parsed = JSON.parse(encryptedData);
                existingAccounts = await decryptData(parsed, env.ENCRYPTION_KEY || env.JWT_SECRET);
            } catch (decryptError) {
                const legacyData = await env.USER_DATA.get('accounts');
                existingAccounts = legacyData ? JSON.parse(legacyData) : [];
            }
        }
        
        const allAccounts = [...existingAccounts];
        let addedCount = 0;
        
        for (const newAccount of validAccounts) {
            const isDuplicate = allAccounts.some(existing => 
                existing.service.toLowerCase() === newAccount.service.toLowerCase() && 
                existing.account.toLowerCase() === newAccount.account.toLowerCase()
            );
            
            if (!isDuplicate) {
                allAccounts.push(newAccount);
                addedCount++;
            }
        }
        
        const encrypted = await encryptData(allAccounts, env.ENCRYPTION_KEY || env.JWT_SECRET);
        await env.USER_DATA.put('accounts_encrypted', JSON.stringify(encrypted));
        
        await logSecurityEvent('IMPORT_SUCCESS', { 
            type, 
            totalImported: validAccounts.length,
            actuallyAdded: addedCount,
            duplicatesSkipped: validAccounts.length - addedCount
        }, request);
        
        return new Response(JSON.stringify({
            success: true,
            count: addedCount,
            total: validAccounts.length,
            duplicates: validAccounts.length - addedCount,
            message: `Successfully imported ${addedCount} accounts (${validAccounts.length - addedCount} duplicates skipped)`
        }), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        console.error('Import error:', error);
        await logSecurityEvent('IMPORT_ERROR', { error: error.message }, request);
        return new Response(JSON.stringify({ 
            error: 'Failed to import data',
            message: error.message
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// 其他处理函数保持不变...
async function handleAccounts(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method === 'GET') {
        try {
            const encryptedData = await env.USER_DATA.get('accounts_encrypted');
            let accounts = [];
            
            if (encryptedData) {
                try {
                    const parsed = JSON.parse(encryptedData);
                    accounts = await decryptData(parsed, env.ENCRYPTION_KEY || env.JWT_SECRET);
                } catch (decryptError) {
                    console.error('Decryption failed, trying legacy format:', decryptError);
                    const legacyData = await env.USER_DATA.get('accounts');
                    accounts = legacyData ? JSON.parse(legacyData) : [];
                }
            }
            
            return new Response(JSON.stringify({ accounts }), {
                status: 200,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        } catch (error) {
            await logSecurityEvent('ACCOUNTS_READ_ERROR', { error: error.message }, request);
            return new Response(JSON.stringify({ 
                error: 'Failed to load accounts',
                message: error.message 
            }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    }
    
    if (request.method === 'POST') {
        try {
            const { service, category, account, secret, digits = 6, period = 30 } = await request.json();
            
            if (!validateServiceName(service)) {
                return new Response(JSON.stringify({ error: 'Invalid service name format' }), {
                    status: 400,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            if (!validateAccountName(account)) {
                return new Response(JSON.stringify({ error: 'Invalid account name format' }), {
                    status: 400,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            if (!validateBase32Secret(secret)) {
                return new Response(JSON.stringify({ error: 'Invalid secret format' }), {
                    status: 400,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            if (![6, 8].includes(digits) || ![30, 60].includes(period)) {
                return new Response(JSON.stringify({ error: 'Invalid digits or period' }), {
                    status: 400,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            const encryptedData = await env.USER_DATA.get('accounts_encrypted');
            let accounts = [];
            
            if (encryptedData) {
                try {
                    const parsed = JSON.parse(encryptedData);
                    accounts = await decryptData(parsed, env.ENCRYPTION_KEY || env.JWT_SECRET);
                } catch (decryptError) {
                    const legacyData = await env.USER_DATA.get('accounts');
                    accounts = legacyData ? JSON.parse(legacyData) : [];
                }
            }
            
            const isDuplicate = accounts.some(acc => 
                acc.service.toLowerCase() === service.toLowerCase() && 
                acc.account.toLowerCase() === account.toLowerCase()
            );
            
            if (isDuplicate) {
                return new Response(JSON.stringify({ error: 'Account already exists' }), {
                    status: 409,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            const newAccount = {
                id: crypto.randomUUID(),
                service: sanitizeInput(service, 50),
                category: category ? sanitizeInput(category, 30) : '',
                account: sanitizeInput(account, 100),
                secret: secret.replace(/\s/g, '').toUpperCase(),
                digits,
                period,
                createdAt: Date.now(),
                createdBy: authenticatedUser.username || authenticatedUser.id
            };
            
            accounts.push(newAccount);
            
            const encrypted = await encryptData(accounts, env.ENCRYPTION_KEY || env.JWT_SECRET);
            await env.USER_DATA.put('accounts_encrypted', JSON.stringify(encrypted));
            
            await logSecurityEvent('ACCOUNT_ADDED', { 
                service: newAccount.service, 
                account: newAccount.account 
            }, request);
            
            return new Response(JSON.stringify({
                success: true,
                account: {
                    ...newAccount,
                    secret: '[PROTECTED]'
                }
            }), {
                status: 200,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        } catch (error) {
            await logSecurityEvent('ACCOUNT_ADD_ERROR', { error: error.message }, request);
            return new Response(JSON.stringify({ 
                error: 'Failed to add account',
                message: error.message 
            }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    }
    
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
}

async function handleClearAllAccounts(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method !== 'DELETE') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    try {
        const encryptedData = await env.USER_DATA.get('accounts_encrypted');
        let currentCount = 0;
        
        if (encryptedData) {
            try {
                const parsed = JSON.parse(encryptedData);
                const accounts = await decryptData(parsed, env.ENCRYPTION_KEY || env.JWT_SECRET);
                currentCount = accounts.length;
            } catch (decryptError) {
                const legacyData = await env.USER_DATA.get('accounts');
                const accounts = legacyData ? JSON.parse(legacyData) : [];
                currentCount = accounts.length;
            }
        }
        
        const emptyAccounts = [];
        const encrypted = await encryptData(emptyAccounts, env.ENCRYPTION_KEY || env.JWT_SECRET);
        await env.USER_DATA.put('accounts_encrypted', JSON.stringify(encrypted));
        await env.USER_DATA.delete('accounts');
        
        await logSecurityEvent('ALL_ACCOUNTS_CLEARED', { 
            previousCount: currentCount,
            clearedBy: authenticatedUser.username || authenticatedUser.id
        }, request);
        
        return new Response(JSON.stringify({
            success: true,
            message: `Successfully cleared ${currentCount} accounts`,
            clearedCount: currentCount
        }), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        await logSecurityEvent('CLEAR_ALL_ERROR', { error: error.message }, request);
        return new Response(JSON.stringify({ 
            error: 'Failed to clear accounts',
            message: error.message 
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleAccountUpdate(request, env, accountId) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (!accountId || typeof accountId !== 'string' || accountId.length > 100) {
        return new Response(JSON.stringify({ error: 'Invalid account ID' }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method === 'PUT') {
        try {
            const { service, category, account } = await request.json();
            
            if (!validateServiceName(service)) {
                return new Response(JSON.stringify({ error: 'Invalid service name format' }), {
                    status: 400,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            if (!validateAccountName(account)) {
                return new Response(JSON.stringify({ error: 'Invalid account name format' }), {
                    status: 400,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            const encryptedData = await env.USER_DATA.get('accounts_encrypted');
            let accounts = [];
            
            if (encryptedData) {
                try {
                    const parsed = JSON.parse(encryptedData);
                    accounts = await decryptData(parsed, env.ENCRYPTION_KEY || env.JWT_SECRET);
                } catch (decryptError) {
                    const legacyData = await env.USER_DATA.get('accounts');
                    accounts = legacyData ? JSON.parse(legacyData) : [];
                }
            }
            
            const accountIndex = accounts.findIndex(acc => acc.id === accountId);
            
            if (accountIndex === -1) {
                return new Response(JSON.stringify({ error: 'Account not found' }), {
                    status: 404,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            accounts[accountIndex] = {
                ...accounts[accountIndex],
                service: sanitizeInput(service, 50),
                category: category ? sanitizeInput(category, 30) : '',
                account: sanitizeInput(account, 100),
                updatedAt: Date.now(),
                updatedBy: authenticatedUser.username || authenticatedUser.id
            };
            
            const encrypted = await encryptData(accounts, env.ENCRYPTION_KEY || env.JWT_SECRET);
            await env.USER_DATA.put('accounts_encrypted', JSON.stringify(encrypted));
            
            await logSecurityEvent('ACCOUNT_UPDATED', { 
                accountId,
                service: accounts[accountIndex].service, 
                account: accounts[accountIndex].account 
            }, request);
            
            return new Response(JSON.stringify({
                success: true,
                message: 'Account updated successfully'
            }), {
                status: 200,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        } catch (error) {
            await logSecurityEvent('ACCOUNT_UPDATE_ERROR', { error: error.message }, request);
            return new Response(JSON.stringify({ 
                error: 'Failed to update account',
                message: error.message 
            }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    }
    
    if (request.method === 'DELETE') {
        try {
            const encryptedData = await env.USER_DATA.get('accounts_encrypted');
            let accounts = [];
            
            if (encryptedData) {
                try {
                    const parsed = JSON.parse(encryptedData);
                    accounts = await decryptData(parsed, env.ENCRYPTION_KEY || env.JWT_SECRET);
                } catch (decryptError) {
                    const legacyData = await env.USER_DATA.get('accounts');
                    accounts = legacyData ? JSON.parse(legacyData) : [];
                }
            }
            
            const accountToDelete = accounts.find(acc => acc.id === accountId);
            const filteredAccounts = accounts.filter(acc => acc.id !== accountId);
            
            if (filteredAccounts.length === accounts.length) {
                return new Response(JSON.stringify({ error: 'Account not found' }), {
                    status: 404,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            
            const encrypted = await encryptData(filteredAccounts, env.ENCRYPTION_KEY || env.JWT_SECRET);
            await env.USER_DATA.put('accounts_encrypted', JSON.stringify(encrypted));
            
            await logSecurityEvent('ACCOUNT_DELETED', { 
                service: accountToDelete?.service, 
                account: accountToDelete?.account 
            }, request);
            
            return new Response(JSON.stringify({
                success: true,
                message: 'Account deleted successfully'
            }), {
                status: 200,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        } catch (error) {
            await logSecurityEvent('ACCOUNT_DELETE_ERROR', { error: error.message }, request);
            return new Response(JSON.stringify({ 
                error: 'Failed to delete account',
                message: error.message 
            }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    }
    
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
}

async function handleGenerateTOTP(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    try {
        const { secret, period = 30, digits = 6 } = await request.json();
        
        if (!validateBase32Secret(secret)) {
            return new Response(JSON.stringify({ error: 'Invalid secret format' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        if (![6, 8].includes(digits) || ![30, 60].includes(period)) {
            return new Response(JSON.stringify({ error: 'Invalid digits or period' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        const code = await generateTOTP(secret, period, digits);
        
        return new Response(JSON.stringify({ code }), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ 
            error: 'Failed to generate TOTP',
            message: 'Internal server error'
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleParseURI(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    try {
        const { uri } = await request.json();
        
        if (!uri) {
            return new Response(JSON.stringify({ error: 'URI is required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        const account = parseOTPAuthURI(uri);
        
        if (!account) {
            return new Response(JSON.stringify({ error: 'Invalid OTP Auth URI' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        return new Response(JSON.stringify({ account }), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ 
            error: 'Failed to parse URI',
            message: error.message 
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleAddFromURI(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    try {
        const { uri, category } = await request.json();
        
        if (!uri) {
            return new Response(JSON.stringify({ error: 'URI is required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        const parsedAccount = parseOTPAuthURI(uri);
        
        if (!parsedAccount) {
            return new Response(JSON.stringify({ error: 'Invalid OTP Auth URI' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        const encryptedData = await env.USER_DATA.get('accounts_encrypted');
        let accounts = [];
        
        if (encryptedData) {
            try {
                const parsed = JSON.parse(encryptedData);
                accounts = await decryptData(parsed, env.ENCRYPTION_KEY || env.JWT_SECRET);
            } catch (decryptError) {
                const legacyData = await env.USER_DATA.get('accounts');
                accounts = legacyData ? JSON.parse(legacyData) : [];
            }
        }
        
        const newAccount = {
            id: crypto.randomUUID(),
            service: parsedAccount.issuer || 'Unknown Service',
            category: category ? sanitizeInput(category, 30) : '',
            account: parsedAccount.account || 'Unknown Account',
            secret: parsedAccount.secret,
            digits: parsedAccount.digits,
            period: parsedAccount.period,
            createdAt: Date.now(),
            createdBy: authenticatedUser.username || authenticatedUser.id
        };
        
        accounts.push(newAccount);
        const encrypted = await encryptData(accounts, env.ENCRYPTION_KEY || env.JWT_SECRET);
        await env.USER_DATA.put('accounts_encrypted', JSON.stringify(encrypted));
        
        await logSecurityEvent('ACCOUNT_ADDED_FROM_QR', { 
            service: newAccount.service, 
            account: newAccount.account 
        }, request);
        
        return new Response(JSON.stringify({
            success: true,
            account: newAccount
        }), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        await logSecurityEvent('ADD_FROM_URI_ERROR', { error: error.message }, request);
        return new Response(JSON.stringify({ 
            error: 'Failed to add account from URI',
            message: error.message 
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleTestWebDAV(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    try {
        const webdavConfig = await request.json();
        
        const validation = validateWebDAVConfig(webdavConfig);
        if (!validation.isValid) {
            return new Response(JSON.stringify({ 
                error: 'Invalid WebDAV configuration: ' + validation.errors.join(', ') 
            }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        const auth = btoa(`${webdavConfig.username}:${webdavConfig.password}`);
        const testUrl = webdavConfig.url.replace(/\/$/, '') + '/';
        
        const response = await fetch(testUrl, {
            method: 'PROPFIND',
            headers: {
                'Authorization': `Basic ${auth}`,
                'Depth': '0',
                'Content-Type': 'application/xml',
                'User-Agent': '2FA-Manager/1.0'
            },
            body: '<?xml version="1.0" encoding="utf-8"?><propfind xmlns="DAV:"><prop><resourcetype/></prop></propfind>'
        });
        
        if (response.ok || response.status === 207) {
            await logSecurityEvent('WEBDAV_TEST_SUCCESS', { url: webdavConfig.url }, request);
            
            return new Response(JSON.stringify({
                success: true,
                message: 'WebDAV connection successful'
            }), {
                status: 200,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        } else {
            const errorText = await response.text();
            throw new WebDAVError(`WebDAV test failed: ${response.status} ${response.statusText}`, response.status, errorText);
        }
    } catch (error) {
        await logSecurityEvent('WEBDAV_TEST_ERROR', { error: error.message }, request);
        
        return new Response(JSON.stringify({ 
            error: 'WebDAV test failed',
            message: error.message
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleListWebDAVBackups(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    try {
        const webdavConfig = await request.json();
        
        if (!webdavConfig || !webdavConfig.url || !webdavConfig.username || !webdavConfig.password) {
            return new Response(JSON.stringify({ error: 'WebDAV configuration required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        const backups = await listWebDAVBackups(webdavConfig);
        
        await logSecurityEvent('WEBDAV_LIST_SUCCESS', { count: backups.length }, request);
        
        return new Response(JSON.stringify({
            success: true,
            backups: backups
        }), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        await logSecurityEvent('WEBDAV_LIST_ERROR', { error: error.message }, request);
        
        return new Response(JSON.stringify({ 
            error: 'Failed to list WebDAV backups',
            message: error.message
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleDownloadWebDAV(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    try {
        const { path, webdavConfig } = await request.json();
        
        if (!path || !webdavConfig || !webdavConfig.url || !webdavConfig.username || !webdavConfig.password) {
            return new Response(JSON.stringify({ error: 'Missing path or WebDAV configuration' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        const content = await downloadFromWebDAV(path, webdavConfig);
        
        await logSecurityEvent('WEBDAV_DOWNLOAD', { path }, request);
        
        return new Response(content, {
            status: 200,
            headers: { 
                ...corsHeaders, 
                'Content-Type': 'application/json',
                'Content-Disposition': `attachment; filename="${path.split('/').pop()}"`
            }
        });
    } catch (error) {
        await logSecurityEvent('WEBDAV_DOWNLOAD_ERROR', { error: error.message }, request);
        
        return new Response(JSON.stringify({ 
            error: 'Failed to download from WebDAV',
            message: error.message
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleRestoreWebDAV(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    try {
        const { path, password, webdavConfig } = await request.json();
        
        if (!path || !password || !webdavConfig || !webdavConfig.url || !webdavConfig.username || !webdavConfig.password) {
            return new Response(JSON.stringify({ error: 'Missing required parameters' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        const content = await downloadFromWebDAV(path, webdavConfig);
        const encryptedFile = JSON.parse(content);
        
        if (!encryptedFile.encrypted || !encryptedFile.data) {
            throw new Error('Invalid encrypted backup file format');
        }
        
        const decryptedData = await decryptData(encryptedFile.data, password);
        
        if (!decryptedData.accounts) {
            throw new Error('No accounts found in backup file');
        }
        
        const restoredAccounts = decryptedData.accounts.map(acc => ({
            id: crypto.randomUUID(),
            service: sanitizeInput(acc.service, 50),
            category: acc.category ? sanitizeInput(acc.category, 30) : '',
            account: sanitizeInput(acc.account, 100),
            secret: acc.secret.replace(/\s/g, '').toUpperCase(),
            digits: acc.digits || 6,
            period: acc.period || 30,
            createdAt: Date.now(),
            createdBy: authenticatedUser.username || authenticatedUser.id,
            restoredAt: Date.now(),
            restoredFrom: 'webdav'
        }));
        
        const encrypted = await encryptData(restoredAccounts, env.ENCRYPTION_KEY || env.JWT_SECRET);
        await env.USER_DATA.put('accounts_encrypted', JSON.stringify(encrypted));
        
        await logSecurityEvent('WEBDAV_RESTORE', { 
            path,
            count: restoredAccounts.length 
        }, request);
        
        return new Response(JSON.stringify({
            success: true,
            count: restoredAccounts.length,
            message: `Successfully restored ${restoredAccounts.length} accounts from WebDAV`
        }), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        await logSecurityEvent('WEBDAV_RESTORE_ERROR', { error: error.message }, request);
        return new Response(JSON.stringify({ 
            error: 'Failed to restore from WebDAV',
            message: error.message.includes('decrypt') ? 'Incorrect password or corrupted backup file' : error.message
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleExportWebDAV(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    try {
        const { password, webdavConfig } = await request.json();
        
        if (!password || password.length < SECURITY_CONFIG.MIN_EXPORT_PASSWORD_LENGTH) {
            return new Response(JSON.stringify({ 
                error: `Export password required (minimum ${SECURITY_CONFIG.MIN_EXPORT_PASSWORD_LENGTH} characters)` 
            }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        if (!webdavConfig || !webdavConfig.url || !webdavConfig.username || !webdavConfig.password) {
            return new Response(JSON.stringify({ error: 'WebDAV configuration required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        const encryptedData = await env.USER_DATA.get('accounts_encrypted');
        let accounts = [];
        
        if (encryptedData) {
            try {
                const parsed = JSON.parse(encryptedData);
                accounts = await decryptData(parsed, env.ENCRYPTION_KEY || env.JWT_SECRET);
            } catch (decryptError) {
                const legacyData = await env.USER_DATA.get('accounts');
                accounts = legacyData ? JSON.parse(legacyData) : [];
            }
        }
        
        const exportData = {
            version: "2.0",
            app: "2fa-secure-manager",
            encrypted: true,
            timestamp: new Date().toISOString(),
            accounts: accounts.map(acc => ({
                service: acc.service,
                category: acc.category,
                account: acc.account,
                secret: acc.secret,
                digits: acc.digits,
                period: acc.period
            }))
        };
        
        const encrypted = await encryptData(exportData, password);
        
        const exportFile = {
            version: "2.0",
            app: "2fa-secure-manager",
            encrypted: true,
            timestamp: new Date().toISOString(),
            data: encrypted,
            note: "This file is encrypted with your export password. Keep it safe!"
        };
        
        const now = new Date();
        const timestamp = now.toISOString().replace(/[:.]/g, '-').split('T')[0] + '_' + 
                         now.toTimeString().split(' ')[0].replace(/:/g, '-');
        const filename = `2fa-backup-encrypted-${timestamp}.json`;
        
        const uploadResult = await uploadToWebDAV(
            JSON.stringify(exportFile, null, 2),
            filename,
            webdavConfig
        );
        
        await logSecurityEvent('WEBDAV_EXPORT', { 
            count: accounts.length,
            path: uploadResult.path 
        }, request);
        
        return new Response(JSON.stringify({
            success: true,
            path: uploadResult.path,
            filename: filename,
            message: 'Backup successfully uploaded to WebDAV'
        }), {
            status: 200,
            headers: { 
                ...corsHeaders, 
                'Content-Type': 'application/json'
            }
        });
    } catch (error) {
        await logSecurityEvent('WEBDAV_EXPORT_ERROR', { error: error.message }, request);
        return new Response(JSON.stringify({ 
            error: 'Failed to export to WebDAV',
            message: error.message
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleSecureExport(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method !== 'GET') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    try {
        const url = new URL(request.url);
        const password = url.searchParams.get('password');
        
        if (!password || password.length < SECURITY_CONFIG.MIN_EXPORT_PASSWORD_LENGTH) {
            return new Response(JSON.stringify({ 
                error: `Export password required (minimum ${SECURITY_CONFIG.MIN_EXPORT_PASSWORD_LENGTH} characters)` 
            }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        const encryptedData = await env.USER_DATA.get('accounts_encrypted');
        let accounts = [];
        
        if (encryptedData) {
            try {
                const parsed = JSON.parse(encryptedData);
                accounts = await decryptData(parsed, env.ENCRYPTION_KEY || env.JWT_SECRET);
            } catch (decryptError) {
                const legacyData = await env.USER_DATA.get('accounts');
                accounts = legacyData ? JSON.parse(legacyData) : [];
            }
        }
        
        const exportData = {
            version: "2.0",
            app: "2fa-secure-manager",
            encrypted: true,
            timestamp: new Date().toISOString(),
            accounts: accounts.map(acc => ({
                service: acc.service,
                category: acc.category,
                account: acc.account,
                secret: acc.secret,
                digits: acc.digits,
                period: acc.period
            }))
        };
        
        const encrypted = await encryptData(exportData, password);
        
        const exportFile = {
            version: "2.0",
            app: "2fa-secure-manager",
            encrypted: true,
            timestamp: new Date().toISOString(),
            data: encrypted,
            note: "This file is encrypted with your export password. Keep it safe!"
        };
        
        await logSecurityEvent('SECURE_EXPORT', { count: accounts.length }, request);
        
        return new Response(JSON.stringify(exportFile, null, 2), {
            status: 200,
            headers: { 
                ...corsHeaders, 
                'Content-Type': 'application/json',
                'Content-Disposition': `attachment; filename="2fa-backup-encrypted-${new Date().toISOString().split('T')[0]}.json"`
            }
        });
    } catch (error) {
        await logSecurityEvent('SECURE_EXPORT_ERROR', { error: error.message }, request);
        return new Response(JSON.stringify({ 
            error: 'Failed to export data',
            message: error.message
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleSecureImport(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    try {
        const { content, password, type } = await request.json();
        
        if (!content || !password || type !== 'encrypted') {
            return new Response(JSON.stringify({ error: 'Content, password and type are required' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        const encryptedFile = JSON.parse(content);
        
        if (!encryptedFile.encrypted || !encryptedFile.data) {
            return new Response(JSON.stringify({ error: 'Invalid encrypted backup file format' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        let decryptedData;
        try {
            decryptedData = await decryptData(encryptedFile.data, password);
        } catch (decryptError) {
            return new Response(JSON.stringify({ error: 'Incorrect password or corrupted backup file' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        if (!decryptedData.accounts || !Array.isArray(decryptedData.accounts)) {
            return new Response(JSON.stringify({ error: 'Invalid backup file structure' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        const validAccounts = [];
        for (const acc of decryptedData.accounts) {
            if (validateServiceName(acc.service) && 
                validateAccountName(acc.account) && 
                validateBase32Secret(acc.secret)) {
                validAccounts.push({
                    id: crypto.randomUUID(),
                    service: sanitizeInput(acc.service, 50),
                    category: acc.category ? sanitizeInput(acc.category, 30) : '',
                    account: sanitizeInput(acc.account, 100),
                    secret: acc.secret.replace(/\s/g, '').toUpperCase(),
                    digits: acc.digits || 6,
                    period: acc.period || 30,
                    createdAt: Date.now(),
                    createdBy: authenticatedUser.username || authenticatedUser.id,
                    importedAt: Date.now(),
                    importType: 'encrypted'
                });
            }
        }
        
        if (validAccounts.length === 0) {
            return new Response(JSON.stringify({ error: 'No valid accounts found in backup file' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        const encryptedData = await env.USER_DATA.get('accounts_encrypted');
        let existingAccounts = [];
        
        if (encryptedData) {
            try {
                const parsed = JSON.parse(encryptedData);
                existingAccounts = await decryptData(parsed, env.ENCRYPTION_KEY || env.JWT_SECRET);
            } catch (decryptError) {
                const legacyData = await env.USER_DATA.get('accounts');
                existingAccounts = legacyData ? JSON.parse(legacyData) : [];
            }
        }
        
        const allAccounts = [...existingAccounts];
        let addedCount = 0;
        
        for (const newAccount of validAccounts) {
            const isDuplicate = allAccounts.some(existing => 
                existing.service.toLowerCase() === newAccount.service.toLowerCase() && 
                existing.account.toLowerCase() === newAccount.account.toLowerCase()
            );
            
            if (!isDuplicate) {
                allAccounts.push(newAccount);
                addedCount++;
            }
        }
        
        const encrypted = await encryptData(allAccounts, env.ENCRYPTION_KEY || env.JWT_SECRET);
        await env.USER_DATA.put('accounts_encrypted', JSON.stringify(encrypted));
        
        await logSecurityEvent('SECURE_IMPORT_SUCCESS', { 
            totalImported: validAccounts.length,
            actuallyAdded: addedCount,
            duplicatesSkipped: validAccounts.length - addedCount
        }, request);
        
        return new Response(JSON.stringify({
            success: true,
            count: addedCount,
            total: validAccounts.length,
            duplicates: validAccounts.length - addedCount,
            message: `Successfully imported ${addedCount} accounts from encrypted backup (${validAccounts.length - addedCount} duplicates skipped)`
        }), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        await logSecurityEvent('SECURE_IMPORT_ERROR', { error: error.message }, request);
        return new Response(JSON.stringify({ 
            error: 'Failed to import encrypted backup',
            message: error.message.includes('decrypt') ? 'Incorrect password or corrupted backup file' : error.message
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleGetWebDAVConfigs(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method !== 'GET') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    try {
        const configs = await loadWebDAVConfigsFromKV(env);
        
        return new Response(JSON.stringify({
            success: true,
            configs: configs
        }), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ 
            error: 'Failed to load WebDAV configurations',
            message: error.message
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

async function handleSaveWebDAVConfigs(request, env) {
    const corsHeaders = getCorsHeaders(request, env);
    const authenticatedUser = await getAuthenticatedUser(request, env);
    
    if (!authenticatedUser) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
    
    try {
        const { configs } = await request.json();
        
        if (!Array.isArray(configs)) {
            return new Response(JSON.stringify({ error: 'Configs must be an array' }), {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
        
        for (const config of configs) {
            const validation = validateWebDAVConfig(config);
            if (!validation.isValid) {
                return new Response(JSON.stringify({ 
                    error: `Invalid WebDAV configuration: ${validation.errors.join(', ')}` 
                }), {
                    status: 400,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
        }
        
        const success = await saveWebDAVConfigToKV(configs, env);
        
        if (success) {
            await logSecurityEvent('WEBDAV_CONFIGS_SAVED', { count: configs.length }, request);
            
            return new Response(JSON.stringify({
                success: true,
                message: 'WebDAV configurations saved successfully'
            }), {
                status: 200,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        } else {
            throw new Error('Failed to save configurations');
        }
    } catch (error) {
        await logSecurityEvent('WEBDAV_CONFIGS_SAVE_ERROR', { error: error.message }, request);
        return new Response(JSON.stringify({ 
            error: 'Failed to save WebDAV configurations',
            message: error.message
        }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
}

// ===== 主请求处理函数 =====
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const corsHeaders = getCorsHeaders(request, env);
        
        if (request.method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: corsHeaders });
        }
        
        try {
            if (path === '/' || path === '/index.html') {
                const html = getMainHTML();
                return new Response(html, {
                    headers: { 
                        'Content-Type': 'text/html',
                        'X-Content-Type-Options': 'nosniff',
                        'X-Frame-Options': 'DENY',
                        'Referrer-Policy': 'strict-origin-when-cross-origin',
                        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://jsdelivr.b-cdn.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self';"
                    }
                });
            }
            
            if (path === '/api/oauth/authorize') return await handleOAuthAuthorize(request, env);
            if (path === '/api/oauth/callback') return await handleOAuthCallback(request, env);
            if (path === '/api/accounts') return await handleAccounts(request, env);
            if (path === '/api/accounts/clear-all') return await handleClearAllAccounts(request, env);
            if (path.startsWith('/api/accounts/')) {
                const accountId = path.split('/')[3];
                return await handleAccountUpdate(request, env, accountId);
            }
            if (path === '/api/generate-totp') return await handleGenerateTOTP(request, env);
            if (path === '/api/parse-uri') return await handleParseURI(request, env);
            if (path === '/api/add-from-uri') return await handleAddFromURI(request, env);
            if (path === '/api/export-secure') return await handleSecureExport(request, env);
            if (path === '/api/import') return await handleImport(request, env);
            if (path === '/api/import-secure') return await handleSecureImport(request, env);
            if (path === '/api/test-webdav') return await handleTestWebDAV(request, env);
            if (path === '/api/list-webdav-backups') return await handleListWebDAVBackups(request, env);
            if (path === '/api/download-webdav') return await handleDownloadWebDAV(request, env);
            if (path === '/api/restore-webdav') return await handleRestoreWebDAV(request, env);
            if (path === '/api/export-webdav') return await handleExportWebDAV(request, env);
            if (path === '/api/get-webdav-configs') return await handleGetWebDAVConfigs(request, env);
            if (path === '/api/save-webdav-configs') return await handleSaveWebDAVConfigs(request, env);
            
            return new Response(JSON.stringify({ error: 'Not found' }), {
                status: 404,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        } catch (error) {
            console.error('Request handling error:', error);
            return new Response(JSON.stringify({ 
                error: 'Internal server error',
                message: error.message
            }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    }
};
