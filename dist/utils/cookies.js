"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.setCookie = setCookie;
exports.getCookie = getCookie;
exports.clearCookie = clearCookie;
// 设置Cookie
function setCookie(response, name, value, options = {}) {
    const cookieHeader = response.headers.get('Set-Cookie') || '';
    const cookies = cookieHeader.split(', ');
    // 构建Cookie字符串
    let cookie = `${name}=${value}`;
    if (options.httpOnly)
        cookie += '; HttpOnly';
    if (options.secure)
        cookie += '; Secure';
    if (options.sameSite)
        cookie += `; SameSite=${options.sameSite}`;
    if (options.path)
        cookie += `; Path=${options.path}`;
    if (options.maxAge)
        cookie += `; Max-Age=${options.maxAge}`;
    cookies.push(cookie);
    // 设置回响应头
    response.headers.set('Set-Cookie', cookies.join(', '));
}
// 从请求中获取Cookie值
function getCookie(request, name) {
    const cookieHeader = request.headers.get('Cookie') || '';
    const cookies = cookieHeader.split(';').map(c => c.trim());
    for (const cookie of cookies) {
        const [cookieName, cookieValue] = cookie.split('=');
        if (cookieName === name) {
            return cookieValue;
        }
    }
    return null;
}
// 清除Cookie
function clearCookie(response, name, options = {}) {
    // 设置过期的Cookie
    const cookieOptions = {
        ...options,
        maxAge: 0 // 立即过期
    };
    setCookie(response, name, '', cookieOptions);
}
