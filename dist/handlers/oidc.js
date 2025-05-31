"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handleOidc = void 0;
const auth_1 = require("../utils/auth");
const jsonwebtoken_1 = require("jsonwebtoken");
// OIDC处理程序
exports.handleOidc = {
    // 授权端点
    async authorize(request) {
        try {
            const env = request.env;
            const url = new URL(request.url);
            const params = url.searchParams;
            // 获取必要参数
            const clientId = params.get('client_id');
            const responseType = params.get('response_type');
            const redirectUri = params.get('redirect_uri');
            const scope = params.get('scope');
            const state = params.get('state');
            const nonce = params.get('nonce');
            // 验证必要参数
            if (!clientId || !responseType || !redirectUri) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '缺少必要参数'
                }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // 验证响应类型
            if (!['code', 'token', 'id_token', 'code token', 'code id_token', 'token id_token', 'code token id_token']
                .includes(responseType)) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '不支持的响应类型'
                }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // 寻找对应的应用
            const appKeys = await env.APPLICATIONS.list({ prefix: 'app:' });
            let app = null;
            for (const key of appKeys.keys) {
                const appJson = await env.APPLICATIONS.get(key.name);
                if (appJson) {
                    const appData = JSON.parse(appJson);
                    if (appData.clientId === clientId) {
                        app = appData;
                        break;
                    }
                }
            }
            if (!app) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '客户端ID无效'
                }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // 验证应用类型
            if (app.type !== 'oidc') {
                return new Response(JSON.stringify({
                    success: false,
                    message: '应用类型不是OIDC'
                }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // 验证重定向URI
            if (!app.redirectUris.includes(redirectUri)) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '重定向URI未授权'
                }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // 创建授权会话
            const sessionId = crypto.randomUUID();
            await env.SESSIONS.put(`oidc:${sessionId}`, JSON.stringify({
                clientId,
                responseType,
                redirectUri,
                scope: scope || 'openid profile email',
                state,
                nonce,
                createdAt: Date.now()
            }), { expirationTtl: 60 * 10 }); // 10分钟过期
            // 返回会话ID，前端需要使用此ID继续登录流程
            return new Response(JSON.stringify({
                success: true,
                sessionId
            }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        catch (error) {
            console.error('OIDC授权请求处理错误:', error);
            return new Response(JSON.stringify({
                success: false,
                message: '处理OIDC授权请求时发生错误',
                error: error instanceof Error ? error.message : String(error)
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    },
    // 令牌端点
    async token(request) {
        try {
            const env = request.env;
            // 验证客户端凭据
            const authHeader = request.headers.get('Authorization');
            let clientId = '';
            let clientSecret = '';
            if (authHeader && authHeader.startsWith('Basic ')) {
                // 从Basic认证中提取客户端凭据
                const base64Credentials = authHeader.split(' ')[1];
                const credentials = atob(base64Credentials).split(':');
                clientId = credentials[0];
                clientSecret = credentials[1];
            }
            else {
                // 从请求体中获取客户端凭据
                const formData = await request.formData();
                clientId = formData.get('client_id')?.toString() || '';
                clientSecret = formData.get('client_secret')?.toString() || '';
            }
            if (!clientId || !clientSecret) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '缺少客户端凭据'
                }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // 寻找对应的应用
            const appKeys = await env.APPLICATIONS.list({ prefix: 'app:' });
            let app = null;
            for (const key of appKeys.keys) {
                const appJson = await env.APPLICATIONS.get(key.name);
                if (appJson) {
                    const appData = JSON.parse(appJson);
                    if (appData.clientId === clientId) {
                        app = appData;
                        break;
                    }
                }
            }
            if (!app || app.clientSecret !== clientSecret) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '客户端凭据无效'
                }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // 获取参数
            const formData = await request.formData();
            const grantType = formData.get('grant_type')?.toString();
            // 根据授权类型处理请求
            if (grantType === 'authorization_code') {
                const code = formData.get('code')?.toString();
                const redirectUri = formData.get('redirect_uri')?.toString();
                if (!code || !redirectUri) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: '缺少必要参数'
                    }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                // 验证重定向URI
                if (!app.redirectUris.includes(redirectUri)) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: '重定向URI与授权请求不匹配'
                    }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                // 获取并验证授权码
                const authCodeJson = await env.SESSIONS.get(`oidc-code:${code}`);
                if (!authCodeJson) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: '授权码无效或已过期'
                    }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                const authCode = JSON.parse(authCodeJson);
                // 验证客户端ID和重定向URI
                if (authCode.clientId !== clientId || authCode.redirectUri !== redirectUri) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: '授权码与客户端不匹配'
                    }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                // 授权码只能使用一次，立即删除
                await env.SESSIONS.delete(`oidc-code:${code}`);
                // 获取用户信息
                const userEmail = await env.USERS.get(`userId:${authCode.userId}`);
                if (!userEmail) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: '用户不存在'
                    }), {
                        status: 404,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                const userJson = await env.USERS.get(`user:${userEmail}`);
                if (!userJson) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: '用户不存在'
                    }), {
                        status: 404,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                const user = JSON.parse(userJson);
                // 生成访问令牌和ID令牌
                const accessToken = (0, jsonwebtoken_1.sign)({
                    sub: user.id,
                    email: user.email,
                    name: user.name,
                    scope: authCode.scope
                }, env.JWT_SECRET, { expiresIn: '1h', audience: clientId });
                let idToken = null;
                if (authCode.scope.includes('openid')) {
                    // 生成ID令牌
                    idToken = (0, jsonwebtoken_1.sign)({
                        sub: user.id,
                        email: user.email,
                        name: user.name,
                        nonce: authCode.nonce
                    }, env.JWT_SECRET, { expiresIn: '1h', audience: clientId });
                }
                // 生成刷新令牌
                const refreshToken = (0, jsonwebtoken_1.sign)({ sub: user.id }, env.JWT_SECRET, { expiresIn: '30d', audience: clientId });
                // 存储刷新令牌
                await env.SESSIONS.put(`oidc-refresh:${refreshToken}`, JSON.stringify({
                    userId: user.id,
                    clientId,
                    scope: authCode.scope,
                    createdAt: Date.now()
                }), { expirationTtl: 60 * 60 * 24 * 30 }); // 30天过期
                // 构建响应
                const response = {
                    access_token: accessToken,
                    token_type: 'Bearer',
                    expires_in: 3600,
                    refresh_token: refreshToken,
                    scope: authCode.scope
                };
                if (idToken) {
                    response['id_token'] = idToken;
                }
                return new Response(JSON.stringify(response), {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            else if (grantType === 'refresh_token') {
                const refreshTokenValue = formData.get('refresh_token')?.toString();
                if (!refreshTokenValue) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: '缺少刷新令牌'
                    }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                // 验证刷新令牌
                try {
                    const decoded = (0, jsonwebtoken_1.verify)(refreshTokenValue, env.JWT_SECRET);
                    // 验证客户端ID
                    if (decoded.aud !== clientId) {
                        return new Response(JSON.stringify({
                            success: false,
                            message: '刷新令牌与客户端不匹配'
                        }), {
                            status: 400,
                            headers: { 'Content-Type': 'application/json' }
                        });
                    }
                    // 获取刷新令牌数据
                    const refreshJson = await env.SESSIONS.get(`oidc-refresh:${refreshTokenValue}`);
                    if (!refreshJson) {
                        return new Response(JSON.stringify({
                            success: false,
                            message: '刷新令牌无效或已过期'
                        }), {
                            status: 400,
                            headers: { 'Content-Type': 'application/json' }
                        });
                    }
                    const refreshData = JSON.parse(refreshJson);
                    // 获取用户信息
                    const userEmail = await env.USERS.get(`userId:${refreshData.userId}`);
                    if (!userEmail) {
                        return new Response(JSON.stringify({
                            success: false,
                            message: '用户不存在'
                        }), {
                            status: 404,
                            headers: { 'Content-Type': 'application/json' }
                        });
                    }
                    const userJson = await env.USERS.get(`user:${userEmail}`);
                    if (!userJson) {
                        return new Response(JSON.stringify({
                            success: false,
                            message: '用户不存在'
                        }), {
                            status: 404,
                            headers: { 'Content-Type': 'application/json' }
                        });
                    }
                    const user = JSON.parse(userJson);
                    // 生成新的访问令牌
                    const accessToken = (0, jsonwebtoken_1.sign)({
                        sub: user.id,
                        email: user.email,
                        name: user.name,
                        scope: refreshData.scope
                    }, env.JWT_SECRET, { expiresIn: '1h', audience: clientId });
                    let idToken = null;
                    if (refreshData.scope.includes('openid')) {
                        // 生成ID令牌
                        idToken = (0, jsonwebtoken_1.sign)({
                            sub: user.id,
                            email: user.email,
                            name: user.name
                        }, env.JWT_SECRET, { expiresIn: '1h', audience: clientId });
                    }
                    // 构建响应
                    const response = {
                        access_token: accessToken,
                        token_type: 'Bearer',
                        expires_in: 3600,
                        scope: refreshData.scope
                    };
                    if (idToken) {
                        response['id_token'] = idToken;
                    }
                    return new Response(JSON.stringify(response), {
                        status: 200,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                catch (error) {
                    // 删除无效的刷新令牌
                    await env.SESSIONS.delete(`oidc-refresh:${refreshTokenValue}`);
                    return new Response(JSON.stringify({
                        success: false,
                        message: '刷新令牌无效或已过期'
                    }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
            }
            else if (grantType === 'client_credentials') {
                // 客户端凭据流程，用于服务器到服务器的通信
                const scope = formData.get('scope')?.toString() || '';
                // 生成访问令牌
                const accessToken = (0, jsonwebtoken_1.sign)({
                    sub: clientId,
                    scope
                }, env.JWT_SECRET, { expiresIn: '1h', audience: clientId });
                return new Response(JSON.stringify({
                    access_token: accessToken,
                    token_type: 'Bearer',
                    expires_in: 3600,
                    scope
                }), {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            else {
                return new Response(JSON.stringify({
                    success: false,
                    message: '不支持的授权类型'
                }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }
        catch (error) {
            console.error('OIDC令牌请求处理错误:', error);
            return new Response(JSON.stringify({
                success: false,
                message: '处理OIDC令牌请求时发生错误',
                error: error instanceof Error ? error.message : String(error)
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    },
    // 用户信息端点
    async userInfo(request) {
        try {
            const env = request.env;
            // 从请求头中获取访问令牌
            const authHeader = request.headers.get('Authorization');
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '未提供访问令牌'
                }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json', 'WWW-Authenticate': 'Bearer' }
                });
            }
            const token = authHeader.split(' ')[1];
            try {
                // 验证令牌
                const decoded = (0, jsonwebtoken_1.verify)(token, env.JWT_SECRET);
                // 检查范围是否包含openid
                if (!decoded.scope || !decoded.scope.includes('openid')) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: '令牌没有足够的权限'
                    }), {
                        status: 403,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                // 构建用户信息响应
                const userInfo = {
                    sub: decoded.sub
                };
                // 根据请求的范围添加用户信息
                if (decoded.scope.includes('profile') && decoded.name) {
                    userInfo.name = decoded.name;
                }
                if (decoded.scope.includes('email') && decoded.email) {
                    userInfo.email = decoded.email;
                    userInfo.email_verified = true; // 假设已验证
                }
                return new Response(JSON.stringify(userInfo), {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            catch (error) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '无效或过期的令牌'
                }), {
                    status: 401,
                    headers: {
                        'Content-Type': 'application/json',
                        'WWW-Authenticate': 'Bearer error="invalid_token", error_description="The access token is invalid"'
                    }
                });
            }
        }
        catch (error) {
            console.error('OIDC用户信息请求处理错误:', error);
            return new Response(JSON.stringify({
                success: false,
                message: '处理OIDC用户信息请求时发生错误',
                error: error instanceof Error ? error.message : String(error)
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    },
    // OIDC回调处理
    async callback(request) {
        try {
            const env = request.env;
            // 获取请求数据
            const data = await request.json();
            const { code, state, sessionId } = data;
            if (!code || !sessionId) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '缺少必要参数'
                }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // 获取OIDC会话信息
            const sessionJson = await env.SESSIONS.get(`oidc:${sessionId}`);
            if (!sessionJson) {
                return new Response(JSON.stringify({
                    success: false,
                    message: 'OIDC会话不存在或已过期'
                }), {
                    status: 404,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            const session = JSON.parse(sessionJson);
            // 验证state参数
            if (session.state && session.state !== state) {
                return new Response(JSON.stringify({
                    success: false,
                    message: 'state参数不匹配'
                }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // 获取当前登录用户信息
            const authResult = await (0, auth_1.verifyToken)(request);
            if (!authResult.success) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '用户未登录'
                }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // 创建授权码
            const authCode = crypto.randomUUID();
            // 存储授权码数据
            await env.SESSIONS.put(`oidc-code:${authCode}`, JSON.stringify({
                userId: authResult.user?.sub,
                clientId: session.clientId,
                redirectUri: session.redirectUri,
                scope: session.scope,
                nonce: session.nonce,
                createdAt: Date.now()
            }), { expirationTtl: 60 * 5 }); // 5分钟过期
            // 删除授权会话
            await env.SESSIONS.delete(`oidc:${sessionId}`);
            // 构建重定向URL
            let redirectUrl = session.redirectUri;
            // 根据响应类型构建不同的响应
            if (session.responseType === 'code') {
                // 授权码流程
                redirectUrl += (redirectUrl.includes('?') ? '&' : '?') + `code=${authCode}`;
                if (session.state) {
                    redirectUrl += `&state=${encodeURIComponent(session.state)}`;
                }
            }
            else {
                // 其他流程，如隐式流程等
                // 这里简化处理，仅实现授权码流程
                return new Response(JSON.stringify({
                    success: false,
                    message: '仅支持授权码流程'
                }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            return new Response(JSON.stringify({
                success: true,
                redirectUrl
            }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        catch (error) {
            console.error('OIDC回调处理错误:', error);
            return new Response(JSON.stringify({
                success: false,
                message: '处理OIDC回调时发生错误',
                error: error instanceof Error ? error.message : String(error)
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }
};
