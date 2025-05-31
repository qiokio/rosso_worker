"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handleAuth = void 0;
const jsonwebtoken_1 = require("jsonwebtoken");
const password_1 = require("../utils/password");
const cookies_1 = require("../utils/cookies");
const auth_1 = require("../utils/auth");
// 处理认证相关的请求
exports.handleAuth = {
    // 用户登录
    async login(request) {
        try {
            const { email, password } = await request.json();
            if (!email || !password) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '邮箱和密码不能为空'
                }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // 从KV存储中获取用户信息
            const userJson = await request.env.USERS.get(`user:${email}`);
            if (!userJson) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '用户不存在或密码错误'
                }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            const user = JSON.parse(userJson);
            // 验证密码
            const isPasswordValid = await (0, password_1.comparePassword)(password, user.password);
            if (!isPasswordValid) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '用户不存在或密码错误'
                }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // 创建访问令牌和刷新令牌
            const accessToken = (0, jsonwebtoken_1.sign)({
                sub: user.id,
                email: user.email,
                name: user.name,
                role: user.role
            }, request.env.JWT_SECRET, { expiresIn: '1h' });
            const refreshToken = (0, jsonwebtoken_1.sign)({ sub: user.id, email: user.email }, request.env.JWT_SECRET, { expiresIn: '7d' });
            // 存储刷新令牌到会话存储
            const sessionId = crypto.randomUUID();
            await request.env.SESSIONS.put(`session:${sessionId}`, JSON.stringify({
                userId: user.id,
                email: user.email,
                refreshToken,
                createdAt: new Date().toISOString()
            }), { expirationTtl: 60 * 60 * 24 * 7 }); // 7天过期
            // 创建响应
            const response = new Response(JSON.stringify({
                success: true,
                message: '登录成功',
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    role: user.role
                },
                accessToken
            }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
            // 设置Cookie
            (0, cookies_1.setCookie)(response, 'refreshToken', sessionId, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                path: '/',
                maxAge: 60 * 60 * 24 * 7 // 7天
            });
            return response;
        }
        catch (error) {
            console.error('登录错误:', error);
            return new Response(JSON.stringify({
                success: false,
                message: '登录过程中发生错误',
                error: error instanceof Error ? error.message : String(error)
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    },
    // 用户登出
    async logout(request) {
        try {
            // 从Cookie中获取会话ID
            const sessionId = (0, cookies_1.getCookie)(request, 'refreshToken');
            if (sessionId) {
                // 从KV存储中删除会话
                await request.env.SESSIONS.delete(`session:${sessionId}`);
            }
            // 创建响应
            const response = new Response(JSON.stringify({
                success: true,
                message: '登出成功'
            }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
            // 清除Cookie
            (0, cookies_1.clearCookie)(response, 'refreshToken', {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                path: '/'
            });
            return response;
        }
        catch (error) {
            console.error('登出错误:', error);
            return new Response(JSON.stringify({
                success: false,
                message: '登出过程中发生错误',
                error: error instanceof Error ? error.message : String(error)
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    },
    // 获取当前用户信息
    async getCurrentUser(request) {
        try {
            // 验证请求权限
            const authResult = await (0, auth_1.verifyToken)(request);
            if (!authResult.success) {
                return new Response(JSON.stringify({
                    success: false,
                    message: authResult.message
                }), {
                    status: authResult.status,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // 不需要删除password，因为JwtPayload中没有这个属性
            return new Response(JSON.stringify({
                success: true,
                user: authResult.user
            }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        catch (error) {
            console.error('获取当前用户信息错误:', error);
            return new Response(JSON.stringify({
                success: false,
                message: '获取当前用户信息时发生错误',
                error: error instanceof Error ? error.message : String(error)
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    },
    // 刷新访问令牌
    async refreshToken(request) {
        try {
            // 从Cookie中获取会话ID
            const sessionId = (0, cookies_1.getCookie)(request, 'refreshToken');
            if (!sessionId) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '未提供刷新令牌'
                }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // 从KV存储中获取会话信息
            const sessionJson = await request.env.SESSIONS.get(`session:${sessionId}`);
            if (!sessionJson) {
                return new Response(JSON.stringify({
                    success: false,
                    message: '无效或过期的会话'
                }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            const session = JSON.parse(sessionJson);
            // 验证刷新令牌
            try {
                (0, auth_1.verifyJwt)(session.refreshToken, request.env.JWT_SECRET);
            }
            catch (error) {
                // 删除无效会话
                await request.env.SESSIONS.delete(`session:${sessionId}`);
                return new Response(JSON.stringify({
                    success: false,
                    message: '无效或过期的刷新令牌'
                }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            // 从KV存储中获取用户信息
            const userJson = await request.env.USERS.get(`user:${session.email}`);
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
            // 创建新的访问令牌
            const accessToken = (0, jsonwebtoken_1.sign)({
                sub: user.id,
                email: user.email,
                name: user.name,
                role: user.role
            }, request.env.JWT_SECRET, { expiresIn: '1h' });
            return new Response(JSON.stringify({
                success: true,
                message: '令牌已刷新',
                accessToken
            }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        catch (error) {
            console.error('刷新令牌错误:', error);
            return new Response(JSON.stringify({
                success: false,
                message: '刷新令牌时发生错误',
                error: error instanceof Error ? error.message : String(error)
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }
};
