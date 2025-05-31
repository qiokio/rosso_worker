"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const itty_router_1 = require("itty-router");
const auth_1 = require("./handlers/auth");
const users_1 = require("./handlers/users");
const applications_1 = require("./handlers/applications");
const saml_1 = require("./handlers/saml");
const oidc_1 = require("./handlers/oidc");
const cors_1 = require("./utils/cors");
// 创建路由器实例
const router = (0, itty_router_1.Router)();
// 中间件: 处理CORS预检请求
router.options('*', request => {
    return new Response(null, {
        headers: cors_1.corsHeaders
    });
});
// 认证相关路由
router.post('/api/auth/login', auth_1.handleAuth.login);
router.post('/api/auth/logout', auth_1.handleAuth.logout);
router.get('/api/auth/user', auth_1.handleAuth.getCurrentUser);
router.post('/api/auth/refresh', auth_1.handleAuth.refreshToken);
// SAML 相关路由
router.get('/api/auth/saml/metadata/:appId', saml_1.handleSaml.metadata);
router.post('/api/auth/saml/login/:appId', saml_1.handleSaml.login);
router.post('/api/auth/saml/callback', saml_1.handleSaml.callback);
router.post('/api/auth/saml/logout', saml_1.handleSaml.logout);
// OIDC 相关路由
router.get('/api/auth/oidc/authorize', oidc_1.handleOidc.authorize);
router.post('/api/auth/oidc/token', oidc_1.handleOidc.token);
router.get('/api/auth/oidc/userinfo', oidc_1.handleOidc.userInfo);
router.post('/api/auth/oidc/callback', oidc_1.handleOidc.callback);
// 用户管理路由
router.get('/api/users', users_1.handleUsers.list);
router.post('/api/users', users_1.handleUsers.create);
router.get('/api/users/:id', users_1.handleUsers.get);
router.put('/api/users/:id', users_1.handleUsers.update);
router.delete('/api/users/:id', users_1.handleUsers.delete);
// 应用管理路由
router.get('/api/applications', applications_1.handleApplications.list);
router.post('/api/applications', applications_1.handleApplications.create);
router.get('/api/applications/:id', applications_1.handleApplications.get);
router.put('/api/applications/:id', applications_1.handleApplications.update);
router.delete('/api/applications/:id', applications_1.handleApplications.delete);
// 404处理程序
router.all('*', () => new Response('404 - 找不到资源', { status: 404 }));
// 主事件监听器
exports.default = {
    async fetch(request, env, ctx) {
        try {
            // 将环境变量添加到请求中以便在处理程序中访问
            const extendedRequest = request;
            extendedRequest.env = env;
            // 处理请求
            const response = await router.handle(extendedRequest);
            // 添加CORS头
            if (request.method !== 'OPTIONS') {
                const headers = new Headers(response.headers);
                Object.entries(cors_1.corsHeaders).forEach(([key, value]) => {
                    headers.set(key, value);
                });
                return new Response(response.body, {
                    status: response.status,
                    statusText: response.statusText,
                    headers
                });
            }
            return response;
        }
        catch (error) {
            console.error('处理请求时发生错误:', error);
            return new Response(JSON.stringify({
                success: false,
                message: '服务器内部错误',
                error: error instanceof Error ? error.message : String(error)
            }), {
                status: 500,
                headers: {
                    'Content-Type': 'application/json',
                    ...cors_1.corsHeaders
                }
            });
        }
    }
};
