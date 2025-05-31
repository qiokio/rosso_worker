import { Router } from 'itty-router';
import { handleAuth } from './handlers/auth';
import { handleUsers } from './handlers/users';
import { handleApplications } from './handlers/applications';
import { handleSaml } from './handlers/saml';
import { handleOidc } from './handlers/oidc';
import { corsHeaders } from './utils/cors';
import { ExtendedRequest } from './types';

// 创建路由器实例
const router = Router<ExtendedRequest>();

// 中间件: 处理CORS预检请求
router.options('*', request => {
  return new Response(null, {
    headers: corsHeaders
  });
});

// 认证相关路由
router.post('/api/auth/login', handleAuth.login);
router.post('/api/auth/logout', handleAuth.logout);
router.get('/api/auth/user', handleAuth.getCurrentUser);
router.post('/api/auth/refresh', handleAuth.refreshToken);

// SAML 相关路由
router.get('/api/auth/saml/metadata/:appId', handleSaml.metadata);
router.post('/api/auth/saml/login/:appId', handleSaml.login);
router.post('/api/auth/saml/callback', handleSaml.callback);
router.post('/api/auth/saml/logout', handleSaml.logout);

// OIDC 相关路由
router.get('/api/auth/oidc/authorize', handleOidc.authorize);
router.post('/api/auth/oidc/token', handleOidc.token);
router.get('/api/auth/oidc/userinfo', handleOidc.userInfo);
router.post('/api/auth/oidc/callback', handleOidc.callback);

// 用户管理路由
router.get('/api/users', handleUsers.list);
router.post('/api/users', handleUsers.create);
router.get('/api/users/:id', handleUsers.get);
router.put('/api/users/:id', handleUsers.update);
router.delete('/api/users/:id', handleUsers.delete);

// 应用管理路由
router.get('/api/applications', handleApplications.list);
router.post('/api/applications', handleApplications.create);
router.get('/api/applications/:id', handleApplications.get);
router.put('/api/applications/:id', handleApplications.update);
router.delete('/api/applications/:id', handleApplications.delete);

// 404处理程序
router.all('*', () => new Response('404 - 找不到资源', { status: 404 }));

// 环境变量接口定义
export interface Env {
  JWT_SECRET: string;
  COOKIE_SECRET: string;
  AUTH_DOMAIN: string;
  SSO_STORE: KVNamespace;
  SSO_DB: D1Database;
  APPLICATIONS: KVNamespace;
  SESSIONS: KVNamespace;
  USERS: KVNamespace;
}

// 主事件监听器
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      // 将环境变量添加到请求中以便在处理程序中访问
      const extendedRequest = request as unknown as ExtendedRequest;
      extendedRequest.env = env;
      
      // 处理请求
      const response = await router.handle(extendedRequest);
      
      // 添加CORS头
      if (request.method !== 'OPTIONS') {
        const headers = new Headers(response.headers);
        Object.entries(corsHeaders).forEach(([key, value]) => {
          headers.set(key, value);
        });
        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers
        });
      }
      
      return response;
    } catch (error) {
      console.error('处理请求时发生错误:', error);
      
      return new Response(JSON.stringify({
        success: false,
        message: '服务器内部错误',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }
  }
};
