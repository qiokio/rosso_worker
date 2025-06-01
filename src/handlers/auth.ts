import { sign } from 'jsonwebtoken';
import { hashPassword, comparePassword } from '../utils/password';
import { setCookie, getCookie, clearCookie } from '../utils/cookies';
import { ExtendedRequest, AuthResult, JwtPayload } from '../types';
import { verifyToken, verifyJwt } from '../utils/auth';

// 处理认证相关的请求
export const handleAuth = {
  // 用户登录
  async login(request: ExtendedRequest): Promise<Response> {
    try {
      const { email, password } = await request.json() as { email: string, password: string };
      
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
      const userJson = await request.env.SSO_STORE.get(`user:${email}`);
      
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
      const isPasswordValid = await comparePassword(password, user.password);
      
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
      const accessToken = sign(
        { 
          sub: user.id,
          email: user.email,
          name: user.name,
          role: user.role
        },
        request.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      
      const refreshToken = sign(
        { sub: user.id, email: user.email },
        request.env.JWT_SECRET,
        { expiresIn: '7d' }
      );
      
      // 存储刷新令牌到会话存储
      const sessionId = crypto.randomUUID();
      await request.env.SSO_STORE.put(`session:${sessionId}`, JSON.stringify({
        userId: user.id,
        email: user.email,
        refreshToken,
        createdAt: new Date().toISOString()
      }), { expirationTtl: 60 * 60 * 24 * 7 }) // 7天过期
      
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
      setCookie(response, 'refreshToken', sessionId, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/',
        maxAge: 60 * 60 * 24 * 7 // 7天
      });
      
      return response;
    } catch (error) {
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
  async logout(request: ExtendedRequest): Promise<Response> {
    try {
      // 从Cookie中获取会话ID
      const sessionId = getCookie(request, 'refreshToken');
      
      if (sessionId) {
        // 从KV存储中删除会话
        await request.env.SSO_STORE.delete(`session:${sessionId}`);
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
      clearCookie(response, 'refreshToken', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/'
      });
      
      return response;
    } catch (error) {
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
  async getCurrentUser(request: ExtendedRequest): Promise<Response> {
    try {
      // 验证请求权限
      const authResult = await verifyToken(request);
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
    } catch (error) {
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
  async refreshToken(request: ExtendedRequest): Promise<Response> {
    try {
      // 从Cookie中获取会话ID
      const sessionId = getCookie(request, 'refreshToken');
      
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
      const sessionJson = await request.env.SSO_STORE.get(`session:${sessionId}`);
      
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
        verifyJwt(session.refreshToken, request.env.JWT_SECRET);
      } catch (error) {
        // 删除无效会话
        await request.env.SSO_STORE.delete(`session:${sessionId}`);
        
        return new Response(JSON.stringify({
          success: false,
          message: '无效或过期的刷新令牌'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 从KV存储中获取用户信息
      const userJson = await request.env.SSO_STORE.get(`user:${session.email}`);
      
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
      const accessToken = sign(
        { 
          sub: user.id,
          email: user.email,
          name: user.name,
          role: user.role
        },
        request.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      
      return new Response(JSON.stringify({
        success: true,
        message: '令牌已刷新',
        accessToken
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
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
  },
  
  // 用户注册
  async register(request: ExtendedRequest): Promise<Response> {
    try {
      // 获取请求体
      const { username, email, password } = await request.json() as { username: string, email: string, password: string };
      
      // 验证必填字段
      if (!username || !email || !password) {
        return new Response(JSON.stringify({
          success: false,
          message: '用户名、邮箱和密码为必填项'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 验证邮箱格式
      const emailRegex = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;
      if (!emailRegex.test(email)) {
        return new Response(JSON.stringify({
          success: false,
          message: '邮箱格式不正确'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 检查邮箱是否已存在
      const existingUser = await request.env.SSO_STORE.get(`user:${email}`);
      if (existingUser) {
        return new Response(JSON.stringify({
          success: false,
          message: '该邮箱已被注册'
        }), {
          status: 409,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 哈希密码
      const hashedPassword = await hashPassword(password);
      
      // 创建用户ID
      const userId = crypto.randomUUID();
      
      // 创建用户对象
      const user = {
        id: userId,
        email,
        name: username,
        password: hashedPassword,
        role: 'user', // 默认角色为普通用户
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      
      // 存储用户信息到KV
      await request.env.SSO_STORE.put(`user:${email}`, JSON.stringify(user));
      
      return new Response(JSON.stringify({
        success: true,
        message: '注册成功',
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role
        }
      }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('注册错误:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '注册过程中发生错误',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },
  
  // 忘记密码
  async forgotPassword(request: ExtendedRequest): Promise<Response> {
    try {
      // 获取请求体
      const { email } = await request.json() as { email: string };
      
      // 验证必填字段
      if (!email) {
        return new Response(JSON.stringify({
          success: false,
          message: '邮箱为必填项'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 检查用户是否存在
      const userJson = await request.env.SSO_STORE.get(`user:${email}`);
      if (!userJson) {
        // 为了安全考虑，即使用户不存在也返回成功
        return new Response(JSON.stringify({
          success: true,
          message: '如果该邮箱已注册，重置密码链接将发送到您的邮箱'
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 在实际应用中，这里应该生成重置令牌并发送邮件
      // 由于这是一个示例，我们只返回成功消息
      
      return new Response(JSON.stringify({
        success: true,
        message: '如果该邮箱已注册，重置密码链接将发送到您的邮箱'
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('忘记密码错误:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '处理忘记密码请求时发生错误',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
};
