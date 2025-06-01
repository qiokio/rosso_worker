import { verifyToken } from '../utils/auth';
import { hashPassword } from '../utils/password';
import { ExtendedRequest, User } from '../types';

// 处理用户管理相关的请求
export const handleUsers = {
  // 获取用户列表
  async list(request: ExtendedRequest): Promise<Response> {
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
      
      // 检查是否为管理员
      if (authResult.user && authResult.user.role !== 'admin') {
        return new Response(JSON.stringify({
          success: false,
          message: '没有权限访问'
        }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 从KV存储中获取所有用户列表
      const userKeys = await request.env.SSO_STORE.list({ prefix: 'user:' });
      const users = [];
      
      for (const key of userKeys.keys) {
        const userJson = await request.env.SSO_STORE.get(key.name);
        if (userJson) {
          const user = JSON.parse(userJson);
          // 不返回密码
          delete (user as Partial<User>).password;
          users.push(user);
        }
      }
      
      return new Response(JSON.stringify({
        success: true,
        users
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('获取用户列表错误:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '获取用户列表时发生错误',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },
  
  // 创建新用户
  async create(request: ExtendedRequest): Promise<Response> {
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
      
      // 检查是否为管理员
      if (authResult.user && authResult.user.role !== 'admin') {
        return new Response(JSON.stringify({
          success: false,
          message: '没有权限执行此操作'
        }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 获取请求体
      const { email, name, password, role } = await request.json() as any;
      
      // 验证必填字段
      if (!email || !name || !password) {
        return new Response(JSON.stringify({
          success: false,
          message: '邮箱、姓名和密码为必填项'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 验证角色
      if (role && !['admin', 'user'].includes(role)) {
        return new Response(JSON.stringify({
          success: false,
          message: '角色必须是 admin 或 user'
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
      
      // 创建新用户
      const userId = crypto.randomUUID();
      const newUser: User = {
        id: userId,
        email,
        name,
        password: hashedPassword,
        role: role || 'user',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      
      // 存储用户信息到KV
      await request.env.SSO_STORE.put(`user:${email}`, JSON.stringify(newUser));
      
      // 不返回密码
      const userResponse = { ...newUser } as Partial<User>;
      delete userResponse.password;
      
      return new Response(JSON.stringify({
        success: true,
        message: '用户创建成功',
        user: userResponse
      }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('创建用户错误:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '创建用户时发生错误',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },
  
  // 获取单个用户
  async get(request: ExtendedRequest): Promise<Response> {
    try {
      // 获取用户ID
      const userId = request.params?.id;
      
      if (!userId) {
        return new Response(JSON.stringify({
          success: false,
          message: '用户ID不能为空'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
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
      
      // 从KV存储中获取所有用户
      const userKeys = await request.env.SSO_STORE.list({ prefix: 'user:' });
      let targetUser = null;
      
      for (const key of userKeys.keys) {
        const userJson = await request.env.SSO_STORE.get(key.name);
        if (userJson) {
          const user = JSON.parse(userJson);
          if (user.id === userId) {
            targetUser = user;
            break;
          }
        }
      }
      
      if (!targetUser) {
        return new Response(JSON.stringify({
          success: false,
          message: '用户不存在'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 检查权限：管理员可以查看所有用户，普通用户只能查看自己
      if (authResult.user && authResult.user.role !== 'admin' && authResult.user.sub !== targetUser.id) {
        return new Response(JSON.stringify({
          success: false,
          message: '没有权限访问'
        }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 不返回密码
      delete (targetUser as Partial<User>).password;
      
      return new Response(JSON.stringify({
        success: true,
        user: targetUser
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('获取用户信息错误:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '获取用户信息时发生错误',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },
  
  // 更新用户信息
  async update(request: ExtendedRequest): Promise<Response> {
    try {
      // 获取用户ID
      const userId = request.params?.id;
      
      if (!userId) {
        return new Response(JSON.stringify({
          success: false,
          message: '用户ID不能为空'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
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
      
      // 从KV存储中获取所有用户
      const userKeys = await request.env.SSO_STORE.list({ prefix: 'user:' });
      let targetUser = null;
      let userEmail = null;
      
      for (const key of userKeys.keys) {
        const userJson = await request.env.SSO_STORE.get(key.name);
        if (userJson) {
          const user = JSON.parse(userJson);
          if (user.id === userId) {
            targetUser = user;
            userEmail = user.email;
            break;
          }
        }
      }
      
      if (!targetUser || !userEmail) {
        return new Response(JSON.stringify({
          success: false,
          message: '用户不存在'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 检查权限：管理员可以更新所有用户，普通用户只能更新自己
      if (authResult.user && authResult.user.role !== 'admin' && authResult.user.sub !== targetUser.id) {
        return new Response(JSON.stringify({
          success: false,
          message: '没有权限执行此操作'
        }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 获取请求体
      const { name, password, role } = await request.json() as any;
      
      // 更新用户信息
      if (name) targetUser.name = name;
      
      // 只有管理员可以更改角色
      if (role && authResult.user && authResult.user.role === 'admin') {
        if (!['admin', 'user'].includes(role)) {
          return new Response(JSON.stringify({
            success: false,
            message: '角色必须是 admin 或 user'
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        targetUser.role = role;
      }
      
      // 更新密码（如果提供）
      if (password) {
        targetUser.password = await hashPassword(password);
      }
      
      targetUser.updatedAt = new Date().toISOString();
      
      // 存储更新后的用户信息
      await request.env.SSO_STORE.put(`user:${userEmail}`, JSON.stringify(targetUser));
      
      // 不返回密码
      const userResponse = { ...targetUser } as Partial<User>;
      delete userResponse.password;
      
      return new Response(JSON.stringify({
        success: true,
        message: '用户信息更新成功',
        user: userResponse
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('更新用户信息错误:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '更新用户信息时发生错误',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },
  
  // 删除用户
  async delete(request: ExtendedRequest): Promise<Response> {
    try {
      // 获取用户ID
      const userId = request.params?.id;
      
      if (!userId) {
        return new Response(JSON.stringify({
          success: false,
          message: '用户ID不能为空'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
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
      
      // 只有管理员可以删除用户
      if (authResult.user && authResult.user.role !== 'admin') {
        return new Response(JSON.stringify({
          success: false,
          message: '没有权限执行此操作'
        }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 从KV存储中获取所有用户
      const userKeys = await request.env.SSO_STORE.list({ prefix: 'user:' });
      let userKeyToDelete = null;
      
      for (const key of userKeys.keys) {
        const userJson = await request.env.SSO_STORE.get(key.name);
        if (userJson) {
          const user = JSON.parse(userJson);
          if (user.id === userId) {
            userKeyToDelete = key.name;
            break;
          }
        }
      }
      
      if (!userKeyToDelete) {
        return new Response(JSON.stringify({
          success: false,
          message: '用户不存在'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 删除用户
      await request.env.SSO_STORE.delete(userKeyToDelete);
      
      return new Response(JSON.stringify({
        success: true,
        message: '用户删除成功'
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('删除用户错误:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '删除用户时发生错误',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
};
