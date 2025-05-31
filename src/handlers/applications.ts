import { verifyToken } from '../utils/auth';
import { ExtendedRequest, Application } from '../types';

// 应用管理处理程序
export const handleApplications = {
  /**
   * 获取应用列表
   */
  async list(request: ExtendedRequest): Promise<Response> {
    // 验证用户令牌
    const authResult = await verifyToken(request);
    if (!authResult.success) {
      return new Response(JSON.stringify({
        success: false,
        message: authResult.message || '未授权'
      }), {
        status: authResult.status,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      // 从KV存储中获取所有应用
      const { keys } = await request.env.APPLICATIONS.list();
      const applications: Application[] = [];

      for (const key of keys) {
        const appData = await request.env.APPLICATIONS.get(key.name, 'json');
        if (appData) {
          applications.push(appData as Application);
        }
      }

      // 根据用户角色过滤应用
      let filteredApps = applications;
      if (authResult.user && authResult.user.role !== 'admin') {
        filteredApps = applications.filter(app => {
          // 如果应用没有指定授权用户，则所有用户都可以访问
          if (!app.authorizedUsers || app.authorizedUsers.length === 0) {
            return true;
          }
          // 否则检查用户是否在授权列表中
          return app.authorizedUsers.includes(authResult.user!.sub);
        });
      }

      return new Response(JSON.stringify({
        success: true,
        data: filteredApps
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('获取应用列表失败:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '获取应用列表失败',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },

  /**
   * 创建新应用
   */
  async create(request: ExtendedRequest): Promise<Response> {
    // 验证用户令牌
    const authResult = await verifyToken(request);
    if (!authResult.success) {
      return new Response(JSON.stringify({
        success: false,
        message: authResult.message || '未授权'
      }), {
        status: authResult.status,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 只有管理员可以创建应用
    if (authResult.user && authResult.user.role !== 'admin') {
      return new Response(JSON.stringify({
        success: false,
        message: '权限不足，只有管理员可以创建应用'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      // 获取请求体
      const data = await request.json() as any;
      
      // 验证必填字段
      if (!data.name || !data.type) {
        return new Response(JSON.stringify({
          success: false,
          message: '应用名称和类型为必填项'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // 创建新应用
      const newApp: Application = {
        id: crypto.randomUUID(),
        name: data.name,
        description: data.description || '',
        type: data.type,
        clientId: data.type === 'oidc' ? crypto.randomUUID() : undefined,
        clientSecret: data.type === 'oidc' ? crypto.randomUUID() : undefined,
        redirectUris: data.redirectUris || [],
        signingCert: data.signingCert,
        encryptCert: data.encryptCert,
        authorizedUsers: data.authorizedUsers || [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      // 保存到KV存储
      await request.env.APPLICATIONS.put(newApp.id, JSON.stringify(newApp));

      return new Response(JSON.stringify({
        success: true,
        data: newApp
      }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('创建应用失败:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '创建应用失败',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },

  /**
   * 获取单个应用详情
   */
  async get(request: ExtendedRequest): Promise<Response> {
    // 验证用户令牌
    const authResult = await verifyToken(request);
    if (!authResult.success) {
      return new Response(JSON.stringify({
        success: false,
        message: authResult.message || '未授权'
      }), {
        status: authResult.status,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      const appId = request.params?.id;
      if (!appId) {
        return new Response(JSON.stringify({
          success: false,
          message: '应用ID不能为空'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // 从KV存储中获取应用
      const appData = await request.env.APPLICATIONS.get(appId, 'json') as Application | null;
      if (!appData) {
        return new Response(JSON.stringify({
          success: false,
          message: '应用不存在'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // 检查用户是否有权限访问该应用
      if (authResult.user && authResult.user.role !== 'admin') {
        if (appData.authorizedUsers && appData.authorizedUsers.length > 0 && 
            !appData.authorizedUsers.includes(authResult.user.sub)) {
          return new Response(JSON.stringify({
            success: false,
            message: '无权访问该应用'
          }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      }

      return new Response(JSON.stringify({
        success: true,
        data: appData
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('获取应用详情失败:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '获取应用详情失败',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },

  /**
   * 更新应用
   */
  async update(request: ExtendedRequest): Promise<Response> {
    // 验证用户令牌
    const authResult = await verifyToken(request);
    if (!authResult.success) {
      return new Response(JSON.stringify({
        success: false,
        message: authResult.message || '未授权'
      }), {
        status: authResult.status,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 只有管理员可以更新应用
    if (authResult.user && authResult.user.role !== 'admin') {
      return new Response(JSON.stringify({
        success: false,
        message: '权限不足，只有管理员可以更新应用'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      const appId = request.params?.id;
      if (!appId) {
        return new Response(JSON.stringify({
          success: false,
          message: '应用ID不能为空'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // 从KV存储中获取应用
      const existingApp = await request.env.APPLICATIONS.get(appId, 'json') as Application | null;
      if (!existingApp) {
        return new Response(JSON.stringify({
          success: false,
          message: '应用不存在'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      const data = await request.json() as any;
      
      // 更新应用信息
      const updatedApp: Application = {
        ...existingApp,
        name: data.name || existingApp.name,
        description: data.description !== undefined ? data.description : existingApp.description,
        type: existingApp.type, // 不允许更改应用类型
        redirectUris: data.redirectUris || existingApp.redirectUris,
        signingCert: data.signingCert !== undefined ? data.signingCert : existingApp.signingCert,
        encryptCert: data.encryptCert !== undefined ? data.encryptCert : existingApp.encryptCert,
        authorizedUsers: data.authorizedUsers || existingApp.authorizedUsers,
        updatedAt: new Date().toISOString()
      };

      // 保存到KV存储
      await request.env.APPLICATIONS.put(updatedApp.id, JSON.stringify(updatedApp));

      return new Response(JSON.stringify({
        success: true,
        data: updatedApp
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('更新应用失败:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '更新应用失败',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },

  /**
   * 删除应用
   */
  async delete(request: ExtendedRequest): Promise<Response> {
    // 验证用户令牌
    const authResult = await verifyToken(request);
    if (!authResult.success) {
      return new Response(JSON.stringify({
        success: false,
        message: authResult.message || '未授权'
      }), {
        status: authResult.status,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 只有管理员可以删除应用
    if (authResult.user && authResult.user.role !== 'admin') {
      return new Response(JSON.stringify({
        success: false,
        message: '权限不足，只有管理员可以删除应用'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      const appId = request.params?.id;
      if (!appId) {
        return new Response(JSON.stringify({
          success: false,
          message: '应用ID不能为空'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // 检查应用是否存在
      const existingApp = await request.env.APPLICATIONS.get(appId, 'json');
      if (!existingApp) {
        return new Response(JSON.stringify({
          success: false,
          message: '应用不存在'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // 从KV存储中删除应用
      await request.env.APPLICATIONS.delete(appId);

      return new Response(JSON.stringify({
        success: true,
        message: '应用已成功删除'
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('删除应用失败:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '删除应用失败',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
};
