import { verifyToken } from '../utils/auth';
import { ExtendedRequest } from '../types';

// 仪表盘处理程序
export const handleDashboard = {
  /**
   * 获取仪表盘统计数据
   */
  async getStats(request: ExtendedRequest): Promise<Response> {
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
      // 从KV存储中获取用户和应用数据以生成统计信息
      const [userKeys, appKeys, sessionKeys] = await Promise.all([
        request.env.SSO_STORE.list({ prefix: 'user:' }),
        request.env.APPLICATIONS.list(),
        request.env.SSO_STORE.list({ prefix: 'session:' })
      ]);

      // 计算用户数量
      const userCount = userKeys.keys.length;
      
      // 计算应用数量
      const appCount = appKeys.keys.length;
      
      // 计算活跃会话数
      const sessionCount = sessionKeys.keys.length;
      
      // 模拟统计数据
      const stats = [
        {
          name: '用户总数',
          stat: `${userCount}`,
          previousStat: `${Math.max(0, userCount - 2)}`,
          change: '+2',
          changeType: 'increase'
        },
        {
          name: '应用总数',
          stat: `${appCount}`,
          previousStat: `${Math.max(0, appCount - 1)}`,
          change: '+1',
          changeType: 'increase'
        },
        {
          name: '活跃会话',
          stat: `${sessionCount}`,
          previousStat: `${Math.max(0, sessionCount - 3)}`,
          change: '+3',
          changeType: 'increase'
        },
        {
          name: '认证成功率',
          stat: '98%',
          previousStat: '95%',
          change: '+3%',
          changeType: 'increase'
        }
      ];

      return new Response(JSON.stringify({
        success: true,
        stats
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('获取仪表盘统计数据失败:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '获取仪表盘统计数据失败',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },

  /**
   * 获取最近活动数据
   */
  async getActivities(request: ExtendedRequest): Promise<Response> {
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
      // 获取查询参数
      const url = new URL(request.url);
      const limit = parseInt(url.searchParams.get('limit') || '10', 10);

      // 模拟活动数据
      // 实际实现应该从数据库或日志中获取真实活动数据
      const activities = [
        {
          id: '1',
          type: '用户登录',
          user: 'admin@example.com',
          status: 'success',
          timestamp: new Date(Date.now() - 5 * 60000).toISOString()
        },
        {
          id: '2',
          type: 'SAML认证',
          user: 'user1@example.com',
          status: 'success',
          timestamp: new Date(Date.now() - 15 * 60000).toISOString(),
          details: 'Salesforce应用'
        },
        {
          id: '3',
          type: 'OIDC认证',
          user: 'user2@example.com',
          status: 'failed',
          timestamp: new Date(Date.now() - 30 * 60000).toISOString(),
          details: '无效的客户端ID'
        },
        {
          id: '4',
          type: '密码重置',
          user: 'user3@example.com',
          status: 'success',
          timestamp: new Date(Date.now() - 60 * 60000).toISOString()
        },
        {
          id: '5',
          type: '用户创建',
          user: 'admin@example.com',
          status: 'success',
          timestamp: new Date(Date.now() - 120 * 60000).toISOString(),
          details: '创建了新用户: user4@example.com'
        }
      ].slice(0, limit);

      return new Response(JSON.stringify({
        success: true,
        activities
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('获取活动数据失败:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '获取活动数据失败',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
}; 