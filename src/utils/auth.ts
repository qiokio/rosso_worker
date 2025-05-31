import { ExtendedRequest, AuthResult, JwtPayload } from '../types';

/**
 * 验证JWT令牌
 * @param request 请求对象
 * @returns 验证结果
 */
export async function verifyToken(request: ExtendedRequest): Promise<AuthResult> {
  try {
    // 从请求头或Cookie中获取令牌
    const authHeader = request.headers.get('Authorization');
    const token = authHeader ? authHeader.replace('Bearer ', '') : getCookie(request, 'token');
    
    if (!token) {
      return {
        success: false,
        message: '未提供认证令牌',
        status: 401
      };
    }
    
    // 解码并验证JWT令牌
    const payload = await verifyJwt(token, request.env.JWT_SECRET);
    
    if (!payload) {
      return {
        success: false,
        message: '无效的认证令牌',
        status: 401
      };
    }
    
    return {
      success: true,
      user: payload,
      status: 200
    };
  } catch (error) {
    console.error('令牌验证错误:', error);
    return {
      success: false,
      message: '令牌验证失败',
      status: 401
    };
  }
}

/**
 * 从请求中获取Cookie值
 * @param request 请求对象
 * @param name Cookie名称
 * @returns Cookie值
 */
export function getCookie(request: Request, name: string): string | null {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return null;
  
  const cookies = cookieHeader.split(';');
  for (const cookie of cookies) {
    const [cookieName, cookieValue] = cookie.trim().split('=');
    if (cookieName === name) {
      return cookieValue;
    }
  }
  
  return null;
}

/**
 * 验证JWT令牌
 * @param token JWT令牌
 * @param secret 密钥
 * @returns 解码后的载荷
 */
export async function verifyJwt(token: string, secret: string): Promise<JwtPayload | null> {
  try {
    // 将JWT密钥转换为加密密钥
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    // 解析JWT令牌
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    
    const header = parts[0];
    const payload = parts[1];
    const signature = parts[2];
    
    // 验证签名
    const signatureData = await crypto.subtle.verify(
      'HMAC',
      key,
      base64UrlDecode(signature),
      encoder.encode(`${header}.${payload}`)
    );
    
    if (!signatureData) {
      return null;
    }
    
    // 解码载荷
    const decodedPayload = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    
    // 验证过期时间
    if (decodedPayload.exp && decodedPayload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    
    return decodedPayload;
  } catch (error) {
    console.error('JWT验证错误:', error);
    return null;
  }
}

/**
 * Base64 URL解码
 * @param str 要解码的字符串
 * @returns 解码后的ArrayBuffer
 */
function base64UrlDecode(str: string): ArrayBuffer {
  // 将Base64 URL编码转换为标准Base64编码
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const base64Padded = base64 + padding;
  
  // 解码Base64字符串
  const rawData = atob(base64Padded);
  const outputArray = new Uint8Array(rawData.length);
  
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  
  return outputArray.buffer;
}
