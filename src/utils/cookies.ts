// Cookie选项接口定义
interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  path?: string;
  maxAge?: number;
}

// 设置Cookie
export function setCookie(response: Response, name: string, value: string, options: CookieOptions = {}): void {
  const cookieHeader = response.headers.get('Set-Cookie') || '';
  const cookies = cookieHeader.split(', ');
  
  // 构建Cookie字符串
  let cookie = `${name}=${value}`;
  
  if (options.httpOnly) cookie += '; HttpOnly';
  if (options.secure) cookie += '; Secure';
  if (options.sameSite) cookie += `; SameSite=${options.sameSite}`;
  if (options.path) cookie += `; Path=${options.path}`;
  if (options.maxAge) cookie += `; Max-Age=${options.maxAge}`;
  
  cookies.push(cookie);
  
  // 设置回响应头
  response.headers.set('Set-Cookie', cookies.join(', '));
}

// 从请求中获取Cookie值
export function getCookie(request: Request, name: string): string | null {
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
export function clearCookie(response: Response, name: string, options: CookieOptions = {}): void {
  // 设置过期的Cookie
  const cookieOptions = {
    ...options,
    maxAge: 0 // 立即过期
  };
  
  setCookie(response, name, '', cookieOptions);
}
