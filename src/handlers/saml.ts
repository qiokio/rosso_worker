import { verifyToken } from '../utils/auth';
import { ServiceProvider, IdentityProvider } from 'samlify';
import { ExtendedRequest, SamlRequest } from '../types';

// SAML处理程序
export const handleSaml = {
  // 获取SAML元数据
  async metadata(request: ExtendedRequest): Promise<Response> {
    try {
      const env = request.env;
      const url = new URL(request.url);
      const appId = url.pathname.split('/').pop();
      
      if (!appId) {
        return new Response(JSON.stringify({
          success: false,
          message: '应用ID不能为空'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 从KV存储中获取应用信息
      const appJson = await env.APPLICATIONS.get(`app:${appId}`);
      
      if (!appJson) {
        return new Response(JSON.stringify({
          success: false,
          message: '应用不存在'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      const app = JSON.parse(appJson);
      
      // 检查应用类型是否为SAML
      if (app.type !== 'saml') {
        return new Response(JSON.stringify({
          success: false,
          message: '应用类型不是SAML'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 创建身份提供者实例
      const idp = IdentityProvider({
        metadata: `
          <EntityDescriptor entityID="https://${env.AUTH_DOMAIN}/api/auth/saml">
            <IDPSSODescriptor>
              <KeyDescriptor use="signing">
                <KeyInfo>
                  <X509Data>
                    <X509Certificate>${app.signingCert || ''}</X509Certificate>
                  </X509Data>
                </KeyInfo>
              </KeyDescriptor>
              <KeyDescriptor use="encryption">
                <KeyInfo>
                  <X509Data>
                    <X509Certificate>${app.encryptCert || ''}</X509Certificate>
                  </X509Data>
                </KeyInfo>
              </KeyDescriptor>
              <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
              <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
              <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
              <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://${env.AUTH_DOMAIN}/api/auth/saml/login/${app.id}"/>
              <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://${env.AUTH_DOMAIN}/api/auth/saml/logout"/>
            </IDPSSODescriptor>
          </EntityDescriptor>
        `
      });
      
      // 返回元数据XML
      const metadata = idp.getMetadata();
      
      return new Response(metadata, {
        status: 200,
        headers: { 'Content-Type': 'application/xml' }
      });
    } catch (error) {
      console.error('获取SAML元数据错误:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '获取SAML元数据时发生错误',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },
  
  // SAML登录请求处理
  async login(request: Request): Promise<Response> {
    try {
      const env = (request as any).env;
      const url = new URL(request.url);
      const appId = url.pathname.split('/').pop();
      
      if (!appId) {
        return new Response(JSON.stringify({
          success: false,
          message: '应用ID不能为空'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 从KV存储中获取应用信息
      const appJson = await env.APPLICATIONS.get(`app:${appId}`);
      
      if (!appJson) {
        return new Response(JSON.stringify({
          success: false,
          message: '应用不存在'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      const app = JSON.parse(appJson);
      
      // 检查应用类型是否为SAML
      if (app.type !== 'saml') {
        return new Response(JSON.stringify({
          success: false,
          message: '应用类型不是SAML'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 获取请求数据
      const data = await request.json() as any;
      const { SAMLRequest, RelayState } = data;
      
      // 验证SAMLRequest存在
      if (!SAMLRequest) {
        return new Response(JSON.stringify({
          success: false,
          message: 'SAML请求不能为空'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 创建服务提供者实例
      const sp = ServiceProvider({
        entityID: app.entityID,
        assertionConsumerService: [{
          Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
          Location: app.acsUrl
        }],
        singleLogoutService: [{
          Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
          Location: app.sloUrl || ''
        }],
        signingCert: app.spCert || ''
      });
      
      // 创建身份提供者实例
      const idp = IdentityProvider({
        metadata: `
          <EntityDescriptor entityID="https://${env.AUTH_DOMAIN}/api/auth/saml">
            <IDPSSODescriptor>
              <KeyDescriptor use="signing">
                <KeyInfo>
                  <X509Data>
                    <X509Certificate>${app.signingCert || ''}</X509Certificate>
                  </X509Data>
                </KeyInfo>
              </KeyDescriptor>
              <KeyDescriptor use="encryption">
                <KeyInfo>
                  <X509Data>
                    <X509Certificate>${app.encryptCert || ''}</X509Certificate>
                  </X509Data>
                </KeyInfo>
              </KeyDescriptor>
              <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
              <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
              <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
              <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://${env.AUTH_DOMAIN}/api/auth/saml/login/${appId}"/>
               <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://${env.AUTH_DOMAIN}/api/auth/saml/logout"/>
             </IDPSSODescriptor>
           </EntityDescriptor>
        `
      });
      
      // 解析SAML请求
      const { extract } = await sp.parseLogoutRequest(idp, 'redirect', { query: { SAMLRequest, RelayState } });
      
      // 存储SAML请求信息到会话中，用于后续回调
      const sessionId = crypto.randomUUID();
      await env.SESSIONS.put(`saml:${sessionId}`, JSON.stringify({
        appId,
        request: extract,
        relayState: RelayState,
        createdAt: Date.now()
      }), { expirationTtl: 60 * 60 }) // 1小时过期
      
      // 返回登录会话ID
      return new Response(JSON.stringify({
        success: true,
        sessionId
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('SAML登录请求处理错误:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '处理SAML登录请求时发生错误',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },
  
  // SAML回调处理
  async callback(request: Request): Promise<Response> {
    try {
      const env = (request as any).env;
      
      // 获取请求数据
      const data = await request.json() as any;
      const { samlResponse, sessionId } = data;
      
      // 验证必要参数
      if (!samlResponse || !sessionId) {
        return new Response(JSON.stringify({
          success: false,
          message: 'SAML响应和会话ID不能为空'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 从会话中获取SAML请求信息
      const samlSessionJson = await env.SESSIONS.get(`saml:${sessionId}`);
      
      if (!samlSessionJson) {
        return new Response(JSON.stringify({
          success: false,
          message: 'SAML会话不存在或已过期'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      const samlSession = JSON.parse(samlSessionJson);
      
      // 获取应用信息
      const appJson = await env.APPLICATIONS.get(`app:${samlSession.appId}`);
      
      if (!appJson) {
        return new Response(JSON.stringify({
          success: false,
          message: '应用不存在'
        }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      const app = JSON.parse(appJson);
      
      // 创建服务提供者实例
      const sp = ServiceProvider({
        entityID: app.entityID,
        assertionConsumerService: [{
          Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
          Location: app.acsUrl
        }],
        singleLogoutService: [{
          Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
          Location: app.sloUrl || ''
        }],
        signingCert: app.spCert || ''
      });
      
      // 创建身份提供者实例
      const idp = IdentityProvider({
        metadata: `
          <EntityDescriptor entityID="https://${env.AUTH_DOMAIN}/api/auth/saml">
            <IDPSSODescriptor>
              <KeyDescriptor use="signing">
                <KeyInfo>
                  <X509Data>
                    <X509Certificate>${app.signingCert || ''}</X509Certificate>
                  </X509Data>
                </KeyInfo>
              </KeyDescriptor>
              <KeyDescriptor use="encryption">
                <KeyInfo>
                  <X509Data>
                    <X509Certificate>${app.encryptCert || ''}</X509Certificate>
                  </X509Data>
                </KeyInfo>
              </KeyDescriptor>
              <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
              <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
              <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
              <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://${env.AUTH_DOMAIN}/api/auth/saml/login/${app.id}"/>
              <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://${env.AUTH_DOMAIN}/api/auth/saml/logout"/>
            </IDPSSODescriptor>
          </EntityDescriptor>
        `
      });
      
      // 生成SAML响应
      const { extract } = await idp.parseLogoutResponse(sp, 'post', { body: { SAMLResponse: samlResponse } });
      
      // 构建SAML断言
      const email = extract.nameID;
      
      // 检查用户是否存在
      let userJson = await env.USERS.get(`user:${email}`);
      let user;
      
      if (!userJson) {
        // 如果用户不存在且应用配置允许自动创建用户，则创建新用户
        if (app.autoCreateUsers) {
          // 创建新用户
          const userId = crypto.randomUUID();
          user = {
            id: userId,
            email,
            name: extract.attributes?.name || email.split('@')[0],
            role: 'user',
            createdAt: Date.now(),
            updatedAt: Date.now()
          };
          
          // 存储用户信息
          await env.USERS.put(`user:${email}`, JSON.stringify(user));
          await env.USERS.put(`userId:${userId}`, email);
        } else {
          return new Response(JSON.stringify({
            success: false,
            message: '用户不存在'
          }), {
            status: 404,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      } else {
        user = JSON.parse(userJson);
      }
      
      // 构建并返回SAML响应
      const samlAssertionResponse = idp.createLoginResponse(
        sp,
        samlSession.request,
        'post',
        {
          samlNameID: user.email,
          attributes: {
            email: user.email,
            name: user.name,
            role: user.role
          },
          relayState: samlSession.relayState
        }
      );
      
      // 删除会话
      await env.SESSIONS.delete(`saml:${sessionId}`);
      
      return new Response(JSON.stringify({
        success: true,
        samlResponse: samlAssertionResponse
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('SAML回调处理错误:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '处理SAML回调时发生错误',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },
  
  // SAML登出处理
  async logout(request: Request): Promise<Response> {
    try {
      const env = (request as any).env;
      
      // 获取请求数据
      const data = await request.json() as any;
      const { SAMLRequest, RelayState } = data;
      
      // 验证SAMLRequest存在
      if (!SAMLRequest) {
        return new Response(JSON.stringify({
          success: false,
          message: 'SAML请求不能为空'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // 从SAMLRequest中提取应用ID
      // 注意：这里需要根据实际情况解析SAMLRequest获取应用ID
      // 这个示例中简化处理
      const sessionId = crypto.randomUUID();
      
      // 存储登出请求信息
      await env.SESSIONS.put(`saml-logout:${sessionId}`, JSON.stringify({
        request: SAMLRequest,
        relayState: RelayState,
        createdAt: Date.now()
      }), { expirationTtl: 60 * 60 }) // 1小时过期
      
      return new Response(JSON.stringify({
        success: true,
        message: '登出会话已创建',
        sessionId
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('SAML登出处理错误:', error);
      return new Response(JSON.stringify({
        success: false,
        message: '处理SAML登出请求时发生错误',
        error: error instanceof Error ? error.message : String(error)
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
};
