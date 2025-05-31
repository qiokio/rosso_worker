import { IRequest } from 'itty-router';

// 扩展Request类型，添加env属性
export interface ExtendedRequest extends IRequest {
  env: Env;
}

// 环境变量接口定义
export interface Env {
  JWT_SECRET: string;
  COOKIE_SECRET: string;
  SSO_DOMAIN: string;
  SSO_STORE: KVNamespace;
  DB: D1Database;
  APPLICATIONS: KVNamespace;
  SESSIONS: KVNamespace;
  USERS: KVNamespace;
}

// 用户接口定义
export interface User {
  id: string;
  email: string;
  name: string;
  password: string;
  role: 'admin' | 'user';
  createdAt: string;
  updatedAt: string;
}

// 应用接口定义
export interface Application {
  id: string;
  name: string;
  description: string;
  type: 'saml' | 'oidc';
  clientId?: string;
  clientSecret?: string;
  redirectUris?: string[];
  signingCert?: string;
  encryptCert?: string;
  authorizedUsers?: string[];
  createdAt: string;
  updatedAt: string;
}

// 会话接口定义
export interface Session {
  id: string;
  userId: string;
  expires: number;
  createdAt: string;
}

// JWT令牌载荷接口定义
export interface JwtPayload {
  sub: string;
  email: string;
  name: string;
  role: string;
  iat?: number;
  exp?: number;
}

// 认证结果接口定义
export interface AuthResult {
  success: boolean;
  message?: string;
  user?: JwtPayload;
  status: number;
}

// SAML请求接口定义
export interface SamlRequest {
  id: string;
  appId: string;
  relayState?: string;
  createdAt: string;
}

// OIDC授权码接口定义
export interface OidcAuthCode {
  code: string;
  clientId: string;
  redirectUri: string;
  userId: string;
  scope: string;
  nonce?: string;
  createdAt: string;
  expiresAt: string;
}

// OIDC令牌接口定义
export interface OidcToken {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  tokenType: string;
  expiresIn: number;
}