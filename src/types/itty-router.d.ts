declare module 'itty-router' {
  export interface IRequest extends Request {
    params?: Record<string, string>;
    query?: Record<string, string>;
    env?: any;
  }

  export interface RouterOptions {
    base?: string;
  }

  export type RouteHandler<TRequest = IRequest> = (
    request: TRequest,
    ...args: any[]
  ) => Response | Promise<Response> | void | Promise<void>;

  export interface Router<TRequest = IRequest> {
    handle: (request: Request | TRequest) => Promise<Response>;
    all: (path: string, ...handlers: RouteHandler<TRequest>[]) => Router<TRequest>;
    get: (path: string, ...handlers: RouteHandler<TRequest>[]) => Router<TRequest>;
    post: (path: string, ...handlers: RouteHandler<TRequest>[]) => Router<TRequest>;
    put: (path: string, ...handlers: RouteHandler<TRequest>[]) => Router<TRequest>;
    patch: (path: string, ...handlers: RouteHandler<TRequest>[]) => Router<TRequest>;
    delete: (path: string, ...handlers: RouteHandler<TRequest>[]) => Router<TRequest>;
    head: (path: string, ...handlers: RouteHandler<TRequest>[]) => Router<TRequest>;
    options: (path: string, ...handlers: RouteHandler<TRequest>[]) => Router<TRequest>;
  }

  export function Router<TRequest = IRequest>(options?: RouterOptions): Router<TRequest>;
}