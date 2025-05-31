"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.corsHeaders = void 0;
// CORS 配置
exports.corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    'Access-Control-Max-Age': '86400',
};
