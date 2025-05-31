"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateKeyPair = generateKeyPair;
exports.signData = signData;
exports.verifySignature = verifySignature;
/**
 * 生成RSA密钥对用于OIDC签名和验证
 */
async function generateKeyPair() {
    // 使用Web Crypto API生成RSA密钥对
    const keyPair = await crypto.subtle.generateKey({
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
    }, true, ['sign', 'verify']);
    // 导出公钥为JWK格式
    const publicKey = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    // 导出私钥为JWK格式
    const privateKey = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    return {
        publicKey,
        privateKey
    };
}
/**
 * 使用私钥签名数据
 */
async function signData(privateKey, data) {
    // 导入私钥
    const key = await crypto.subtle.importKey('jwk', privateKey, {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
    }, false, ['sign']);
    // 将数据转换为ArrayBuffer
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    // 签名数据
    const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, dataBuffer);
    // 将签名转换为Base64
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
}
/**
 * 使用公钥验证签名
 */
async function verifySignature(publicKey, data, signature) {
    // 导入公钥
    const key = await crypto.subtle.importKey('jwk', publicKey, {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
    }, false, ['verify']);
    // 将数据转换为ArrayBuffer
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    // 将Base64签名转换为ArrayBuffer
    const signatureArray = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    // 验证签名
    return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signatureArray, dataBuffer);
}
