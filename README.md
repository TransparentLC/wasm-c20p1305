# wasm-c20p1305

[![build](https://github.com/TransparentLC/wasm-c20p1305/actions/workflows/build.yml/badge.svg)](https://github.com/TransparentLC/wasm-c20p1305/actions/workflows/build.yml)

使用 WASM 运行的 ChaCha20Poly1305 算法，预编译版可在 [Actions](https://github.com/TransparentLC/wasm-c20p1305/actions/workflows/build.yml) 或 [Releases](https://github.com/TransparentLC/wasm-c20p1305/releases) 下载。

ChaCha20 的实现来自 [Ginurx/chacha20-c](https://github.com/Ginurx/chacha20-c)，Poly1305 的实现来自 [floodyberry/poly1305-donna](https://github.com/floodyberry/poly1305-donna)。加密和解密结果和 Node.js 自带的 `crypto` 模块相同。

## 使用方式

```js
class ChaCha20Poly1305 {
    /**
     * @param {Uint8Array} key 32字节的密钥
     * @param {Uint8Array} nonce 12字节的不重用随机数
     * @param {Uint8Array} aad 长度不限的认证信息
     */
    constructor(key, nonce, aad) {}

    /**
     * @param {Uint8Array} data 需要加密的数据
     * @returns {Uint8Array} 加密后的数据
     */
    encrypt(data) {}

    /**
     * @param {Uint8Array} data 需要解密的数据
     * @returns {Uint8Array} 解密后的数据
     */
    decrypt(data) {}

    /**
     * @returns {Uint8Array} 16字节的加密后的消息认证码
     */
    mac() {}

    /**
     * @param {Uint8Array} mac 与密文一同收到的消息认证码
     * @returns {Boolean} 解密后的消息是否通过认证
     */
    verify(mac) {}

    /** @type {Promise<void>} 在WASM模块加载完成后fulfill的Promise */
    static ready,
}
```
<details>

<summary>试试看！</summary>

```js
if (typeof btoa === 'undefined') {
    global.btoa = str => Buffer.from(str, 'binary').toString('base64');
}

if (typeof atob === 'undefined') {
    global.atob = b64Encoded => Buffer.from(b64Encoded, 'base64').toString('binary');
}

// 在浏览器中加载时，名称为ChaCha20Poly1305
const ChaCha20Poly1305 = require('./dist/c20p1305-wasm.speed.min.js');

(async () => {

// 等待WASM模块异步加载完成
// 也可以使用ChaCha20Poly1305.ready.then(() => {...})
await ChaCha20Poly1305.ready;

// 以下的测试向量来自 https://datatracker.ietf.org/doc/html/rfc7539#section-2.8.2

// key长度固定为32
const key = new Uint8Array([
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
]);
// nonce长度固定为12
const nonce = new Uint8Array([
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47,
]);
// aad长度不限
const aad = new Uint8Array([
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7,
]);
// 需要加密的明文
const plaintext = new Uint8Array([
    0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
    0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
    0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
    0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
    0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
    0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
    0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
    0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
    0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
    0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
    0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
    0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
    0x74, 0x2e,
]);

// 创建加密对象，在加密后获取消息认证码
const encryptor = new ChaCha20Poly1305(key, nonce, aad);
const encrypted = encryptor.encrypt(plaintext);
const mac = encryptor.mac();
// Uint8Array(114) [211, 26, 141, 52, ...]
console.log(encrypted);
// Uint8Array(16) [26, 225, 11, 89, ...]
console.log(mac);

// 创建解密对象，在解密后检查消息认证码
const decryptor = new ChaCha20Poly1305(key, nonce, aad);
const decrypted = decryptor.decrypt(encrypted);
// true
console.log(decryptor.verify(mac));
// true
console.log(plaintext.every((e, i) => e === decrypted[i]));

})()
```

</details>

注意事项：

* 请不要在同一个对象上**同时进行加密和解密操作**（要么只调用 `encrypt` 和 `mac`，要么只调用 `decrypt` 和 `verify`）。
* 每个对象只能对**一段**数据加密或解密**一遍**，不能再用于加密或解密另一段数据。
* 每个对象调用 `mac` 或 `verify` 后，就不能再调用 `encrypt` 和 `decrypt`。
* 对于同一段数据，可以分成块后依次调用 `encrypt` 或 `decrypt` 进行加密或解密。

## 编译

需要安装 [Emscripten](https://emscripten.org) 和 [Node.js](https://nodejs.org) 环境。

```bash
npm install -g terser
node build.js
```

运行后可以在 `dist` 目录找到以下文件：

* `c20p1305.{mode}.wasm`
* `c20p1305-wasm.{mode}.js`
* `c20p1305-wasm.{mode}.d.ts`
* `c20p1305-wasm.{mode}.min.js`
* `c20p1305-wasm.{mode}.min.d.ts`

`{mode}` 是 size 和 speed 之一，对应文件大小或运行速度的优化（也就是 Emscripten 编译时使用的 `-Oz` 或 `-O3` 参数）。使用时在浏览器 / Node.js 中加载 JS 文件即可，WASM 文件可以不保留。

> 实际上 speed 比 size 大不了多少，但是速度是 size 的 2.5x 以上，所以还是选 speed 吧 (っ'ω')っ

## 测试

以 Node.js 的 `crypto` 模块和基于 [thesimj/js-chacha20](https://github.com/thesimj/js-chacha20) 和 [devi/chacha20poly1305](https://github.com/devi/chacha20poly1305) 修改的[纯 JS 版](https://gist.github.com/TransparentLC/a528c9122f1e356ba202892461cdce90)作为参考，随机生成数据进行加密和解密，检查运行结果是否相同。

运行 `node benchmark.js` 开始测试（对 32 MB 的随机数据进行加密），以下测试结果是在 WSL Ubuntu 20.04 Node.js v14.15.5 下运行的，仅供参考：

| 加密模式 | 运行时间（ms） | 加密速度（Bytes/ms） | 与纯 JS 版比较的速度比例 |
| - | - | - | - |
| vanilla-js | 1271.26 | 26394.71 | 1 |
| wasm-size | 499.58 | 67165.79 | 2.54 |
| wasm-speed | 203.60 | 164805.90 | 6.24 |
| node | 49.85 | 673147.12 | 25.50 |
