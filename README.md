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
    static ready
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
* `c20p1305-wasm.{mode}.{moduleFormat}.js`
* `c20p1305-wasm.{mode}.{moduleFormat}.min.js`
* `c20p1305-wasm.{mode}.d.ts`
* `c20p1305-wasm.{mode}.min.d.ts`

`{mode}` 是 size 和 speed 之一，对应文件大小或运行速度的优化（也就是 Emscripten 编译时使用的 `-Oz` 或 `-O3` 参数）。`{moduleFormat}` 是 `cjs` 和 `esm` 之一，分别对应 CommonJS 和 ES Modules 模块。使用时在浏览器 / Node.js 中加载 JS 文件即可，WASM 文件可以不保留。

## 测试

以 Node.js 的 `crypto` 模块和基于 [thesimj/js-chacha20](https://github.com/thesimj/js-chacha20) 和 [devi/chacha20poly1305](https://github.com/devi/chacha20poly1305) 修改的[纯 JS 版](https://gist.github.com/TransparentLC/a528c9122f1e356ba202892461cdce90)作为参考，随机生成数据进行加密和解密，检查运行结果是否相同。

运行 `node benchmark.js` 开始测试。测试内容为对不同长度的随机明文进行加密，并检查密文与 MAC 和 `crypto` 的输出是否相同，以及解密结果和明文是否相同。检查过程不计时。

以下测试结果是在 WSL Ubuntu 20.04 Node.js v14.15.5 下运行的，仅供参考：

<details>

```plaintext
Benchmark for encrypting 16 bytes (Tested 1024 times)
┌─────────┬──────────────┬──────────────────────┬────────────────────┬────────────────────┐
│ (index) │     name     │     averageTime      │       speed        │       ratio        │
├─────────┼──────────────┼──────────────────────┼────────────────────┼────────────────────┤
│    0    │ 'vanilla-js' │ 0.026104687500264845 │ 612.9167414793865  │         1          │
│    1    │ 'wasm-size'  │ 0.008672265641507693 │ 1844.9619351395197 │ 3.010134672918816  │
│    2    │ 'wasm-speed' │ 0.005821191411087057 │ 2748.5782325464093 │ 4.484423489415893  │
│    3    │    'node'    │ 0.013761621090452536 │ 1162.6537233393524 │ 1.8969195074245733 │
└─────────┴──────────────┴──────────────────────┴────────────────────┴────────────────────┘
Benchmark for encrypting 64 bytes (Tested 1024 times)
┌─────────┬──────────────┬──────────────────────┬────────────────────┬───────────────────┐
│ (index) │     name     │     averageTime      │       speed        │       ratio       │
├─────────┼──────────────┼──────────────────────┼────────────────────┼───────────────────┤
│    0    │ 'vanilla-js' │ 0.01733037106168922  │ 3692.938816611917  │         1         │
│    1    │ 'wasm-size'  │ 0.007056933607600513 │ 9069.094816347744  │ 2.455793411889823 │
│    2    │ 'wasm-speed' │ 0.005150781225893297 │ 12425.299618292469 │ 3.364610202151155 │
│    3    │    'node'    │ 0.012354589860478882 │ 5180.2609979575045 │ 1.402747582671876 │
└─────────┴──────────────┴──────────────────────┴────────────────────┴───────────────────┘
Benchmark for encrypting 256 bytes (Tested 1024 times)
┌─────────┬──────────────┬──────────────────────┬────────────────────┬────────────────────┐
│ (index) │     name     │     averageTime      │       speed        │       ratio        │
├─────────┼──────────────┼──────────────────────┼────────────────────┼────────────────────┤
│    0    │ 'vanilla-js' │ 0.023146191397245275 │ 11060.134931333352 │         1          │
│    1    │ 'wasm-size'  │ 0.008616113247626345 │ 29711.77288907217  │ 2.686384304851358  │
│    2    │ 'wasm-speed' │ 0.00503847656364087  │ 50809.00878796804  │ 4.593886883244631  │
│    3    │    'node'    │ 0.009573339882990695 │ 26740.92878023109  │ 2.4177759987786462 │
└─────────┴──────────────┴──────────────────────┴────────────────────┴────────────────────┘
Benchmark for encrypting 1024 bytes (Tested 1024 times)
┌─────────┬──────────────┬──────────────────────┬────────────────────┬────────────────────┐
│ (index) │     name     │     averageTime      │       speed        │       ratio        │
├─────────┼──────────────┼──────────────────────┼────────────────────┼────────────────────┤
│    0    │ 'vanilla-js' │ 0.05213916018146847  │ 19639.748634922482 │         1          │
│    1    │ 'wasm-size'  │ 0.01930302737855527  │ 53048.67365714947  │ 2.7010872004146123 │
│    2    │ 'wasm-speed' │ 0.00923710940151068  │ 110857.19086888051 │ 5.644532062480649  │
│    3    │    'node'    │ 0.010978906244417885 │ 93269.76451052605  │ 4.749030460841953  │
└─────────┴──────────────┴──────────────────────┴────────────────────┴────────────────────┘
Benchmark for encrypting 8192 bytes (Tested 512 times)
┌─────────┬──────────────┬──────────────────────┬────────────────────┬────────────────────┐
│ (index) │     name     │     averageTime      │       speed        │       ratio        │
├─────────┼──────────────┼──────────────────────┼────────────────────┼────────────────────┤
│    0    │ 'vanilla-js' │  0.3212708984283381  │ 25498.73032408283  │         1          │
│    1    │ 'wasm-size'  │ 0.11527968747031991  │ 71061.95531722902  │ 2.786882108012767  │
│    2    │ 'wasm-speed' │ 0.04331660157549777  │ 189119.17606744665 │ 7.416807568996051  │
│    3    │    'node'    │ 0.014593750001949957 │ 561336.1883618274  │ 22.014279975017473 │
└─────────┴──────────────┴──────────────────────┴────────────────────┴────────────────────┘
Benchmark for encrypting 16384 bytes (Tested 256 times)
┌─────────┬──────────────┬──────────────────────┬────────────────────┬────────────────────┐
│ (index) │     name     │     averageTime      │       speed        │       ratio        │
├─────────┼──────────────┼──────────────────────┼────────────────────┼────────────────────┤
│    0    │ 'vanilla-js' │  0.6306421874542139  │ 25979.866754774503 │         1          │
│    1    │ 'wasm-size'  │  0.224820703122532   │ 72875.85072212134  │ 2.8050894721670745 │
│    2    │ 'wasm-speed' │  0.0829070312611293  │ 197618.9443859822  │ 7.606618858030301  │
│    3    │    'node'    │ 0.020592187502188608 │ 795641.5508677091  │ 30.62531299247285  │
└─────────┴──────────────┴──────────────────────┴────────────────────┴────────────────────┘
Benchmark for encrypting 65536 bytes (Tested 64 times)
┌─────────┬──────────────┬──────────────────────┬────────────────────┬────────────────────┐
│ (index) │     name     │     averageTime      │       speed        │       ratio        │
├─────────┼──────────────┼──────────────────────┼────────────────────┼────────────────────┤
│    0    │ 'vanilla-js' │  2.519428125000559   │ 26012.252284428818 │         1          │
│    1    │ 'wasm-size'  │  0.8772453124984168  │ 74706.58328552572  │ 2.8719767311439535 │
│    2    │ 'wasm-speed' │  0.3227796874125488  │ 203036.32030053245 │  7.80541100710729  │
│    3    │    'node'    │ 0.058490625146077946 │ 1120453.0612611256 │ 43.07405022101217  │
└─────────┴──────────────┴──────────────────────┴────────────────────┴────────────────────┘
```

</details>

太长不看版：

* size 版的速度是纯 JS 版的 2.5-3x，speed 版的速度是纯 JS 版的 3-8x。
* speed 版的速度任何时候都大于 size 版。
* 出乎意料的是，对于小于 1 KB 的较短的数据，使用 WASM 实现的 speed 版的速度甚至超过了 Node.js 自带的 crypto。