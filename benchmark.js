if (typeof btoa === 'undefined') {
    global.btoa = str => Buffer.from(str, 'binary').toString('base64');
}

if (typeof atob === 'undefined') {
    global.atob = b64Encoded => Buffer.from(b64Encoded, 'base64').toString('binary');
}

const { performance } = require('perf_hooks');

const crypto = require('crypto');
const c20p1305WasmSize = require('./dist/c20p1305-wasm.size.cjs.min.js');
const c20p1305WasmSpeed = require('./dist/c20p1305-wasm.speed.cjs.min.js');
// const c20p1305WasmSimd = require('./dist/c20p1305-wasm.simd.cjs.min.js');
const { ChaCha20Poly1305: c20p1305VanillaJS } = require('./vanilla/chacha20poly1305.min.js');

(async () => {

await Promise.all([
    c20p1305WasmSize.ready,
    c20p1305WasmSpeed.ready,
    // c20p1305WasmSimd.ready,
]);

for (const [bufferLength, testCount] of [
    [16, 1024],
    [64, 1024],
    [256, 1024],
    [1024, 1024],
    [8192, 512],
    [16384, 256],
    [65536, 64],
]) {
    const result = {
        'vanilla-js': 0,
        'wasm-size': 0,
        'wasm-speed': 0,
        node: 0,
    };

    for (let i = 0; i < testCount; i++) {
        const key = crypto.randomBytes(32);
        const nonce = crypto.randomBytes(12);
        const aad = crypto.randomBytes(256);
        const plain = crypto.randomBytes(bufferLength);
        let start;
        let end;

        start = performance.now();
        const nodeCipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, {authTagLength: 16});
        nodeCipher.setAAD(aad);
        const nodeEncrypted = nodeCipher.update(plain);
        nodeCipher.final();
        const nodeMac = nodeCipher.getAuthTag();
        end = performance.now();
        result['node'] += end - start;

        for (const [name, c20p1305] of [
            ['vanilla-js', c20p1305VanillaJS],
            ['wasm-size', c20p1305WasmSize],
            ['wasm-speed', c20p1305WasmSpeed],
            // ['wasm-simd', c20p1305WasmSimd],
        ]) {
            start = performance.now();
            const cipher = new c20p1305(key, nonce, aad);
            const encrypted = cipher.encrypt(plain);
            const mac = cipher.mac();
            end = performance.now();
            result[name] += end - start;

            if (!nodeEncrypted.equals(Buffer.from(encrypted))) {
                throw new Error('Encrypted not equal');
            }
            if (!nodeMac.equals(Buffer.from(mac))) {
                throw new Error('MAC not equal');
            }

            const cipher2 = new c20p1305(key, nonce, aad);
            const decrypted = cipher2.decrypt(encrypted);
            if (!cipher2.verify(mac)) {
                throw new Error('MAC verify failed');
            }
            if (!plain.equals(Buffer.from(decrypted))) {
                throw new Error('Decrypted not equal');
            }
        }
    }

    const vanillaTime = result['vanilla-js'];
    console.log(`Benchmark for encrypting ${bufferLength} bytes (Tested ${testCount} times)`);
    console.table(Object.entries(result).map(([name, time]) => ({
        name,
        averageTime: time / testCount,
        speed: bufferLength / (time / testCount),
        ratio: vanillaTime / time,
    })));
}

})();