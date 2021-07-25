const childProcess = require('child_process');
const fs = require('fs');
const ReplacementCollector = require('./replacement-collector.js');

(async () => {

await fs.promises.rmdir('dist', { recursive: true });
await fs.promises.mkdir('dist');

await Promise.all([
    // ['simd', '-O3', '-msimd128'],
    ['speed', '-O3'],
    ['size', '-Oz'],
].map(async e => {
    const [optimizeMode, optimizeParam, ...otherParam] = e;

    const uniqueId = Math.random().toString(36).slice(2, 10);
    const rc = new ReplacementCollector(/\$\$.+?\$\$/g, {
        $$UNIQUE_ID$$: uniqueId,
        $$WASM_BASE64$$: null,
    });
    await Promise.all([
        'src/c20p1305.c',
        'c20p1305-wasm-template.js',
    ].map(async f => rc.collect(await fs.promises.readFile(f, { encoding: 'utf-8' }))));

    await fs.promises.writeFile(
        `src/c20p1305-${uniqueId}.c`,
        rc.applyReplace(await fs.promises.readFile('src/c20p1305.c', { encoding: 'utf-8' }))
    );
    await fs.promises.writeFile(
        `c20p1305-wasm-template-${uniqueId}.js`,
        rc.applyReplace(await fs.promises.readFile('c20p1305-wasm-template.js', { encoding: 'utf-8' }))
    );
    console.log(`${optimizeMode} emcc output:\n`, await new Promise((resolve, reject) => childProcess.execFile(
        'emcc',
        [
            `src/c20p1305-${uniqueId}.c`,
            'src/chacha20.c',
            'src/memset.c',
            'src/poly1305-donna.c',
            optimizeParam,
            ...otherParam,
            '-v',
            '-s', 'SIDE_MODULE=2',
            '-o', `dist/c20p1305.${optimizeMode}.wasm`,
        ],
        (error, stdout, stderr) => error ? reject(error) : resolve(stderr)
    )));
    await fs.promises.unlink(`src/c20p1305-${uniqueId}.c`);
    await fs.promises.unlink(`c20p1305-wasm-template-${uniqueId}.js`);
    rc.mapping.set('$$WASM_BASE64$$', (await fs.promises.readFile(`dist/c20p1305.${optimizeMode}.wasm`, { encoding: 'base64' })).replace(/=+$/g, ''));

    await fs.promises.writeFile(
        `dist/c20p1305-wasm.${optimizeMode}.js`,
        rc.applyReplace(await fs.promises.readFile('c20p1305-wasm-template.js', { encoding: 'utf-8' }))
    );
    await fs.promises.copyFile('c20p1305-wasm-template.d.ts', `dist/c20p1305-wasm.${optimizeMode}.d.ts`);
    console.log(`${optimizeMode} terser output:\n`, await new Promise((resolve, reject) => childProcess.execFile(
        'terser',
        [
            '--ecma', '2020',
            '--compress', 'unsafe_math,unsafe_methods,unsafe_proto,unsafe_regexp,unsafe_undefined,passes=2',
            '--mangle',
            '--mangle-props', 'keep_quoted=strict',
            '--comments', 'false',
            '--output', `dist/c20p1305-wasm.${optimizeMode}.min.js`,
            `dist/c20p1305-wasm.${optimizeMode}.js`,
        ],
        (error, stdout, stderr) => error ? reject(error) : resolve(stderr)
    )));
    await fs.promises.copyFile('c20p1305-wasm-template.d.ts', `dist/c20p1305-wasm.${optimizeMode}.min.d.ts`);
}));

})();