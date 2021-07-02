const childProcess = require('child_process');
const fs = require('fs');
const ReplacementCollector = require('./replacement-collector.js');

fs.rmdirSync('dist', { recursive: true });
fs.mkdirSync('dist');

for (const [optimizeMode, optimizeParam] of [
    ['speed', '-O3'],
    ['size', '-Oz'],
]) {
    const uniqueId = Math.random().toString(36).slice(2, 10);
    const rc = new ReplacementCollector(/\$\$.+?\$\$/g, {
        $$UNIQUE_ID$$: uniqueId,
        $$WASM_BASE64$$: null,
    });
    for (const f of [
        'c20p1305.c',
        'c20p1305-wasm-template.js',
    ]) {
        rc.collect(fs.readFileSync(f, { encoding: 'utf-8' }));
    }

    fs.writeFileSync(
        `c20p1305-${uniqueId}.c`,
        rc.applyReplace(fs.readFileSync('c20p1305.c', { encoding: 'utf-8' }))
    );
    fs.writeFileSync(
        `c20p1305-wasm-template-${uniqueId}.js`,
        rc.applyReplace(fs.readFileSync('c20p1305-wasm-template.js', { encoding: 'utf-8' }))
    );
    const emscriptenProcess = childProcess.spawnSync(
        'emcc',
        [
            `c20p1305-${uniqueId}.c`,
            'chacha20.c',
            'memset.c',
            'poly1305-donna.c',
            optimizeParam,
            '-v',
            '-s', 'SIDE_MODULE=2',
            '-o', `dist/c20p1305.${optimizeMode}.wasm`,
        ],
    );
    console.log(emscriptenProcess.output.toString());
    fs.unlinkSync(`c20p1305-${uniqueId}.c`);
    fs.unlinkSync(`c20p1305-wasm-template-${uniqueId}.js`);
    rc.mapping.set('$$WASM_BASE64$$', fs.readFileSync(`dist/c20p1305.${optimizeMode}.wasm`, { encoding: 'base64' }));

    fs.writeFileSync(
        `dist/c20p1305-wasm.${optimizeMode}.js`,
        rc.applyReplace(fs.readFileSync('c20p1305-wasm-template.js', { encoding: 'utf-8' }))
    );
    const terserProcess = childProcess.spawnSync(
        'terser',
        [
            '--ecma', '2020',
            '--compress', 'unsafe_math,unsafe_methods,unsafe_proto,unsafe_regexp,unsafe_undefined,passes=2',
            '--mangle',
            '--mangle-props', 'keep_quoted=strict',
            '--comments', 'false',
            '--source-map', `url="c20p1305-wasm.${optimizeMode}.min.js.map"`,
            '--output', `dist/c20p1305-wasm.${optimizeMode}.min.js`,
            `dist/c20p1305-wasm.${optimizeMode}.js`,
        ],
    );
    console.log(terserProcess.output.toString());
}