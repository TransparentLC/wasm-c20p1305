/** @type {globalThis} */
const GLOBAL = typeof globalThis !== 'undefined' ? globalThis : (global || self);

const {
    Uint8Array,
    WebAssembly,
} = GLOBAL;

const wasmMemory = new WebAssembly.Memory({
    'initial': 1,
});
const wasmHeapU8 = new Uint8Array(wasmMemory.buffer);
const $memoryTotalLength = 0x10000;
const $memoryStackPointer = 0x00E00;
const $memoryCryptContext = 0x00E00;
const $memoryFreeArea = 0x01000;
const $memoryCryptContextLength = 336;

/** @typedef {Number} Pointer */

/** @type {WebAssembly.Exports} */
/**
 * @type {{
 *  __WASMEXPORTS_c20p1305_ctx_init__(ctx: Pointer, key: Pointer, nonce: Pointer, auth: Pointer, authLength: Number) => void,
 *  __WASMEXPORTS_c20p1305_encrypt__(ctx: Pointer, data: Pointer, dataLength: Number) => void,
 *  __WASMEXPORTS_c20p1305_decrypt__(ctx: Pointer, data: Pointer, dataLength: Number) => void,
 *  __WASMEXPORTS_c20p1305_finish__(ctx: Pointer, mac: Pointer) => void,
 * }}
 */
let wasmExports;
/** @type {Promise<void>} */
const wasmReady = new Promise(resolve => WebAssembly
    .instantiate(
        Uint8Array.from(atob(__WASM_BASE64__), e => e.charCodeAt()),
        {
            'env': {
                'memory': wasmMemory,
                '__memory_base': 0x0000,
                '__stack_pointer': new WebAssembly.Global(
                    {
                        'mutable': true,
                        'value': 'i32',
                    },
                    $memoryStackPointer,
                ),
            },
        }
    )
    .then(result => {
        wasmExports = result['instance']['exports'];
        resolve();
    })
);

class ChaCha20Poly1305 {
    /**
     * @param {Uint8Array} key 32 bytes
     * @param {Uint8Array} nonce 12 bytes
     * @param {Uint8Array} aad any length
     */
    constructor(key, nonce, aad) {
        wasmHeapU8.set(key, $memoryFreeArea);
        wasmHeapU8.set(nonce, $memoryFreeArea + 32);
        wasmHeapU8.set(aad, $memoryFreeArea + 32 + 12);
        wasmExports[__WASMEXPORTS_c20p1305_ctx_init__](
            $memoryCryptContext,
            $memoryFreeArea,
            $memoryFreeArea + 32,
            $memoryFreeArea + 32 + 12,
            aad.length,
        );
        this.cryptContext = wasmHeapU8.slice($memoryCryptContext, $memoryCryptContext + $memoryCryptContextLength);
    }

    // saveContext() {
    //     this.cryptContext.set(wasmHeapU8.subarray($memoryCryptContext, $memoryCryptContext + $memoryCryptContextLength));
    // }

    loadContext() {
        wasmHeapU8.set(this.cryptContext, $memoryCryptContext);
    }

    /**
     * @param {(ctx: Pointer, data: Pointer, dataLength: Number) => void} func
     * @param {Uint8Array} data
     * @returns {Uint8Array}
     */
    crypt(func, data) {
        this.loadContext();
        const dataLength = data.length;
        const result = new Uint8Array(dataLength);
        let cryptedLength = 0;
        while (cryptedLength < dataLength) {
            const sliceLength = Math.min(dataLength - cryptedLength, $memoryTotalLength - $memoryFreeArea);
            wasmHeapU8.set(data.subarray(cryptedLength, cryptedLength + sliceLength), $memoryFreeArea);
            func($memoryCryptContext, $memoryFreeArea, sliceLength);
            result.set(wasmHeapU8.subarray($memoryFreeArea, $memoryFreeArea + sliceLength), cryptedLength);
            cryptedLength += sliceLength;
        }
        // this.saveContext();
        this.cryptContext.set(wasmHeapU8.subarray($memoryCryptContext, $memoryCryptContext + $memoryCryptContextLength));
        return result;
    }

    /**
     * @param {Uint8Array} data
     * @returns {Uint8Array}
     */
    'encrypt'(data) {
        return this.crypt(wasmExports[__WASMEXPORTS_c20p1305_encrypt__], data);
    }

    /**
     * @param {Uint8Array} data
     * @returns {Uint8Array}
     */
    'decrypt'(data) {
        return this.crypt(wasmExports[__WASMEXPORTS_c20p1305_decrypt__], data);
    }

    /**
     * @returns {Uint8Array}
     */
    'mac'() {
        this.loadContext();
        wasmExports[__WASMEXPORTS_c20p1305_finish__]($memoryCryptContext, $memoryFreeArea);
        return wasmHeapU8.slice($memoryFreeArea, $memoryFreeArea + 16);
    }

    /**
     * @param {Uint8Array} mac
     * @returns {Boolean}
     */
    'verify'(mac) {
        this.loadContext();
        const m = this['mac']();
        let result = 0;
        let i = 16;
        while (i--) result |= m[i] ^ mac[i];
        return !result;
    }
}

ChaCha20Poly1305['ready'] = wasmReady;
