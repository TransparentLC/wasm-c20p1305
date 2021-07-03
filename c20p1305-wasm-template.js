(() => {

/** @type {globalThis} */
const GLOBAL = typeof globalThis !== 'undefined' ? globalThis : (global || self);

const {
    Uint8Array,
    WebAssembly,
} = GLOBAL;

/** @typedef {Number} Pointer */

/** @type {WebAssembly.Module} */
const cachedModule = new WebAssembly.Module(Uint8Array.from(atob('$$WASM_BASE64$$'), e => e.charCodeAt()));
const $memoryTotalLength = 0x10000;
const $memoryStackPointer = 0x00DFF;
const $memoryCryptContext = 0x00E00;
const $memoryFreeArea = 0x01000;

class ChaCha20Poly1305 {
    /**
     * @param {Uint8Array} key 32 bytes
     * @param {Uint8Array} nonce 12 bytes
     * @param {Uint8Array} aad any length
     */
    constructor(key, nonce, aad) {
        const memory = new WebAssembly.Memory({
            'initial': 1,
        });
        const heapU8 = this.heapU8 = new Uint8Array(memory.buffer);
        /** @type {WebAssembly.Exports} */
        /**
         * @type {{
         *  $$WASMEXPORTS_c20p1305_ctx_init$$(ctx: Pointer, key: Pointer, nonce: Pointer, auth: Pointer, authLength: Number) => void,
         *  $$WASMEXPORTS_c20p1305_encrypt$$(ctx: Pointer, data: Pointer, dataLength: Number) => void,
         *  $$WASMEXPORTS_c20p1305_decrypt$$(ctx: Pointer, data: Pointer, dataLength: Number) => void,
         *  $$WASMEXPORTS_c20p1305_finish$$(ctx: Pointer, mac: Pointer) => void,
         * }}
         */
        this.wasmExports = new WebAssembly.Instance(cachedModule, {
            'env': {
                'memory': memory,
                '__memory_base': 0x0000,
                '__stack_pointer': new WebAssembly.Global(
                    {
                        'mutable': true,
                        'value': 'i32',
                    },
                    $memoryStackPointer,
                ),
            },
        }).exports;

        heapU8.set(key, $memoryFreeArea);
        heapU8.set(nonce, $memoryFreeArea + 32);
        heapU8.set(aad, $memoryFreeArea + 32 + 12);
        this.wasmExports['$$WASMEXPORTS_c20p1305_ctx_init$$'](
            $memoryCryptContext,
            $memoryFreeArea,
            $memoryFreeArea + 32,
            $memoryFreeArea + 32 + 12,
            aad.length,
        );
    }

    /**
     * @param {(ctx: Pointer, data: Pointer, dataLength: Number) => void} func
     * @param {Uint8Array} data
     * @returns {Uint8Array}
     */
    crypt(func, data) {
        const dataLength = data.length;
        const result = new Uint8Array(dataLength);
        const heapU8 = this.heapU8;
        let cryptedLength = 0;
        while (cryptedLength < dataLength) {
            const sliceLength = Math.min(dataLength - cryptedLength, $memoryTotalLength - $memoryFreeArea);
            heapU8.set(data.subarray(cryptedLength, cryptedLength + sliceLength), $memoryFreeArea);
            func($memoryCryptContext, $memoryFreeArea, sliceLength);
            result.set(heapU8.subarray($memoryFreeArea, $memoryFreeArea + sliceLength), cryptedLength);
            cryptedLength += sliceLength;
        }
        return result;
    }

    /**
     * @param {Uint8Array} data
     * @returns {Uint8Array}
     */
    'encrypt'(data) {
        return this.crypt(this.wasmExports['$$WASMEXPORTS_c20p1305_encrypt$$'], data);
    }

    /**
     * @param {Uint8Array} data
     * @returns {Uint8Array}
     */
    'decrypt'(data) {
        return this.crypt(this.wasmExports['$$WASMEXPORTS_c20p1305_decrypt$$'], data);
    }

    /**
     * @returns {Uint8Array}
     */
    'mac'() {
        this.wasmExports['$$WASMEXPORTS_c20p1305_finish$$']($memoryCryptContext, $memoryFreeArea);
        return new Uint8Array(this.heapU8.subarray($memoryFreeArea, $memoryFreeArea + 16));
    }

    /**
     * @param {Uint8Array} mac
     * @returns {Boolean}
     */
    'verify'(mac) {
        const m = this['mac']();
        let result = 0;
        let i = 16;
        while (i--) result |= m[i] ^ mac[i];
        return !result;
    }
}

if (typeof module !== 'undefined') {
    module.exports = ChaCha20Poly1305;
} else {
    GLOBAL['ChaCha20Poly1305'] = ChaCha20Poly1305;
}

})()