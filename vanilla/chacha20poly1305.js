/*
 * Copyright (c) 2017, Bubelich Mykola
 * https://www.bubelich.com
 *
 * (｡◕‿‿◕｡)
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met, 0x
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * ChaCha20 is a stream cipher designed by D. J. Bernstein.
 * It is a refinement of the Salsa20 algorithm, and it uses a 256-bit key.
 *
 * ChaCha20 successively calls the ChaCha20 block function, with the same key and nonce, and with successively increasing block counter parameters.
 * ChaCha20 then serializes the resulting state by writing the numbers in little-endian order, creating a keystream block.
 *
 * Concatenating the keystream blocks from the successive blocks forms a keystream.
 * The ChaCha20 function then performs an XOR of this keystream with the plaintext.
 * Alternatively, each keystream block can be XORed with a plaintext block before proceeding to create the next block, saving some memory.
 * There is no requirement for the plaintext to be an integral multiple of 512 bits.  If there is extra keystream from the last block, it is discarded.
 *
 * The inputs to ChaCha20 are
 * - 256-bit key
 * - 32-bit initial counter
 * - 96-bit nonce.  In some protocols, this is known as the Initialization Vector
 * - Arbitrary-length plaintext
 *
 * Implementation derived from chacha-ref.c version 20080118
 * See for details, 0x http, 0x//cr.yp.to/chacha/chacha-20080128.pdf
 */

/* poly1305
*
 * Written in 2014 by Devi Mandiri. Public domain.
 * Implementation derived from poly1305-donna-16.h
 * See for details: https://github.com/floodyberry/poly1305-donna
 */

/*
Terser option:
{
  module: true,
  compress: {
    passes: 2,
  },
  mangle: {
    properties: {
      keep_quoted: 'strict',
    },
  },
  output: {},
  parse: {},
  rename: {},
}
*/

(() => {

/** @type {globalThis} */
const GLOBAL = typeof globalThis !== 'undefined' ? globalThis : (global || self);

const {
  Error,
  Uint8Array,
  Uint16Array,
  Uint32Array,
} = GLOBAL;

/**
 * The basic operation of the ChaCha algorithm is the quarter round.
 * It operates on four 32-bit unsigned integers, denoted a, b, c, and d.
 *
 * @param {Uint32Array} output
 * @param {Number} a
 * @param {Number} b
 * @param {Number} c
 * @param {Number} d
 */
const _quarterround = (output, a, b, c, d) => {
  output[d] = _rotl(output[d] ^ (output[a] += output[b]), 16)
  output[b] = _rotl(output[b] ^ (output[c] += output[d]), 12)
  output[d] = _rotl(output[d] ^ (output[a] += output[b]), 8)
  output[b] = _rotl(output[b] ^ (output[c] += output[d]), 7)

  // JavaScript hack to make UINT32 :) //
  // output[a] >>>= 0
  // output[b] >>>= 0
  // output[c] >>>= 0
  // output[d] >>>= 0
}

/**
 * Little-endian to uint 32 bytes
 *
 * @param {Uint8Array} data
 * @param {Number} index
 * @return {Number}
 */
const _get32 = (data, index) => data[index++] | (data[index++] << 8) | (data[index++] << 16) | (data[index] << 24);

/**
 * Little-endian to uint 16 bytes
 *
 * @param {Uint8Array} data
 * @param {Number} index
 * @return {Number}
 */
const _get16 = (data, index) => data[index++] | (data[index] << 8);

/**
 * Cyclic left rotation
 *
 * @param {Number} data
 * @param {Number} shift
 * @return {Number}
 */
const _rotl = (data, shift) => ((data << shift) | (data >>> (32 - shift)));

class ChaCha20 {
  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} nonce
   * @param {Number} [counter]
   */
  constructor(key, nonce, counter = 0) {
    if (!(key instanceof Uint8Array) || key.length !== 32) {
      throw new Error('Key should be 32 byte array!')
    }

    if (!(nonce instanceof Uint8Array) || nonce.length !== 12) {
      throw new Error('Nonce should be 12 byte array!')
    }

    this._rounds = 20

    // param construction
    const _param = new Uint32Array(16);
    _param.set(new Uint32Array([0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]));
    _param[12] = counter;
    let i = 8;
    while (i--) {
      _param[i + 4] = _get32(key, i << 2);
    }
    i = 3;
    while (i--) {
      _param[i + 13] = _get32(nonce, i << 2);
    }
    this._param = _param;

    // init 64 byte keystream block //
    this._keystream = new Uint8Array(64)

    // internal byte counter //
    this._byteCounter = 0
  }

  _chacha() {
    // copy param array to mix //
    const mix = new Uint32Array(this._param)
    let i = 0
    let j = 0

    // mix rounds //
    for (i = 0; i < this._rounds; i += 2) {
      for (j = 0; j < 4; j++) {
        _quarterround(mix, j, j | 0x4, j | 0x8, j | 0xC);
        // _quarterround(mix, j, j + 4, j + 8, j + 12);
      }
      // this._quarterround(mix, 0, 4, 8, 12)
      // this._quarterround(mix, 1, 5, 9, 13)
      // this._quarterround(mix, 2, 6, 10, 14)
      // this._quarterround(mix, 3, 7, 11, 15)

      for (j = 0; j < 4; j++) {
        _quarterround(mix, j, ((j + 1) & 3) | 0x4, ((j + 2) & 3) | 0x8, ((j + 3) & 3) | 0xC)
        // _quarterround(mix, j, ((j + 1) & 3) + 4, ((j + 2) & 3) + 8, ((j + 3) & 3) + 12)
      }
      // _quarterround(mix, 0, 5, 10, 15)
      // _quarterround(mix, 1, 6, 11, 12)
      // _quarterround(mix, 2, 7, 8, 13)
      // _quarterround(mix, 3, 4, 9, 14)
    }

    let b = 0
    for (i = 0; i < 16; i++) {
      // add
      mix[i] += this._param[i]

      // store keystream
      for (j = 0; j < 4; j++) {
        this._keystream[b++] = (mix[i] >>> (j << 3)) // & 0xFF
      }
      // this._keystream[b++] = mix[i] & 0xFF
      // this._keystream[b++] = (mix[i] >>> 8) & 0xFF
      // this._keystream[b++] = (mix[i] >>> 16) & 0xFF
      // this._keystream[b++] = (mix[i] >>> 24) & 0xFF
    }
  }

  /**
   * Encrypt or Decrypt data with key and nonce
   *
   * @param {Uint8Array} data
   * @return {Uint8Array}
   */
  _update(data) {
    if (!(data instanceof Uint8Array) || data.length === 0) {
      throw new Error('Data should be Uint8Array and not empty!')
    }

    const output = new Uint8Array(data.length)

    // core function, build block and xor with input data //
    for (let i = 0; i < data.length; i++) {
      if (this._byteCounter === 0 || this._byteCounter === 64) {
        // generate new block //

        this._chacha()
        // counter increment //
        this._param[12]++

        // reset internal counter //
        this._byteCounter = 0
      }

      output[i] = data[i] ^ this._keystream[this._byteCounter++]
    }

    return output
  }

  /**
   * Encrypt data with key and nonce
   *
   * @param {Uint8Array} data
   * @return {Uint8Array}
   */
  'encrypt'(data) {
    return this._update(data);
  }

  /**
   * Decrypt data with key and nonce
   *
   * @param {Uint8Array} data
   * @return {Uint8Array}
   */
  'decrypt'(data) {
    return this._update(data);
  }
}

class Poly1305 {
  /**
   * @param {Uint8Array} key
   */
  constructor(key) {
    this.b = new Uint8Array(16);
    this.l = 0;
    this.h = new Uint16Array(10);
    this.p = new Uint16Array(8);
    this.f = false;

    const t = new Uint16Array(8);

    let i;
    for (i = 8; i--;) t[i] = _get16(key, i << 1);

    this.r = new Uint16Array([
        t[0]                         & 0x1fff,
      ((t[0] >>> 13) | (t[1] <<  3)) & 0x1fff,
      ((t[1] >>> 10) | (t[2] <<  6)) & 0x1f03,
      ((t[2] >>>  7) | (t[3] <<  9)) & 0x1fff,
      ((t[3] >>>  4) | (t[4] << 12)) & 0x00ff,
       (t[4] >>>  1)                 & 0x1ffe,
      ((t[4] >>> 14) | (t[5] <<  2)) & 0x1fff,
      ((t[5] >>> 11) | (t[6] <<  5)) & 0x1f81,
      ((t[6] >>>  8) | (t[7] <<  8)) & 0x1fff,
       (t[7] >>>  5)                 & 0x007f,
    ]);

    for (i = 8; i--;) {
      // this.p[i] = _get16(key, 16 + (i << 1));
      this.p[i] = _get16(key, (i << 1) | 16);
    }
    this.l = 0;
  }

  /**
   * @param {Uint8Array} m
   * @param {Number} mpos
   * @param {Number} bytes
   */
  blocks(m, mpos, bytes) {
    let hibit = this.f ? 0 : (1 << 11);
    const t = new Uint16Array(8);
    const d = new Uint32Array(10);
    const {h, r} = this;
    let c = 0, i = 0, j = 0;

    while (bytes >= 16) {
      for (i = 8; i--;) t[i] = _get16(m, (i << 1) + mpos);

      h[0] +=   t[0]                         & 0x1FFF;
      h[1] += ((t[0] >>> 13) | (t[1] <<  3)) & 0x1FFF;
      h[2] += ((t[1] >>> 10) | (t[2] <<  6)) & 0x1FFF;
      h[3] += ((t[2] >>>  7) | (t[3] <<  9)) & 0x1FFF;
      h[4] += ((t[3] >>>  4) | (t[4] << 12)) & 0x1FFF;
      h[5] +=  (t[4] >>>  1)                 & 0x1FFF;
      h[6] += ((t[4] >>> 14) | (t[5] <<  2)) & 0x1FFF;
      h[7] += ((t[5] >>> 11) | (t[6] <<  5)) & 0x1FFF;
      h[8] += ((t[6] >>>  8) | (t[7] <<  8)) & 0x1FFF;
      h[9] +=  (t[7] >>>  5)                 | hibit;

      for (i = 0, c = 0; i < 10; i++) {
        d[i] = c;
        for (j = 0; j < 10; j++) {
          d[i] += (h[j] & 0xFFFFFFFF) * ((j <= i) ? r[i - j] : (5 * r[i + 10 - j]));
          if (j === 4) {
            c = d[i] >>> 13;
            d[i] &= 0x1FFF;
          }
        }
        c += d[i] >>> 13;
        d[i] &= 0x1FFF;
      }
      c = (c << 2) + c;
      c += d[0];
      d[0] = c & 0x1FFF;
      c >>>= 13;
      d[1] += c;

      h.set(d);
      // for (i = 10; i--;) h[i] = d[i];

      mpos += 16;
      bytes -= 16;
    }
  }

  /**
   * @param {Uint8Array} m
   */
  'update'(m) {
    let want = 0, i = 0, mpos = 0, bytes = m.length;
    const {b} = this;

    if (this.l) {
      want = 16 - this.l;
      if (want > bytes)
        want = bytes;
      for (i = want; i--;) {
        b[this.l+i] = m[i+mpos];
      }
      bytes -= want;
      mpos += want;
      this.l += want;
      if (this.l < 16)
        return;
      this.blocks(b, 0, 16);
      this.l = 0;
    }

    if (bytes >= 16) {
      want = (bytes & -16);
      this.blocks(m, mpos, want);
      mpos += want;
      bytes -= want;
    }

    if (bytes) {
      b.set(m.subarray(mpos, mpos + bytes), this.l);
      // for (i = bytes; i--;) {
      //   b[this.l+i] = m[i+mpos];
      // }
      this.l += bytes;
    }
  }

  /**
   * @returns {Uint8Array}
   */
  'finish'() {
    const mac = new Uint8Array(16);
    const g = new Uint16Array(10);
    const {b, h} = this;
    let c = 0, mask = 0, f = 0, i = 0;

    if (this.l) {
      i = this.l;
      b[i++] = 1;
      for (; i < 16; i++) {
        b[i] = 0;
      }
      this.f = true;
      this.blocks(b, 0, 16);
    }

    c = h[1] >>> 13;
    h[1] &= 0x1FFF;
    for (i = 2; i < 10; i++) {
      h[i] += c;
      c = h[i] >>> 13;
      h[i] &= 0x1FFF;
    }
    h[0] += c * 5;
    c = h[0] >>> 13;
    h[0] &= 0x1FFF;
    h[1] += c;
    c = h[1] >>> 13;
    h[1] &= 0x1FFF;
    h[2] += c;

    g[0] = h[0] + 5;
    c = g[0] >>> 13;
    g[0] &= 0x1FFF;
    for (i = 1; i < 10; i++) {
      g[i] = h[i] + c;
      c = g[i] >>> 13;
      g[i] &= 0x1FFF;
    }
    g[9] -= 1 << 13;

    mask = (g[9] >>> 15) - 1;
    for (i = 10; i--;) g[i] &= mask;
    mask = ~mask;
    for (i = 10; i--;) {
      h[i] = (h[i] & mask) | g[i];
    }

    h[0] = (h[0]      ) | (h[1] << 13);
    h[1] = (h[1] >>  3) | (h[2] << 10);
    h[2] = (h[2] >>  6) | (h[3] <<  7);
    h[3] = (h[3] >>  9) | (h[4] <<  4);
    h[4] = (h[4] >> 12) | (h[5] <<  1) | (h[6] << 14);
    h[5] = (h[6] >>  2) | (h[7] << 11);
    h[6] = (h[7] >>  5) | (h[8] <<  8);
    h[7] = (h[8] >>  8) | (h[9] <<  5);

    f = (h[0] & 0xFFFFFFFF) + this.p[0];
    h[0] = f;
    for (i = 1; i < 8; i++) {
      f = (h[i] & 0xFFFFFFFF) + this.p[i] + (f >>> 16);
      h[i] = f;
    }

    for (i = 8; i--;) {
      mac[i << 1] = h[i];
      mac[(i << 1) + 1] = h[i] >>> 8;
    }

    return mac;
  }
}

class ChaCha20Poly1305 {
  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} nonce
   * @param {Uint8Array} auth
   */
  constructor(key, nonce, auth) {
    if (!(auth instanceof Uint8Array) || auth.length === 0) {
      throw new Error('Auth should be Uint8Array and not empty!');
    }

    this.chacha20 = new ChaCha20(key, nonce);
    this.poly1305 = new Poly1305(this.chacha20['encrypt'](new Uint8Array(64)));
    this.authLength = auth.length;
    this.dataLength = 0;
    this.poly1305['update'](auth);
    if (16 - auth.length & 15) {
      this.poly1305['update'](new Uint8Array(16 - auth.length & 15));
    }
  }

  /**
   * @param {Uint8Array} data
   * @returns {Uint8Array}
   */
  'encrypt'(data) {
    const cipher = this.chacha20['encrypt'](data);
    this.dataLength += cipher.length;
    this.poly1305['update'](cipher);
    return cipher;
  }

  /**
   * @param {Uint8Array} data
   * @returns {Uint8Array}
   */
  'decrypt'(data) {
    this.poly1305['update'](data);
    const plain = this.chacha20['decrypt'](data);
    this.dataLength += plain.length;
    return plain;
  }

  /**
   * @returns {Uint8Array}
   */
  'mac'() {
    if (16 - this.dataLength & 15) {
      this.poly1305['update'](new Uint8Array(16 - this.dataLength & 15));
    }
    // Uint32 only. Javascript cannot handle Uint64.
    this.poly1305['update'](new Uint8Array(new Uint32Array([this.authLength, 0, this.dataLength, 0]).buffer));
    return this.poly1305['finish']();
  }

  /**
   * @param {Uint8Array} mac
   * @returns {Boolean}
   */
  'verify'(mac) {
    const m = this['mac']();
    let i = 16;
    let result = 0;
    while (i--) result |= m[i] ^ mac[i];
    return !result;
  }
}

// EXPORT //
if (typeof module !== 'undefined') {
  module.exports = {
    'ChaCha20': ChaCha20,
    'ChaCha20Poly1305': ChaCha20Poly1305,
  };
} else {
  GLOBAL['ChaCha20'] = ChaCha20;
  GLOBAL['ChaCha20Poly1305'] = ChaCha20Poly1305;
}

})();
