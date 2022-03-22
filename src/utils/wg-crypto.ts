// License below retained on purpose

/*! SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

import * as crypto from "crypto";

function gf(init?: number[]): Float64Array {
  let r = new Float64Array(16);
  if (init) {
    for (let i = 0; i < init.length; ++i)
      r[i] = init[i];
  }
  return r;
}

function pack(o: Uint8Array, n: Float64Array) {
  let b, m = gf(), t = gf();
  for (let i = 0; i < 16; ++i)
    t[i] = n[i];
  carry(t);
  carry(t);
  carry(t);
  for (let j = 0; j < 2; ++j) {
    m[0] = t[0] - 0xffed;
    for (let i = 1; i < 15; ++i) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    b = (m[15] >> 16) & 1;
    m[14] &= 0xffff;
    cswap(t, m, 1 - b);
  }
  for (let i = 0; i < 16; ++i) {
    o[2 * i] = t[i] & 0xff;
    o[2 * i + 1] = t[i] >> 8;
  }
}

function carry(o: Float64Array) {
  for (let i = 0; i < 16; ++i) {
    o[(i + 1) % 16] += (i < 15 ? 1 : 38) * Math.floor(o[i] / 65536);
    o[i] &= 0xffff;
  }
}

function cswap(p: Float64Array, q: Float64Array, b: number) {
  let t, c = ~(b - 1);
  for (let i = 0; i < 16; ++i) {
    t = c & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

function add(o: Float64Array, a: Float64Array, b: Float64Array) {
  for (let i = 0; i < 16; ++i)
    o[i] = (a[i] + b[i]) | 0;
}

function subtract(o: Float64Array, a: Float64Array, b: Float64Array) {
  for (let i = 0; i < 16; ++i)
    o[i] = (a[i] - b[i]) | 0;
}

function multmod(o: Float64Array, a: Float64Array, b: Float64Array) {
  let t = new Float64Array(31);
  for (let i = 0; i < 16; ++i) {
    for (let j = 0; j < 16; ++j)
      t[i + j] += a[i] * b[j];
  }
  for (let i = 0; i < 15; ++i)
    t[i] += 38 * t[i + 16];
  for (let i = 0; i < 16; ++i)
    o[i] = t[i];
  carry(o);
  carry(o);
}

function invert(o: Float64Array, i: Float64Array) {
  let c = gf();
  for (let a = 0; a < 16; ++a)
    c[a] = i[a];
  for (let a = 253; a >= 0; --a) {
    multmod(c, c, c);
    if (a !== 2 && a !== 4)
      multmod(c, c, i);
  }
  for (let a = 0; a < 16; ++a)
    o[a] = c[a];
}

function clamp(z: Uint8Array) {
  z[31] = (z[31] & 127) | 64;
  z[0] &= 248;
}

export function generatePublicKey(privateKey: Uint8Array): Uint8Array {
  let r, z = new Uint8Array(32);
  let a = gf([1]),
    b = gf([9]),
    c = gf(),
    d = gf([1]),
    e = gf(),
    f = gf(),
    _121665 = gf([0xdb41, 1]),
    _9 = gf([9]);
  for (let i = 0; i < 32; ++i)
    z[i] = privateKey[i];
  clamp(z);
  for (let i = 254; i >= 0; --i) {
    r = (z[i >>> 3] >>> (i & 7)) & 1;
    cswap(a, b, r);
    cswap(c, d, r);
    add(e, a, c);
    subtract(a, a, c);
    add(c, b, d);
    subtract(b, b, d);
    multmod(d, e, e);
    multmod(f, a, a);
    multmod(a, c, a);
    multmod(c, b, e);
    add(e, a, c);
    subtract(a, a, c);
    multmod(b, a, a);
    subtract(c, d, f);
    multmod(a, c, _121665);
    add(a, a, d);
    multmod(c, c, a);
    multmod(a, d, f);
    multmod(d, b, _9);
    multmod(b, e, e);
    cswap(a, b, r);
    cswap(c, d, r);
  }
  invert(c, c);
  multmod(a, a, c);
  pack(z, a);
  return z;
}

export function generatePresharedKey(): Uint8Array {
  const privateKey = new Uint8Array(32)
  crypto.randomFillSync(privateKey)
  return privateKey
}

export function generatePrivateKey(): Uint8Array {
  const privateKey = generatePresharedKey();
  clamp(privateKey);
  return privateKey;
}
