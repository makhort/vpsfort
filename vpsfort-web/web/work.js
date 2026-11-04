// The login's proof of work, in a worker so the page stays responsive: finds a nonce such that
// SHA-256(salt + nonce) starts with `difficulty` zero bits (the console checks the same, in
// src/work.rs). Message in: {salt, difficulty}; out: {nonce, tries} or {progress: tries}.
//
// SHA-256 is done here in plain JavaScript (FIPS 180-4): WebCrypto's digest is asynchronous,
// and a million awaited round trips take seconds more than a million calls.
"use strict";

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const W = new Uint32Array(64);

// SHA-256 of a message of at most 55 bytes (one block): the salt is 32 and a nonce under 20.
function sha256(msg, len) {
  // msg: a Uint8Array of 64 bytes, the message in its first `len`, padded here
  msg.fill(0, len);
  msg[len] = 0x80;
  const bits = len * 8;
  msg[62] = bits >>> 8;
  msg[63] = bits & 0xff;
  for (let i = 0; i < 16; i++) W[i] = (msg[i * 4] << 24) | (msg[i * 4 + 1] << 16) | (msg[i * 4 + 2] << 8) | msg[i * 4 + 3];
  for (let i = 16; i < 64; i++) {
    const w15 = W[i - 15], w2 = W[i - 2];
    const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
    const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
  }
  let a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a, e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;
  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const ch = (e & f) ^ (~e & g);
    const t1 = (h + S1 + ch + K[i] + W[i]) | 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (S0 + maj) | 0;
    h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  // only the first two words matter: the difficulty is at most 28 bits
  return [(a + 0x6a09e667) >>> 0, (b + 0xbb67ae85) >>> 0];
}

function leadingZeroBits([w0, w1], bits) {
  if (bits <= 32) return bits === 0 || w0 >>> (32 - bits) === 0;
  return w0 === 0 && w1 >>> (64 - bits) === 0;
}

// Finds the nonce for `salt` at `difficulty`; `tick(tries)` every 100000 tries.
function findNonce(salt, difficulty, tick) {
  const saltBytes = new TextEncoder().encode(salt);
  const msg = new Uint8Array(64);
  msg.set(saltBytes);
  // start from a random point: two tabs don't do the same work
  let n = Math.floor(Math.random() * 2 ** 40);
  const start = n;
  for (;;) {
    const nonce = String(n);
    for (let i = 0; i < nonce.length; i++) msg[saltBytes.length + i] = nonce.charCodeAt(i);
    if (leadingZeroBits(sha256(msg, saltBytes.length + nonce.length), difficulty)) return { nonce, tries: n - start + 1 };
    n++;
    if (tick && (n - start) % 100000 === 0) tick(n - start);
  }
}

// under Node (the tests) there is no worker to listen on
if (typeof self !== "undefined" && typeof self.postMessage === "function") {
  self.onmessage = (e) => self.postMessage(findNonce(e.data.salt, e.data.difficulty, (tries) => self.postMessage({ progress: tries })));
}
if (typeof module !== "undefined") module.exports = { sha256, leadingZeroBits, findNonce };
