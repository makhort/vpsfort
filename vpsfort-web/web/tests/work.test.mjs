// The login's proof of work (work.js): its SHA-256 against the standard's vectors, and the
// nonce it finds against the console's own check.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { createHash } from "node:crypto";

const { sha256, leadingZeroBits, findNonce } = createRequire(import.meta.url)("../work.js");

const words = (hex) => [parseInt(hex.slice(0, 8), 16), parseInt(hex.slice(8, 16), 16)];
const hashOf = (text) => { const m = new Uint8Array(64); const b = new TextEncoder().encode(text); m.set(b); return sha256(m, b.length); };

test("SHA-256 as the standard has it", () => {
  assert.deepEqual(hashOf("abc"), words("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  assert.deepEqual(hashOf(""), words("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  const long = "a".repeat(55);
  assert.deepEqual(hashOf(long), words(createHash("sha256").update(long).digest("hex")));
});

test("a nonce found here passes the console's check", () => {
  const salt = "53868df6267bfcf98907ed7dd13a81e4";
  const { nonce, tries } = findNonce(salt, 12);
  assert.ok(tries >= 1);
  const digest = createHash("sha256").update(salt + nonce).digest();
  assert.equal(digest[0], 0, "12 zero bits: the first byte");
  assert.equal(digest[1] >> 4, 0, "and the next four");
  assert.ok(leadingZeroBits(hashOf(salt + nonce), 12));
  assert.ok(!leadingZeroBits([0x0fffffff, 0], 5));
  assert.ok(leadingZeroBits([0, 0x0fffffff], 36));
});

test("a million hashes in well under a few seconds", () => {
  const m = new Uint8Array(64); m.set(new TextEncoder().encode("timing"));
  const start = performance.now();
  for (let i = 0; i < 200000; i++) sha256(m, 6);
  const perSec = 200000 / ((performance.now() - start) / 1000);
  assert.ok(perSec > 300000, `${Math.round(perSec)} hashes/s`);
});
