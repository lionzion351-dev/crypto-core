// Shamir's Secret Sharing over GF(256).
//
// Splits a secret into N shares such that any THRESHOLD of them reconstruct it,
// and any fewer reveal zero information (information-theoretic secrecy).
// Field: GF(2^8) with reduction polynomial 0x11d. Coefficients are drawn from
// the platform CSPRNG (`crypto.getRandomValues`).

import { bytesToBase64, base64ToBytes } from "./base64.ts";

function gfMul(a: number, b: number): number {
  let r = 0,
    aa = a,
    bb = b;
  for (let i = 0; i < 8; i++) {
    if (bb & 1) r ^= aa;
    bb >>= 1;
    aa <<= 1;
    if (aa & 0x100) aa ^= 0x11d;
  }
  return r & 0xff;
}

/** Exponentiation in GF(256). gfPow(x, 254) yields the multiplicative inverse of x. */
function gfPow(base: number, exp: number): number {
  let r = 1,
    b = base,
    e = exp;
  while (e > 0) {
    if (e & 1) r = gfMul(r, b);
    b = gfMul(b, b);
    e >>= 1;
  }
  return r;
}

function polyEval(c: Uint8Array, x: number): number {
  let r = 0;
  for (let i = c.length - 1; i >= 0; i--) r = c[i] ^ gfMul(r, x);
  return r;
}

interface Share {
  x: number;
  y: Uint8Array;
}

function sssSplit(secret: Uint8Array, shares: number, threshold: number): Share[] {
  const result: Share[] = Array.from({ length: shares }, (_, i) => ({
    x: i + 1,
    y: new Uint8Array(secret.length),
  }));
  for (let bi = 0; bi < secret.length; bi++) {
    const coeffs = new Uint8Array(threshold);
    coeffs[0] = secret[bi];
    const rand = crypto.getRandomValues(new Uint8Array(threshold - 1));
    for (let i = 1; i < threshold; i++) coeffs[i] = rand[i - 1];
    for (let s = 0; s < shares; s++) result[s].y[bi] = polyEval(coeffs, result[s].x);
  }
  return result;
}

function sssCombine(shares: Share[], threshold = 2): Uint8Array {
  if (shares.length < threshold) throw new Error(`Need at least ${threshold} shares`);
  const xs = shares.map((s) => s.x);
  if (new Set(xs).size !== xs.length) throw new Error("Duplicate share x-values");
  const len = shares[0].y.length;
  const secret = new Uint8Array(len);
  for (let bi = 0; bi < len; bi++) {
    let value = 0;
    for (let i = 0; i < shares.length; i++) {
      let num = 1,
        den = 1;
      for (let j = 0; j < shares.length; j++) {
        if (j === i) continue;
        num = gfMul(num, shares[j].x);
        den = gfMul(den, shares[i].x ^ shares[j].x);
      }
      // Lagrange interpolation at x=0; den^254 is the GF(256) inverse of den.
      value ^= gfMul(shares[i].y[bi], gfMul(num, gfPow(den, 254)));
    }
    secret[bi] = value;
  }
  return secret;
}

function ser(s: Share): string {
  return `${s.x}:${bytesToBase64(s.y)}`;
}

function deser(raw: string): Share {
  const parts = raw.split(":");
  if (parts.length !== 2) throw new Error("Invalid shard format");
  const x = parseInt(parts[0], 10);
  if (!Number.isInteger(x) || x < 1 || x > 255) throw new Error("Invalid shard index");
  return { x, y: base64ToBytes(parts[1]) };
}

/** Split a base64 key into a 2-of-3 set of serialized shards. */
export function splitKey(keyB64: string): [string, string, string] {
  const keyBytes = base64ToBytes(keyB64);
  const shares = sssSplit(keyBytes, 3, 2);
  return [ser(shares[0]), ser(shares[1]), ser(shares[2])];
}

/** Reconstruct the base64 key from any 2+ serialized shards. */
export function reconstructKey(shards: string[]): string {
  if (!Array.isArray(shards) || shards.length < 2) throw new Error("Need at least 2 shards");
  const shares = shards.map(deser);
  const keyBytes = sssCombine(shares);
  return bytesToBase64(keyBytes);
}
