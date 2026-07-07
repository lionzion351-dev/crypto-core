import { test } from "node:test";
import assert from "node:assert/strict";

import { encryptSeedPhrase, decryptSeedPhrase } from "../src/aes-gcm.ts";
import { sha256 } from "../src/hash.ts";
import { splitKey, reconstructKey } from "../src/shamir.ts";

test("AES-256-GCM round-trips a secret", async () => {
  const secret = "correct horse battery staple — abandon ability able about";
  const { encryptedBlob, key } = await encryptSeedPhrase(secret);
  assert.match(encryptedBlob, /^[^.]+\.[^.]+$/, "blob is iv.ciphertext");
  assert.equal(await decryptSeedPhrase(encryptedBlob, key), secret);
});

test("AES-GCM rejects a tampered ciphertext (auth tag)", async () => {
  const { encryptedBlob, key } = await encryptSeedPhrase("hello");
  const [iv, ct] = encryptedBlob.split(".");
  const flipped = ct.slice(0, -2) + (ct.slice(-2) === "AA" ? "AB" : "AA");
  await assert.rejects(() => decryptSeedPhrase(`${iv}.${flipped}`, key));
});

test("AES-GCM uses a unique IV per encryption", async () => {
  const a = await encryptSeedPhrase("same plaintext");
  const b = await encryptSeedPhrase("same plaintext");
  assert.notEqual(a.encryptedBlob.split(".")[0], b.encryptedBlob.split(".")[0]);
});

test("SHA-256 matches the known vector for 'abc'", async () => {
  assert.equal(
    await sha256("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("Shamir 2-of-3: any two shards reconstruct the key", () => {
  const key = "c29tZS0yNTYtYml0LWtleS1tYXRlcmlhbC1iYXNlNjQ="; // arbitrary base64
  const [s1, s2, s3] = splitKey(key);
  assert.equal(reconstructKey([s1, s2]), key);
  assert.equal(reconstructKey([s1, s3]), key);
  assert.equal(reconstructKey([s2, s3]), key);
  assert.equal(reconstructKey([s1, s2, s3]), key);
});

test("Shamir: a single shard reveals nothing and cannot reconstruct", () => {
  const key = "YW5vdGhlci1zZWNyZXQta2V5LXZhbHVl";
  const [s1] = splitKey(key);
  assert.throws(() => reconstructKey([s1]), /at least 2 shards/);
});

test("Shamir: malformed shard input is rejected", () => {
  assert.throws(() => reconstructKey(["not-a-shard", "also-bad"]));
});

test("Shamir: empty shard payload is rejected (SSS-06)", () => {
  const [, s2] = splitKey("YW5vdGhlci1zZWNyZXQta2V5LXZhbHVl");
  assert.throws(() => reconstructKey(["1:", s2]), /empty/);
});

test("Shamir: mismatched shard lengths are rejected (SSS-02)", () => {
  const [s1] = splitKey("c29tZS0yNTYtYml0LWtleS1tYXRlcmlhbC1iYXNlNjQ=");
  assert.throws(() => reconstructKey([s1, "2:AAAA"]), /length mismatch/);
});

test("Shamir: non-numeric shard index is rejected (SSS-03)", () => {
  const [, s2] = splitKey("YW5vdGhlci1zZWNyZXQta2V5LXZhbHVl");
  assert.throws(() => reconstructKey(["1abc:AAAA", s2]), /Invalid shard index/);
});

test("Shamir: empty shard array is rejected", () => {
  assert.throws(() => reconstructKey([]), /at least 2 shards/);
});

test("Shamir: whitespace in shard base64 is rejected (SSS-09)", () => {
  const [s1, s2] = splitKey("YW5vdGhlci1zZWNyZXQta2V5LXZhbHVl");
  const [x, b64] = s2.split(":");
  const mutated = `${x}:${b64.slice(0, 2)} ${b64.slice(2)}`;
  assert.throws(() => reconstructKey([s1, mutated]), /whitespace/);
});

test("AES-GCM: wrong-length IV blob is rejected (AES-01)", async () => {
  const { encryptedBlob, key } = await encryptSeedPhrase("hello");
  const ct = encryptedBlob.split(".")[1];
  await assert.rejects(() => decryptSeedPhrase(`AAAA.${ct}`, key), /Invalid IV/);
});

test("SHA-256 of empty string matches the known vector", async () => {
  assert.equal(
    await sha256(""),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
});
