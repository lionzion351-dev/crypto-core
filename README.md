# @vaultpass/crypto-core

The cryptographic core of [VaultPass](https://www.vaultpass.network) — extracted as a
standalone, **MIT-licensed**, dependency-free module so anyone can read, run, and verify
the primitives that protect a vault.

> **Zero-knowledge by design.** Every operation here runs client-side. Plaintext and
> full keys never reach a server. This repo is the math behind that guarantee — published
> so you don't have to take our word for it.

## What's inside

| Primitive | Purpose | Implementation |
|-----------|---------|----------------|
| **AES-256-GCM** | Vault encryption | Browser-native `crypto.subtle`; fresh 256-bit key + random 96-bit IV per encryption; 128-bit auth tag retained |
| **SHA-256** | Hashing | Browser-native `crypto.subtle.digest` |
| **Shamir's Secret Sharing** | Key sharding | GF(2⁸), reduction polynomial `0x11d`, 2-of-3 threshold, coefficients from the platform CSPRNG |

**No third-party cryptographic dependencies.** Everything builds on the
[Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API),
available natively in browsers and in Node.js ≥ 22.

## Usage

```ts
import { encryptSeedPhrase, decryptSeedPhrase, splitKey, reconstructKey } from "@vaultpass/crypto-core";

// 1. Encrypt client-side
const { encryptedBlob, key } = await encryptSeedPhrase("my secret recovery phrase");

// 2. Split the key into a 2-of-3 set of shards (owner / heir / sentinel)
const [ownerShard, heirShard, sentinelShard] = splitKey(key);

// 3. Any two shards reconstruct the key — no single party can
const recoveredKey = reconstructKey([ownerShard, heirShard]);

// 4. Decrypt
const plaintext = await decryptSeedPhrase(encryptedBlob, recoveredKey);
```

## Verify it yourself

```bash
npm test        # round-trip, tamper-detection, IV-uniqueness, known SHA-256 vector, 2-of-3 reconstruction
```

Or paste the primitives into any browser DevTools console — `crypto.subtle` is right there.

## Design rationale

- **Why AES-256-GCM over ChaCha20-Poly1305?** Both are AEAD with equivalent margins;
  AES-256-GCM is browser-native, eliminating the risk of a flawed JS cipher implementation,
  and benefits from hardware acceleration.
- **Why Shamir's Secret Sharing over threshold signatures (FROST)?** SSS is
  information-theoretically secure and supports *offline* shard distribution — essential for
  inheritance, where an heir may only come online months or years after setup.
- **Why browser-native primitives only?** To eliminate supply-chain risk from third-party
  cryptographic JavaScript.

## Scope & status

This is the cryptographic core only — not the full VaultPass application. An independent
third-party audit of VaultPass is scheduled for H2 2026; its report will be published on
completion. Until then, this code is provided for transparency and independent review.

## License

MIT © VaultPass
