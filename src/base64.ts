// Safe base64 <-> bytes conversion.
//
// `btoa(String.fromCharCode(...bytes))` throws RangeError once the spread
// exceeds the engine's argument limit (~125k), so it breaks on any blob larger
// than a short seed phrase. These helpers chunk the work and are byte-identical
// to the btoa/atob path.

const CHUNK = 0x8000; // 32 KB — safely under the argument-count limit

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
