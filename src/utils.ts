export function base64urlEncode(input: ArrayBuffer | Uint8Array): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64urlDecodeToUint8Array(base64url: string): Uint8Array {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4 ? '='.repeat(4 - (base64.length % 4)) : '';
  const bin = atob(base64 + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export async function sha256Base64url(input: string): Promise<string> {
  const enc = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', enc);
  return base64urlEncode(digest);
}

export function randomBase64url(bytes: number = 32): string {
  const arr = crypto.getRandomValues(new Uint8Array(bytes));
  return base64urlEncode(arr);
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}


