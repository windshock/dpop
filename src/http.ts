export function json(data: unknown, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  return new Response(JSON.stringify(data), { ...init, headers });
}

export async function readJson<T>(request: Request): Promise<T> {
  return (await request.json()) as T;
}

export function getCookie(request: Request, name: string): string | undefined {
  const cookie = request.headers.get('Cookie');
  if (!cookie) return undefined;
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match?.[1];
}

export function setCookieHeader(opts: {
  name: string;
  value: string;
  maxAgeSeconds?: number;
  httpOnly?: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None';
  path?: string;
  secure?: boolean;
}): string {
  const parts = [`${opts.name}=${opts.value}`];
  parts.push(`Path=${opts.path ?? '/'}`);
  if (opts.maxAgeSeconds != null) parts.push(`Max-Age=${opts.maxAgeSeconds}`);
  if (opts.httpOnly !== false) parts.push('HttpOnly');
  parts.push(`SameSite=${opts.sameSite ?? 'Lax'}`);
  if (opts.secure) parts.push('Secure');
  return parts.join('; ');
}




