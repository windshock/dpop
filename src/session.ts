import { getCookie } from './http';
import { nowSeconds } from './utils';
import type { User } from './types';

const SESSION_COOKIE = 'session';

export function isSecureRequest(request: Request): boolean {
  return new URL(request.url).protocol === 'https:';
}

export async function createSession(db: D1Database, userId: string, ttlSeconds: number = 60 * 60 * 24): Promise<string> {
  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
  await db
    .prepare('INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .bind(id, userId, createdAt, expiresAt)
    .run();
  return id;
}

export async function getSessionUser(request: Request, db: D1Database): Promise<User | null> {
  const sessionId = getCookie(request, SESSION_COOKIE);
  if (!sessionId) return null;

  const now = nowSeconds();
  const row = (await db
    .prepare(
      `SELECT u.* FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.id = ?
       AND strftime('%s', s.expires_at) > ?`,
    )
    .bind(sessionId, now)
    .first()) as User | null;

  return row ?? null;
}

export function sessionCookieName(): string {
  return SESSION_COOKIE;
}






