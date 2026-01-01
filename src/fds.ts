import { Event, CanonicalEvent, DPoPKey } from './types';

export async function processEvent(event: Event, db: D1Database): Promise<CanonicalEvent> {
  let member_id_canonical = event.member_id;
  let confidence = 1.0;
  let trust_level = 'HIGH';
  let risk_score = 0;
  let action: 'ALLOW' | 'CHALLENGE' | 'QUARANTINE' = 'ALLOW';
  const reason_codes: string[] = [];

  // Rule 1: distinct member ids per jkt
  const distinctMembers = await db.prepare('SELECT DISTINCT member_id FROM events WHERE jkt = ?').bind(event.jkt).all();
  if (distinctMembers.results.length > 1) {
    reason_codes.push('MULTIPLE_MEMBER_IDS_PER_JKT');
    risk_score += 0.3;
    confidence -= 0.2;
  }

  // Rule 2: event rate (e.g., >10 per minute)
  const recentEvents = await db.prepare('SELECT COUNT(*) as count FROM events WHERE jkt = ? AND created_at > ?').bind(event.jkt, new Date(Date.now() - 60000).toISOString()).first();
  if (recentEvents.count > 10) {
    reason_codes.push('HIGH_EVENT_RATE');
    risk_score += 0.4;
    action = 'CHALLENGE';
  }

  // Rule 3: new key for member
  const keyRecord = await db.prepare('SELECT * FROM dpop_keys WHERE jkt = ?').bind(event.jkt).first() as DPoPKey | null;
  if (keyRecord && keyRecord.member_id && keyRecord.member_id !== event.member_id) {
    reason_codes.push('MEMBER_ID_MISMATCH');
    risk_score += 0.5;
    confidence -= 0.5;
    action = 'QUARANTINE';
  }

  // Rule 4: rooted/emulator flags (placeholder)
  // Assume payload has flags
  if (event.payload.rooted || event.payload.emulator) {
    reason_codes.push('ROOTED_OR_EMULATOR');
    risk_score += 0.6;
    action = 'QUARANTINE';
  }

  // Rule 5: invalid member id format
  if (!/^[a-zA-Z0-9_-]+$/.test(event.member_id)) {
    reason_codes.push('INVALID_MEMBER_ID_FORMAT');
    risk_score += 0.2;
    confidence -= 0.1;
  }

  // Rule 6: proof failures (already checked in verifyDPoP)

  if (risk_score > 0.5) action = 'CHALLENGE';
  if (risk_score > 0.8) action = 'QUARANTINE';

  if (confidence < 0.5) trust_level = 'LOW';
  else if (confidence < 0.8) trust_level = 'MEDIUM';

  return {
    member_id_canonical,
    member_id_confidence: confidence,
    trust_level,
    risk_score,
    action,
    reason_codes
  };
}