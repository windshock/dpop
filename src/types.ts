export interface User {
  id: string;
  email: string;
  google_id?: string;
  webauthn_credential_id?: string;
  webauthn_public_key?: string;
  created_at: string;
}

export interface DPoPKey {
  id: string;
  user_id: string;
  jkt: string; // key thumbprint
  public_key: string; // JWK
  member_id?: string; // optional bound member_id
  created_at: string;
}

export interface Event {
  id: string;
  member_id: string;
  jkt: string;
  htm: string;
  htu: string;
  iat: number;
  jti: string;
  payload: any;
  created_at: string;
}

export interface CanonicalEvent {
  member_id_canonical: string;
  member_id_confidence: number;
  trust_level: string;
  risk_score: number;
  action: 'ALLOW' | 'CHALLENGE' | 'QUARANTINE';
  reason_codes: string[];
}

export interface IngestResponse {
  proof_verified: boolean;
  risk_score: number;
  action: 'ALLOW' | 'CHALLENGE' | 'QUARANTINE';
  trust_level: string;
  reason_codes: string[];
}