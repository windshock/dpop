export interface Env {
  DB: D1Database;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  RP_ID: string;
  ORIGIN: string;
  WEBAUTHN_RP_NAME: string;
  ACCESS_TOKEN_SECRET: string;
  /**
   * Comma-separated list of legacy origins allowed to use the popup SDK agent.
   * Example: "https://www.okcashbag.com,https://m.okcashbag.com"
   * If unset, the agent will allow all origins (dev-only).
   */
  SDK_ALLOWED_ORIGINS?: string;
  /**
   * Local dev only: trust X-Forwarded-* headers for URL reconstruction behind the TLS proxy.
   * Set to "1" in .dev.vars when using dev/tls-proxy.mjs.
   */
  TRUST_PROXY_HEADERS?: string;
}




