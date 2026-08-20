/** Typed errors — the integrator branches on class/code, never on message strings. */

export class DefarmError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** A non-2xx API response. */
export class ApiError extends DefarmError {
  constructor(
    public readonly status: number,
    public readonly code: string | undefined,
    message: string,
    public readonly body?: unknown,
  ) {
    super(message);
  }
}

/**
 * A recipient cannot receive seals yet (no registered encryption key). The app should surface
 * "invite them / ask them to register a key", not a stack trace.
 */
export class RecipientNotReadyError extends DefarmError {
  constructor(public readonly recipient: string) {
    super(
      `recipient "${recipient}" has no valid encryption key registered — they must register one before they can receive sealed fields`,
    );
  }
}

/**
 * The recipient's key binding did not verify: the Ed25519 signature over
 * (workspace_id, enc_key_id, enc_pubkey) does not close. NEVER seal to such a key —
 * a swapped lock is exactly what this check exists to catch.
 */
export class RecipientBindingError extends DefarmError {
  constructor(public readonly recipient: string) {
    super(
      `encryption-key binding for "${recipient}" failed verification — refusing to seal to an unverified key`,
    );
  }
}

/**
 * The field is not declared sealable on the DeFarm side (`field_protection` is `clear`).
 * Declaring it is a DeFarm admin action (engines#582), not something the partner can do.
 */
export class NotSealableFieldError extends DefarmError {
  constructor(public readonly fieldPath: string) {
    super(
      `field "${fieldPath}" is not declared sealable — ask DeFarm to set its field_protection (engines#582)`,
    );
  }
}

/** Feature blocked on a backend issue — declared, not faked. */
export class NotImplementedError extends DefarmError {
  constructor(feature: string, issue: string) {
    super(`${feature} is not available yet — blocked on ${issue}`);
  }
}

export class KeystoreError extends DefarmError {}

/** Wrong credential type for a call (e.g. ingestion requires X-API-Key, not a Bearer token). */
export class AuthModeError extends DefarmError {}
