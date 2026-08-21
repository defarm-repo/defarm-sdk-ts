/**
 * @defarm/sdk — DeFarm client SDK with client-side sealing (blind envelopes).
 *
 * The five core operations:
 *   ensureKeys()  — generate + register key pairs (private keys never leave your side)
 *   ingest()      — partner ingestion (X-API-Key), with dry-run preview
 *   seal()        — encrypt a field so only addressed recipients can read; DeFarm stays blind
 *   open()        — a recipient decrypts locally and verifies commitment + authorship
 *   verify()      — public verification of a DFID
 *
 * Pure crypto lives in `@defarm/sdk/core` — auditable, network-free, held to byte-for-byte
 * conformance with the Rust reference implementation.
 */
export {
  DefarmClient,
  MemoryKeystore,
  FileKeystore,
  type DefarmConfig,
  type KeyIdentity,
  type SealInput,
  type OpenInput,
  type SealResult,
  type SealRecipientInput,
  type OpenResult,
  type IngestOptions,
  type IngestResult,
  type VerifyReport,
  type Keystore,
} from "./client.js";
export type { KeyKind, StoredKey } from "./keystore.js";
export {
  DefarmError,
  ApiError,
  AuthModeError,
  InvalidInputError,
  KeyMismatchError,
  KeystoreError,
  NotImplementedError,
  NotSealableFieldError,
  RecipientBindingError,
  RecipientNotReadyError,
} from "./errors.js";
export type { SealedField, Wrap, Recipient } from "./core/envelope.js";
export { OpenFieldError, type OpenFailureReason } from "./core/open.js";
