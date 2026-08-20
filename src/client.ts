import {
  ed25519PublicKey,
  generateEd25519KeyPair,
  generateX25519KeyPair,
  x25519PublicKey,
} from "./core/index.js";
import { fromBase64, fromUtf8, toBase64, toHex, utf8 } from "./core/encoding.js";
import type { Recipient, SealedField } from "./core/envelope.js";
import { sealField } from "./core/seal.js";
import { openField } from "./core/open.js";
import {
  signEncKeyBinding,
  signSealedField,
  verifyEncKeyBinding,
  verifySealerSignature,
} from "./core/signing.js";
import { sha256 } from "@noble/hashes/sha256";
import { Http } from "./api/http.js";
import type {
  RecipientSealedField,
  RecipientSealedFieldsPage,
  UserInfo,
} from "./api/types.js";
import {
  ApiError,
  AuthModeError,
  InvalidInputError,
  KeyMismatchError,
  KeystoreError,
  NotImplementedError,
  NotSealableFieldError,
  RecipientBindingError,
} from "./errors.js";
import { FileKeystore, MemoryKeystore, type Keystore } from "./keystore.js";

export interface DefarmConfig {
  /**
   * Gateway base URL (e.g. `https://gateway.defarm.net`). `/auth/*` lives at the root,
   * everything else under `/v1`. Swapping this repoints the whole client.
   */
  gateway: string;
  auth?: { bearer?: string; apiKey?: string };
  /** Where private keys live. Defaults to a chmod-0600 JSON file under `~/.defarm/`. */
  keystore?: Keystore;
  /** Which network anchors are expected on. Default `testnet`; `public` (mainnet) is explicit opt-in. */
  network?: "testnet" | "public";
  fetch?: typeof fetch;
}

/** Identity + registered key ids — NEVER private material. */
export interface KeyIdentity {
  workspaceId: string;
  signingKeyId: string;
  signingPubkeyB64: string;
  encKeyId: string;
  encPubkeyB64: string;
  encKeyFingerprint: string;
}

/**
 * A recipient to seal to, pre-resolved OUT OF BAND (workaround while the in-circuit recipient
 * resolver endpoint is broken behind the gateway — collection step [S6]). The SDK still
 * re-verifies the binding before sealing, exactly as it would with directory-served keys, so the
 * cryptographic guarantee is unchanged. This input surface will be removed once the directory
 * endpoint works — identity→key resolution belongs to the directory, not the caller.
 */
export interface SealRecipientInput {
  workspaceId: string;
  encKeyId: string;
  encPubkeyB64: string;
  /** The recipient's Ed25519 signing public key (to verify the binding against). */
  signingPubkeyB64: string;
  /** The recipient's Ed25519 signature over the canonical (workspace, key id, pubkey) binding. */
  bindingSigB64: string;
}

/** Everything `seal` needs, in one object (issue #3: `seal` and `open` share the same shape style). */
export interface SealInput {
  /** The item's DFID. */
  dfid: string;
  /** The field to seal (e.g. `preco_venda`). */
  fieldPath: string;
  /** The value — a string is sealed as `text/plain`, anything else as JSON. */
  value: unknown;
  /** The circuit the event is written into (the integrator's domain knowledge). */
  circuitId: string;
  /** Who can open. Default: nobody but yourself (sealed-private). */
  to?: SealRecipientInput[];
  /** Wrap for your own key too, so you never lose access to your own data. Default true; opt-out is explicit. */
  includeSelf?: boolean;
  /** Declared content type. Default: `text/plain` for strings, `application/json` otherwise. */
  contentType?: string;
  /**
   * Event visibility. Default `private` (safe default for sensitive data). `public` makes the
   * ENVELOPE (commitment, not the value) surface on the public /verify page.
   */
  visibility?: "private" | "public";
}

export interface OpenInput {
  dfid: string;
  fieldPath: string;
}

export interface SealResult {
  dfid: string;
  fieldPath: string;
  clientEventId: string;
  commitment: string;
  /** How many locks were added (wraps) — 1 vault, N padlocks. */
  recipients: number;
  envelope: SealedField;
  response: unknown;
}

export interface OpenResult {
  dfid: string;
  fieldPath: string;
  /** Decoded per the declared content type (string for text/plain, parsed JSON for application/json). */
  value: unknown;
  raw: Uint8Array;
  sealer: { workspaceId: string; keyId: string };
  /** Server-side authorship verdict (re-verified against the trusted key valid at event time). */
  authorshipVerified: boolean;
  /** Local re-verification of the sealer signature (when the server returned the public key). */
  sealerSignatureVerifiedLocally: boolean | null;
}

export interface IngestOptions {
  /** Dry-run via `/partner/ingestions/preview` — nothing is written or anchored. */
  preview?: boolean;
}

export interface IngestResult {
  dfids: string[];
  preview: boolean;
  response: unknown;
}

export interface VerifyReport {
  dfid: string;
  /** The aggregator response as returned by `GET /v1/verify/{dfid}` — the source of truth. */
  raw: unknown;
  /** Best-effort extraction: RFC3161 trusted timestamps present? */
  hasTrustedTimestamps: boolean;
  /** Best-effort extraction: sealed-field commitments surfaced (envelope visible, value blind)? */
  sealedCommitments: string[];
}

export class DefarmClient {
  private readonly http: Http;
  private readonly keystore: Keystore;
  readonly network: "testnet" | "public";
  private identity: KeyIdentity | null = null;
  private cachedMe: { userId: string; workspaceId: string } | null = null;

  constructor(private readonly config: DefarmConfig) {
    this.http = new Http(config.gateway, { ...config.auth }, config.fetch ?? fetch);
    this.keystore = config.keystore ?? new LazyFileKeystore();
    this.network = config.network ?? "testnet";
  }

  // ── auth ────────────────────────────────────────────────────────────────────

  /** Log in with workspace credentials; stores the bearer for subsequent calls. */
  async login(email: string, password: string): Promise<void> {
    const j = await this.http.request<Record<string, unknown>>(
      "POST",
      `${this.http.root}/auth/login`,
      { body: { email, password }, auth: "none" },
    );
    const token =
      (j["access_token"] as string | undefined) ??
      (j["token"] as string | undefined) ??
      ((j["data"] as Record<string, unknown> | undefined)?.["access_token"] as
        | string
        | undefined);
    if (!token) throw new ApiError(0, "no_token", "login response carried no token");
    this.http.setBearer(token);
    this.cachedMe = null;
  }

  /** Who am I — user + workspace of the current bearer. */
  async me(): Promise<{ userId: string; workspaceId: string }> {
    if (this.cachedMe) return this.cachedMe;
    const j = await this.http.request<UserInfo>("GET", `${this.http.root}/auth/me`);
    const workspaceId = j.workspace_id ?? j.workspace?.id;
    const userId = j.user_id ?? j.id;
    if (!workspaceId) {
      throw new ApiError(0, "no_workspace", "/auth/me returned no workspace id");
    }
    this.cachedMe = { userId: userId ?? "", workspaceId };
    return this.cachedMe;
  }

  // ── 1. ensureKeys ───────────────────────────────────────────────────────────

  /**
   * Generate (client-side, first time only) and register this workspace's key pairs:
   * Ed25519 for authorship and X25519 for encryption, the public halves only, the encryption key
   * carrying its signed binding. Idempotent. The DeFarm server is a DIRECTORY, not an authority:
   * it never sees a private key, and this method never returns one.
   */
  async ensureKeys(): Promise<KeyIdentity> {
    if (this.identity) return this.identity;
    const { workspaceId } = await this.me();

    let signing = await this.keystore.get("signing");
    if (!signing) {
      const kp = generateEd25519KeyPair();
      signing = { keyId: `sign-${randomSuffix()}`, privateKey: kp.seed };
      await this.keystore.put("signing", signing);
    }
    const signingPub = ed25519PublicKey(signing.privateKey);
    const signingPubB64 = toBase64(signingPub);

    let enc = await this.keystore.get("encryption");
    if (!enc) {
      const kp = generateX25519KeyPair();
      enc = { keyId: `enc-${randomSuffix()}`, privateKey: kp.privateKey };
      await this.keystore.put("encryption", enc);
    }
    const encPub = x25519PublicKey(enc.privateKey);
    const encPubB64 = toBase64(encPub);

    await this.registerTolerant(`${this.http.base}/workspace/signing-keys`, {
      key_id: signing.keyId,
      algorithm: "ed25519",
      public_key_b64: signingPubB64,
      metadata: {},
    });

    const bindingSig = signEncKeyBinding(
      workspaceId,
      enc.keyId,
      encPubB64,
      signing.privateKey,
    );
    await this.registerTolerant(`${this.http.base}/workspace/encryption-keys`, {
      key_id: enc.keyId,
      algorithm: "x25519",
      public_key_b64: encPubB64,
      signing_key_id: signing.keyId,
      binding_sig_b64: bindingSig,
      metadata: {},
    });

    this.identity = {
      workspaceId,
      signingKeyId: signing.keyId,
      signingPubkeyB64: signingPubB64,
      encKeyId: enc.keyId,
      encPubkeyB64: encPubB64,
      encKeyFingerprint: `sha256:${toHex(sha256(encPub))}`,
    };
    return this.identity;
  }

  /**
   * POST that tolerates "already registered" (409) — what makes ensureKeys idempotent. But a 409
   * is only success if the key registered under this key_id has the SAME public key the local
   * private key derives (issue #4): a restored backup, two machines sharing a key_id, or a race
   * can leave the directory holding a different public key — then every seal addressed to this
   * workspace is unopenable, with the error surfacing far from the cause (the engines#528 class:
   * registers fine, breaks every later seal). On 409 we GET the registered key and compare;
   * mismatch is a hard, named error — never a silent "ok".
   */
  private async registerTolerant(
    url: string,
    body: { key_id: string; public_key_b64: string; [k: string]: unknown },
  ): Promise<void> {
    try {
      await this.http.request("POST", url, { body });
    } catch (e) {
      if (!(e instanceof ApiError) || e.status !== 409) throw e;
      const registered = await this.http.request<
        { key_id: string; public_key_b64: string }[]
      >("GET", url);
      const existing = registered.find((k) => k.key_id === body.key_id);
      if (!existing) throw e; // 409 for some other reason — surface the original error
      if (existing.public_key_b64.trim() !== body.public_key_b64.trim()) {
        throw new KeyMismatchError(body.key_id);
      }
    }
  }

  // ── 2. ingest ───────────────────────────────────────────────────────────────

  /**
   * Partner ingestion (X-API-Key only — a Bearer here is a config mistake and fails fast).
   * With `preview: true` it dry-runs: nothing written, nothing anchored. Items land in the
   * circuit bound to the API key.
   */
  async ingest(items: Record<string, unknown>[], opts: IngestOptions = {}): Promise<IngestResult> {
    if (!this.http.hasApiKey()) {
      throw new AuthModeError(
        "ingest requires a partner API key (auth.apiKey) — Bearer tokens are rejected by /partner/ingestions",
      );
    }
    const url = opts.preview
      ? `${this.http.base}/partner/ingestions/preview`
      : `${this.http.base}/partner/ingestions`;
    const response = await this.http.request<unknown>("POST", url, {
      body: { items },
      auth: "apiKey",
    });
    return { dfids: collectDfids(response), preview: !!opts.preview, response };
  }

  // ── 3. seal ─────────────────────────────────────────────────────────────────

  /**
   * Seal one field of an item: encrypt client-side so that ONLY the addressed recipients can ever
   * read it — the DeFarm server stores the envelope and is structurally blind. Defaults are the
   * safe ones: no recipients = sealed for yourself only; your own key is always included unless
   * you explicitly opt out; visibility is private.
   *
   * Every recipient's key binding is RE-VERIFIED here before sealing — a key whose binding does
   * not close is refused (`RecipientBindingError`), even if it came from the DeFarm directory.
   */
  async seal(input: SealInput): Promise<SealResult> {
    requireString(input, "dfid");
    requireString(input, "fieldPath");
    requireString(input, "circuitId");
    if (!("value" in input) || input.value === undefined) {
      throw new InvalidInputError("value", 'seal() requires "value" — the data to seal');
    }
    const { dfid, fieldPath, value, ...opts } = input;
    const identity = await this.ensureKeys();
    const signing = await this.keystore.get("signing");
    if (!signing) throw new KeystoreError("signing key vanished from keystore");

    // Recipients: verify EVERY binding, then add self unless opted out.
    const recipients: Recipient[] = [];
    for (const r of opts.to ?? []) {
      const ok = verifyEncKeyBinding(
        r.workspaceId,
        r.encKeyId,
        r.encPubkeyB64,
        r.bindingSigB64,
        r.signingPubkeyB64,
      );
      if (!ok) throw new RecipientBindingError(`${r.workspaceId}/${r.encKeyId}`);
      recipients.push({
        workspaceId: r.workspaceId,
        encKeyId: r.encKeyId,
        encPubkeyB64: r.encPubkeyB64,
      });
    }
    if (opts.includeSelf !== false) {
      recipients.push({
        workspaceId: identity.workspaceId,
        encKeyId: identity.encKeyId,
        encPubkeyB64: identity.encPubkeyB64,
      });
    }
    if (recipients.length === 0) {
      throw new KeystoreError(
        "sealing with includeSelf:false and no recipients would make the value unreadable forever",
      );
    }

    // Encode the value + pick the content type.
    const isString = typeof value === "string";
    const contentType = opts.contentType ?? (isString ? "text/plain" : "application/json");
    const plaintext = utf8(isString ? value : JSON.stringify(value));

    // The $sealed event needs the item's internal UUID, not the DFID — resolve it here so the
    // integrator never learns this dance exists.
    const itemUuid = await this.itemUuid(dfid);

    const clientEventId = crypto.randomUUID();
    const unsigned = await sealField(
      dfid,
      clientEventId,
      fieldPath,
      contentType,
      plaintext,
      recipients,
    );
    const envelope = signSealedField(
      unsigned,
      identity.workspaceId,
      identity.signingKeyId,
      signing.privateKey,
    );

    let response: unknown;
    try {
      response = await this.http.request("POST", `${this.http.base}/events`, {
        body: {
          event_type: "item_updated",
          source_type: "producer",
          circuit_id: opts.circuitId,
          item_id: itemUuid,
          visibility: opts.visibility ?? "private",
          payload: {
            client_event_id: clientEventId,
            $sealed: [{ field_path: fieldPath, sealed_field: envelope }],
          },
        },
      });
    } catch (e) {
      if (e instanceof ApiError && /field_protection|not.*sealable|sealed_not_allowed/i.test(`${e.code} ${e.message}`)) {
        throw new NotSealableFieldError(fieldPath);
      }
      throw e;
    }

    return {
      dfid,
      fieldPath,
      clientEventId,
      commitment: envelope.commitment_sha256,
      recipients: recipients.length,
      envelope,
      response,
    };
  }

  // ── 4. open ─────────────────────────────────────────────────────────────────

  /**
   * Open a sealed field addressed to this workspace: fetch the envelope, unwrap the DK with the
   * LOCAL private key, decrypt, and verify commitment + sealer signature. All decryption happens
   * here — the server only ever handed over the padlocked envelope.
   */
  async open(ref: OpenInput): Promise<OpenResult> {
    requireString(ref, "dfid");
    requireString(ref, "fieldPath");
    const enc = await this.keystore.get("encryption");
    if (!enc) {
      throw new KeystoreError("no encryption key in keystore — call ensureKeys() first");
    }

    const match = await this.findSealedField(ref.dfid, ref.fieldPath, enc.keyId);
    if (!match) {
      throw new ApiError(
        404,
        "sealed_field_not_found",
        `no sealed field "${ref.fieldPath}" on ${ref.dfid} addressed to this workspace's key`,
      );
    }

    const raw = await openField(match.sealed_field, enc.keyId, enc.privateKey);

    const sealerSignatureVerifiedLocally = localAuthorshipCheck(match);

    const text = fromUtf8(raw);
    const value = match.content_type === "application/json" ? JSON.parse(text) : text;

    return {
      dfid: ref.dfid,
      fieldPath: ref.fieldPath,
      value,
      raw,
      sealer: { workspaceId: match.sealer_workspace_id, keyId: match.sealer_key_id },
      authorshipVerified: match.authorship_verified,
      sealerSignatureVerifiedLocally,
    };
  }

  /** Paginate the recipient inbox until the field is found. Stop on `next_cursor == null`, not on an empty page. */
  private async findSealedField(
    dfid: string,
    fieldPath: string,
    encKeyId: string,
  ): Promise<RecipientSealedField | null> {
    let cursor: string | null = null;
    do {
      const url = new URL(`${this.http.base}/workspace/sealed-fields`);
      url.searchParams.set("dfid", dfid);
      if (cursor) url.searchParams.set("cursor", cursor);
      const page: RecipientSealedFieldsPage = await this.http.request(
        "GET",
        url.toString(),
      );
      const hit = page.sealed_fields.find(
        (f) => f.field_path === fieldPath && f.recipient_enc_key_id === encKeyId,
      );
      if (hit) return hit;
      cursor = page.next_cursor;
    } while (cursor);
    return null;
  }

  // ── 5. verify ───────────────────────────────────────────────────────────────

  /**
   * Public verification of a DFID via the aggregator (`GET /v1/verify/{dfid}` — no auth). Returns
   * the raw report plus best-effort extractions. For fully independent verification (Horizon,
   * IPFS, hash recomputation) use the open-source `defarm-repo/defarm-verify` tooling — deep
   * parity is planned for this SDK.
   */
  async verify(dfid: string): Promise<VerifyReport> {
    const raw = await this.http.request<unknown>(
      "GET",
      `${this.http.base}/verify/${encodeURIComponent(dfid)}`,
      { auth: "none" },
    );
    const text = JSON.stringify(raw);
    const sealedCommitments = [...text.matchAll(/"commitment[^"]*"\s*:\s*"([0-9a-f]{64})"/g)].map(
      (m) => m[1]!,
    );
    return {
      dfid,
      raw,
      hasTrustedTimestamps: /trusted_timestamps/.test(text),
      sealedCommitments: [...new Set(sealedCommitments)],
    };
  }

  // ── secondary surface ───────────────────────────────────────────────────────

  /** Full item view (membership-gated: members see raw fields, others get a uniform 404). */
  async getItem(dfid: string): Promise<unknown> {
    return this.http.request("GET", `${this.http.base}/items/${encodeURIComponent(dfid)}`);
  }

  /** Public item view (skeleton + commitments; personal identifiers masked). No auth. */
  async getItemPublic(dfid: string): Promise<unknown> {
    return this.http.request(
      "GET",
      `${this.http.base}/items/${encodeURIComponent(dfid)}/public`,
      { auth: "none" },
    );
  }

  /** Resolve an item by domain identifier (SISBOV, chip, …). */
  async resolveByIdentifier(
    identifierType: string,
    value: string,
    circuitId?: string,
  ): Promise<unknown> {
    const url = new URL(`${this.http.base}/search/identifier`);
    url.searchParams.set("identifier_type", identifierType);
    url.searchParams.set("value", value);
    if (circuitId) url.searchParams.set("circuit_id", circuitId);
    return this.http.request("GET", url.toString());
  }

  private async itemUuid(dfid: string): Promise<string> {
    const j = (await this.getItem(dfid)) as {
      item?: { id?: string };
      id?: string;
    };
    const uuid = j.item?.id ?? j.id;
    if (!uuid) {
      throw new ApiError(0, "no_item_uuid", `could not resolve internal item id for ${dfid}`);
    }
    return uuid;
  }

  // ── declared but blocked on backend (marked, not faked) ─────────────────────

  /** Grant an existing participant access to an already-sealed field (re-wrap). */
  grant(): never {
    throw new NotImplementedError("grant (re-wrap for a participant)", "engines#584");
  }

  /** Grant read access through a link (capability token). */
  grantLink(): never {
    throw new NotImplementedError("grantLink (capability token)", "engines#574");
  }

  /** Revoke a grant (forward-only: cuts future access, never un-reads the past). */
  revoke(): never {
    throw new NotImplementedError("revoke", "engines#574/#584");
  }
}

/**
 * Re-run the sealer-signature verification LOCALLY, against the public key the server returned
 * (`sealer_public_key_b64` — name pinned to the Rust struct). This is the point of the whole
 * architecture: the integrator does not have to trust the server's `authorship_verified` boolean.
 * Returns `null` only when the server sent no key (none was valid at event time) — never
 * silently. Exported so the contract is testable without HTTP (`test/api-shape.test.ts`).
 */
export function localAuthorshipCheck(field: RecipientSealedField): boolean | null {
  if (!field.sealer_public_key_b64) return null;
  return verifySealerSignature(field.sealed_field, field.sealer_public_key_b64);
}

/** File keystore that resolves its default path on first use (keeps the constructor sync). */
class LazyFileKeystore implements Keystore {
  private inner: Keystore | null = null;

  private async resolve(): Promise<Keystore> {
    if (!this.inner) {
      this.inner = new FileKeystore(await FileKeystore.defaultPath());
    }
    return this.inner;
  }

  async get(kind: Parameters<Keystore["get"]>[0]) {
    return (await this.resolve()).get(kind);
  }

  async put(kind: Parameters<Keystore["put"]>[0], key: Parameters<Keystore["put"]>[1]) {
    return (await this.resolve()).put(kind, key);
  }
}

/**
 * Fail at the door with the field's NAME when a required string is missing (issue #3): an
 * untyped caller (plain JS, MCP agent) must get "seal() requires dfid", never a downstream 404
 * that prints the literal string "undefined".
 */
function requireString(obj: object, field: string): void {
  const v = (obj as Record<string, unknown> | null | undefined)?.[field];
  if (typeof v !== "string" || v.length === 0) {
    throw new InvalidInputError(field, `expected "${field}" to be a non-empty string`);
  }
}

function randomSuffix(): string {
  return toHex(crypto.getRandomValues(new Uint8Array(4)));
}

/** Walk a response for DFID strings (the ingestion response nests them per item). */
function collectDfids(obj: unknown, out: string[] = []): string[] {
  if (Array.isArray(obj)) {
    for (const v of obj) collectDfids(v, out);
  } else if (obj && typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      if (k.toLowerCase() === "dfid" && typeof v === "string" && v.startsWith("DFID")) {
        if (!out.includes(v)) out.push(v);
      } else {
        collectDfids(v, out);
      }
    }
  }
  return out;
}

export { MemoryKeystore, FileKeystore };
export type { Keystore };
