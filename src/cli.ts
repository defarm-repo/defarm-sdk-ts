#!/usr/bin/env node
/**
 * `defarm` — the try-it CLI over the SDK (engines#590): experiment from the terminal without
 * writing code. Thin by design: every command is one SDK call plus JSON on stdout.
 *
 * Same security posture as the MCP server: credentials come from the ENVIRONMENT only
 * (DEFARM_EMAIL/DEFARM_PASSWORD, DEFARM_API_KEY) — never from argv, where they would leak into
 * shell history and process listings. Private keys live in the local keystore
 * (DEFARM_KEYSTORE, default ~/.defarm/keys.json) and no command prints them.
 *
 * Output contract: RESULT as JSON on stdout (pipe-friendly); hints and errors on stderr;
 * exit 0 only on success. Zero dependencies beyond the SDK itself (node:util parseArgs).
 */
import { parseArgs } from "node:util";
import { readFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { DefarmClient, FileKeystore } from "./index.js";
import { DefarmError } from "./errors.js";

const USAGE = `defarm — DeFarm from the terminal (SDK ${"0.2.x"})

Environment:
  DEFARM_GATEWAY    (required) gateway base URL — ask DeFarm for your test host
  DEFARM_EMAIL      workspace login   } enable authenticated commands
  DEFARM_PASSWORD                     }
  DEFARM_API_KEY    partner key — enables 'ingest'
  DEFARM_KEYSTORE   private-key file (default ~/.defarm/keys.json)

Commands:
  whoami                                   user + workspace of the configured credentials
  keys ensure                              generate (locally) + register key pairs
  keys export                              print this workspace's public recipient bundle
  ingest --file <items.json> [--preview]   partner ingestion (array of items; preview = dry run)
  seal --dfid D --field F --value V --circuit C
       [--to <bundle.json>] [--visibility private|public] [--no-self]
  open --dfid D --field F                  decrypt a sealed field addressed to you, locally
  verify --dfid D                          public verification (no credentials needed)
  item --dfid D [--public]                 membership-gated (or public) item read
  resolve --type SISBOV --value V [--circuit C]

Examples:
  defarm keys export > my-bundle.json      # send this to whoever seals for you
  defarm seal --dfid DFID-… --field preco_venda --value "R$ 8.500,00" \\
      --circuit c1 --to their-bundle.json
  defarm open --dfid DFID-… --field preco_venda
`;

function fail(message: string, code = 1): never {
  console.error(`✖ ${message}`);
  process.exit(code);
}

function out(value: unknown): void {
  console.log(JSON.stringify(value, null, 2));
}

function requireOpt(opts: Record<string, unknown>, name: string): string {
  const v = opts[name];
  if (typeof v !== "string" || v.length === 0) fail(`missing --${name} (see 'defarm help')`);
  return v;
}

const BUNDLE_FIELDS = [
  "workspaceId",
  "encKeyId",
  "encPubkeyB64",
  "signingPubkeyB64",
  "bindingSigB64",
] as const;

/** Parse a recipient-bundle file, failing with the FILE as the culprit when it is malformed. */
function readBundle(path: string): import("./client.js").SealRecipientInput {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    fail(`${path} is not readable JSON (${e instanceof Error ? e.message : e})`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    fail(`${path} must hold ONE recipient bundle object (from 'defarm keys export')`);
  }
  const bundle = parsed as Record<string, unknown>;
  const missing = BUNDLE_FIELDS.filter((f) => typeof bundle[f] !== "string" || !bundle[f]);
  if (missing.length > 0) {
    fail(
      `${path} is not a recipient bundle — missing field(s): ${missing.join(", ")}. ` +
        `Expected the JSON printed by 'defarm keys export' on the RECIPIENT's side.`,
    );
  }
  return bundle as unknown as import("./client.js").SealRecipientInput;
}

function client(): DefarmClient {
  const gateway = process.env.DEFARM_GATEWAY;
  if (!gateway) {
    fail(
      "DEFARM_GATEWAY is not set — export it first. Ask the DeFarm team for your " +
        "test-environment host; production is an explicit decision.",
    );
  }
  return new DefarmClient({
    gateway,
    ...(process.env.DEFARM_API_KEY ? { auth: { apiKey: process.env.DEFARM_API_KEY } } : {}),
    ...(process.env.DEFARM_KEYSTORE
      ? { keystore: new FileKeystore(process.env.DEFARM_KEYSTORE) }
      : {}),
  });
}

async function loggedIn(): Promise<DefarmClient> {
  const email = process.env.DEFARM_EMAIL;
  const password = process.env.DEFARM_PASSWORD;
  if (!email || !password) {
    fail("this command needs DEFARM_EMAIL and DEFARM_PASSWORD in the environment");
  }
  const c = client();
  await c.login(email, password);
  return c;
}

export async function main(argv: string[]): Promise<void> {
  const [command, sub, ...rest] = argv;
  if (!command || command === "help") {
    console.error(USAGE);
    process.exit(command ? 0 : 1);
  }
  const flagArgs = command === "keys" ? rest : [sub, ...rest].filter((a): a is string => a !== undefined);

  const { values: opts } = parseArgs({
    args: flagArgs,
    options: {
      file: { type: "string" },
      preview: { type: "boolean" },
      dfid: { type: "string" },
      field: { type: "string" },
      value: { type: "string" },
      circuit: { type: "string" },
      to: { type: "string" },
      visibility: { type: "string" },
      "no-self": { type: "boolean" },
      public: { type: "boolean" },
      type: { type: "string" },
    },
    strict: true,
  });

  switch (`${command}${command === "keys" ? ` ${sub ?? ""}` : ""}`) {
    case "whoami": {
      out(await (await loggedIn()).me());
      break;
    }
    case "keys ensure": {
      const id = await (await loggedIn()).ensureKeys();
      out(id);
      console.error("✔ chaves prontas — as privadas ficaram no keystore local, nunca no servidor");
      break;
    }
    case "keys export": {
      out(await (await loggedIn()).exportRecipient());
      console.error(
        "✔ bundle público — mande pra quem vai selar pra você (o SDK deles re-verifica o binding)",
      );
      break;
    }
    case "ingest": {
      const file = requireOpt(opts, "file");
      const items = JSON.parse(readFileSync(file, "utf8"));
      if (!Array.isArray(items)) fail(`${file} must hold a JSON ARRAY of items`);
      const c = client();
      const result = await c.ingest(items, opts.preview ? { preview: true } : {});
      out(result);
      if (!opts.preview && result.dfids.length === 0) {
        fail("ingestion returned no DFID — inspect the response above");
      }
      break;
    }
    case "seal": {
      // Validate the bundle AT THE DOOR, before any network (review finding on #22): a
      // malformed file must say "malformed file", never surface later as
      // RecipientBindingError — which, in a product whose whole story is anti-MITM, reads as
      // "someone swapped the key" when it was "you pointed at the wrong file". Same pattern
      // as `ingest --file`.
      const to = opts.to ? [readBundle(opts.to as string)] : undefined;
      const c = await loggedIn();
      const visibility = opts.visibility as "private" | "public" | undefined;
      if (visibility && visibility !== "private" && visibility !== "public") {
        fail("--visibility must be 'private' or 'public'");
      }
      const result = await c.seal({
        dfid: requireOpt(opts, "dfid"),
        fieldPath: requireOpt(opts, "field"),
        value: requireOpt(opts, "value"),
        circuitId: requireOpt(opts, "circuit"),
        ...(to ? { to } : {}),
        ...(opts["no-self"] ? { includeSelf: false } : {}),
        ...(visibility ? { visibility } : {}),
      });
      out({
        dfid: result.dfid,
        fieldPath: result.fieldPath,
        commitment: result.commitment,
        recipients: result.recipients,
        clientEventId: result.clientEventId,
      });
      console.error("✔ selado client-side — a DeFarm recebeu um envelope que não abre");
      break;
    }
    case "open": {
      const result = await (await loggedIn()).open({
        dfid: requireOpt(opts, "dfid"),
        fieldPath: requireOpt(opts, "field"),
      });
      out({
        value: result.value,
        sealer: result.sealer,
        authorshipVerified: result.authorshipVerified,
        sealerSignatureVerifiedLocally: result.sealerSignatureVerifiedLocally,
      });
      break;
    }
    case "verify": {
      out(await client().verify(requireOpt(opts, "dfid")));
      break;
    }
    case "item": {
      const c = opts.public ? client() : await loggedIn();
      const dfid = requireOpt(opts, "dfid");
      out(opts.public ? await c.getItemPublic(dfid) : await c.getItem(dfid));
      break;
    }
    case "resolve": {
      out(
        await (await loggedIn()).resolveByIdentifier(
          requireOpt(opts, "type"),
          requireOpt(opts, "value"),
          opts.circuit as string | undefined,
        ),
      );
      break;
    }
    default:
      fail(`unknown command "${command}" — run 'defarm help'`);
  }
}

/**
 * Run when invoked as a binary, INCLUDING through the symlink npm installs into
 * `node_modules/.bin` (P0 of the 0.2.0 release review): Node resolves the symlink in
 * `import.meta.url` but keeps it in `argv[1]`, so a naive equality check is false through the
 * bin and `main()` silently never runs — published and inert. Realpath-ing argv[1] makes both
 * paths agree; the guard exists so importing this module (tests) doesn't execute main.
 */
function isDirectRun(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch {
    return false;
  }
}

if (isDirectRun()) {
  main(process.argv.slice(2)).catch((e: unknown) => {
    if (e instanceof DefarmError) fail(`${e.name}: ${e.message}`);
    fail(e instanceof Error ? e.message : String(e));
  });
}
