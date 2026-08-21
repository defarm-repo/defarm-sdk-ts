/**
 * Shared setup for the runnable examples. Reads everything from environment variables
 * (see ../.env.example) — the examples ship with ZERO credentials, you bring your own
 * test-environment users. Never point them at production accounts you care about.
 *
 * In your own project, import from "@defarm/sdk" — here we import the local source directly
 * so the examples run from a fresh clone with `npm run example:...`.
 */
import { DefarmClient, FileKeystore } from "../../src/index.js";

export function env(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (!v) {
    console.error(`✖ missing env var ${name} — copy examples/.env.example and fill it in`);
    process.exit(1);
  }
  return v;
}

/**
 * No fallback ON PURPOSE: a default gateway would be the only var silently skipping the
 * "missing env var" guard — and a wrong default published in a public repo is worse than none.
 * Ask DeFarm for your test-environment host; production is an explicit decision.
 */
export const GATEWAY = env("DEFARM_GATEWAY");

/**
 * Each actor gets its OWN keystore file — the whole model is that the producer's private keys
 * and the recipient's private keys live on different machines. Two files under .defarm-example/
 * simulate that separation in one process; in real life these are two different systems.
 */
export function producerClient(): DefarmClient {
  return new DefarmClient({
    gateway: GATEWAY,
    keystore: new FileKeystore(".defarm-example/producer-keys.json"),
  });
}

export function recipientClient(): DefarmClient {
  return new DefarmClient({
    gateway: GATEWAY,
    keystore: new FileKeystore(".defarm-example/recipient-keys.json"),
  });
}

export function partnerClient(): DefarmClient {
  return new DefarmClient({
    gateway: GATEWAY,
    auth: { apiKey: env("DEFARM_PARTNER_API_KEY") },
  });
}

export function step(n: number, text: string): void {
  console.log(`\n[${n}] ${text}`);
}

export function show(label: string, value: unknown): void {
  console.log(`    ${label}:`, typeof value === "string" ? value : JSON.stringify(value));
}
