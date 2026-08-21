/**
 * [Folder 1 · passos S1–S3 da collection] Identidade e chaves.
 *
 * Cada ator gera SUAS chaves localmente (a privada nunca sai daqui) e registra só as públicas:
 * Ed25519 (assinatura/autoria) e X25519 (cifra), a de cifra com o binding assinado. A DeFarm é
 * DIRETÓRIO de chaves, não autoridade — hospeda a lista pública, não custodia segredo.
 *
 * Rode uma vez por ambiente. Idempotente: rodar de novo confirma em vez de duplicar (e se o
 * key_id existir no servidor com OUTRA pública, falha alto com KeyMismatchError — nunca segue).
 */
import { env, producerClient, recipientClient, step, show } from "./lib/setup.js";

const producer = producerClient();
const recipient = recipientClient();

step(1, "Produtor: login + gerar/registrar chaves (Ed25519 + X25519 com binding)");
await producer.login(env("DEFARM_PRODUCER_EMAIL"), env("DEFARM_PRODUCER_PASSWORD"));
const p = await producer.ensureKeys();
show("workspace", p.workspaceId);
show("signing key", p.signingKeyId);
show("encryption key", `${p.encKeyId} (${p.encKeyFingerprint})`);
console.log("    → as PRIVADAS ficaram em .defarm-example/producer-keys.json (0600), nunca no servidor");

step(2, "Destinatário (ex.: frigorífico): o mesmo, no keystore DELE");
await recipient.login(env("DEFARM_RECIPIENT_EMAIL"), env("DEFARM_RECIPIENT_PASSWORD"));
const r = await recipient.ensureKeys();
show("workspace", r.workspaceId);
show("encryption key", `${r.encKeyId} (${r.encKeyFingerprint})`);

step(3, "Destinatário exporta o BUNDLE público pra quem vai selar pra ele");
const bundle = await recipient.exportRecipient();
show("bundle (só material público)", bundle);
console.log(
  "    → é isto que o destinatário manda ao produtor por fora (email, portal). O seal()\n" +
    "      RE-VERIFICA a assinatura do binding antes de usar — se alguém trocar a chave no\n" +
    "      caminho, a selagem recusa. Guarde este bundle pra usar no 03-seal.",
);
console.log("\n✔ chaves prontas nos dois lados");
