/**
 * [Folder 2 da collection] VISIBILIDADE — o mesmo animal lido de três ângulos.
 *
 * O ensino central da DeFarm é *quem vê o quê*. Dois eixos ORTOGONAIS:
 *   membership gate o ITEM (quem lê os campos claros) · selo gate o CAMPO (quem decifra).
 * "Selo = chave, membership = item."
 *
 * A regra que este exemplo demonstra: quem não pode ver leva **404 UNIFORME** — não 403, não
 * "existe mas está mascarado". Quem não pode ver não descobre nem que existe. Por isso um 404
 * aqui não é tratado como crash: é interpretado e explicado — ele É a lição.
 *
 * Pré-requisito pra ver as leituras públicas com 200: o item precisa estar num circuito
 * PÚBLICO (ver "Pré-requisitos" no README). Num circuito privado, as leituras anônimas dão o
 * 404 uniforme — e o exemplo diz isso em vez de morrer.
 */
import { env, producerClient, step, show, GATEWAY } from "./lib/setup.js";
import { ApiError, DefarmClient } from "../src/index.js";

const dfid = env("DEFARM_DFID");

/** Roda uma leitura e interpreta o 404 uniforme como o resultado didático que ele é. */
async function read(label: string, fn: () => Promise<unknown>, on404: string): Promise<void> {
  try {
    show(label, await fn());
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) {
      console.log(`    ${label}: 404 UNIFORME — ${on404}`);
    } else {
      throw e;
    }
  }
}

step(1, "ANÔNIMO: GET /items/{dfid}/public — o esqueleto, sem login nenhum");
const anon = new DefarmClient({ gateway: GATEWAY });
await read(
  "resposta pública",
  () => anon.getItemPublic(dfid),
  "o item está em circuito PRIVADO, e quem não pode ver não descobre nem que existe. " +
    "Pra demonstrar a leitura pública (esqueleto + commitments), use um item de circuito público.",
);

step(2, "LOGADO E COM ACESSO: o produtor lê o cru");
const producer = producerClient();
await producer.login(env("DEFARM_PRODUCER_EMAIL"), env("DEFARM_PRODUCER_PASSWORD"));
await read(
  "resposta autenticada",
  () => producer.getItem(dfid),
  "este workspace NÃO é membro do circuito do item — login sozinho não fura membership. " +
    "Exatamente o esperado pra um não-membro; entre como membro pra ver o cru.",
);

step(3, "Resolver por SISBOV (identificador de domínio) — a máscara é consistente por qualquer porta");
const sisbov = process.env.DEFARM_SISBOV;
if (sisbov) {
  await read(
    "resolve por identificador",
    () => producer.resolveByIdentifier("SISBOV", sisbov),
    "mesma regra por qualquer identificador: não-membro/privado = 404 uniforme.",
  );
} else {
  console.log("    (pulado — exporte DEFARM_SISBOV com o SISBOV do animal do 02-ingest pra rodar)");
}

console.log(
  "\n✔ o que este exemplo prova: login sozinho não fura membership, o 404 é uniforme (sem\n" +
    "  oráculo de existência), e o campo SELADO não abre pra ninguém aqui — nem pro membro —\n" +
    "  só pro endereçado (04-open).",
);
