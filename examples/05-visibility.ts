/**
 * [Folder 2 da collection] VISIBILIDADE — o mesmo animal lido de três ângulos.
 *
 * O ensino central da DeFarm é *quem vê o quê*. Dois eixos ORTOGONAIS:
 *   membership gate o ITEM (quem lê os campos claros) · selo gate o CAMPO (quem decifra).
 * "Selo = chave, membership = item."
 *
 * Este exemplo lê o MESMO DFID como: (A) anônimo — esqueleto público, identificador pessoal
 * mascarado/commitment; (B) logado — membership decide (não-membro leva 404 UNIFORME, sem
 * oráculo de existência: quem não pode ver não descobre nem que existe); e resolve por
 * identificador de domínio (SISBOV) pra mostrar que trocar o identificador não muda a regra.
 */
import { env, producerClient, step, show, GATEWAY } from "./lib/setup.js";
import { DefarmClient } from "../src/index.js";

const dfid = env("DEFARM_DFID");

step(1, "ANÔNIMO: GET /items/{dfid}/public — o esqueleto, sem login nenhum");
const anon = new DefarmClient({ gateway: GATEWAY });
const pub = await anon.getItemPublic(dfid);
show("resposta pública", pub);
console.log("    → repare: commitments/mascarado onde o dado é sensível; NUNCA o cru de identificador pessoal");

step(2, "LOGADO E COM ACESSO: o produtor lê o cru");
const producer = producerClient();
await producer.login(env("DEFARM_PRODUCER_EMAIL"), env("DEFARM_PRODUCER_PASSWORD"));
const full = await producer.getItem(dfid);
show("resposta autenticada", full);

step(3, "Resolver por SISBOV (identificador de domínio) — a máscara é consistente por qualquer porta");
const sisbov = process.env.DEFARM_SISBOV;
if (sisbov) {
  const bySisbov = await producer.resolveByIdentifier("SISBOV", sisbov);
  show("resolve por identificador", bySisbov);
} else {
  console.log("    (pulado — exporte DEFARM_SISBOV com o SISBOV do animal do 02-ingest pra rodar)");
}

console.log(
  "\n✔ a regra que este exemplo demonstra: login sozinho não fura membership (um usuário\n" +
    "  logado NÃO-membro leva o mesmo 404 uniforme do anônimo pra item privado), e o campo\n" +
    "  SELADO não abre pra ninguém aqui — nem pro membro — só pro endereçado (04-open).",
);
