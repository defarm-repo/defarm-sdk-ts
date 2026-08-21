/**
 * [Folder 4 · passos I2/I3 da collection] Ingestão de parceiro.
 *
 * Só X-API-Key — um Bearer aqui é erro de configuração e o SDK falha antes de tocar a rede.
 * O animal cai no circuito amarrado à chave. `preview: true` é dry-run: valida tudo, não grava
 * nada, não ancora nada — use antes de comprometer dados de verdade.
 *
 * Pré-requisito de ambiente: a API key precisa ter um circuito de staging de parceiro
 * (`partner_staging`) — ver "Pré-requisitos" no README.
 */
import { partnerClient, step, show } from "./lib/setup.js";

const partner = partnerClient();

const animal = {
  value_chain: "DEFARM",
  country: "BR",
  year: 2026,
  // SISBOV real tem 14–15 dígitos ("105" + 12 aleatórios = 15). Menos que isso o servidor rejeita.
  sisbov: `105${String(Math.floor(Math.random() * 1e12)).padStart(12, "0")}`,
  breed: "Nelore",
  sex: "male",
  weight_kg: 512,
  category: "Boi gordo",
};

/** O preview reporta erros DENTRO de um 200 — quem ignora o corpo transforma dry-run em enfeite. */
function collectErrors(obj: unknown, out: unknown[] = []): unknown[] {
  if (Array.isArray(obj)) for (const v of obj) collectErrors(v, out);
  else if (obj && typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      if (/^errors?$/i.test(k) && Array.isArray(v) && v.length > 0) out.push(...v);
      else collectErrors(v, out);
    }
  }
  return out;
}

step(1, "PREVIEW (dry-run): valida sem gravar");
const preview = await partner.ingest([animal], { preview: true });
show("resposta do preview", preview.response);
const previewErrors = collectErrors(preview.response);
if (previewErrors.length > 0) {
  console.error("\n✖ o preview reportou erros — corrija o payload ANTES da ingestão real:");
  for (const e of previewErrors) console.error("   ", JSON.stringify(e));
  process.exit(1);
}
console.log("    → nada foi gravado; é o teste de fogo do payload");

step(2, "Ingestão real: o animal ganha um DFID");
const real = await partner.ingest([animal]);
const dfid = real.dfids[0];
if (!dfid) {
  // NUNCA imprimir sucesso sobre falha: sem DFID não há o que exportar, e um
  // "export DEFARM_DFID=undefined" envenenaria os exemplos 03→06 em cascata.
  console.error("\n✖ a ingestão não devolveu DFID — resposta completa pra diagnóstico:");
  console.error(JSON.stringify(real.response, null, 2));
  process.exit(1);
}
show("dfid", dfid);
console.log(`\n✔ exporte pra usar nos próximos exemplos:\n  export DEFARM_DFID=${dfid}`);
console.log(`  (e opcional, pro 05:)\n  export DEFARM_SISBOV=${animal.sisbov}`);
