/**
 * [Folder 4 · passos I2/I3 da collection] Ingestão de parceiro.
 *
 * Só X-API-Key — um Bearer aqui é erro de configuração e o SDK falha antes de tocar a rede.
 * O animal cai no circuito amarrado à chave. `preview: true` é dry-run: valida tudo, não grava
 * nada, não ancora nada — use antes de comprometer dados de verdade.
 */
import { partnerClient, step, show } from "./lib/setup.js";

const partner = partnerClient();

const animal = {
  value_chain: "DEFARM",
  country: "BR",
  year: 2026,
  sisbov: `105${String(Math.floor(Math.random() * 1e9)).padStart(9, "0")}`,
  breed: "Nelore",
  sex: "male",
  weight_kg: 512,
  category: "Boi gordo",
};

step(1, "PREVIEW (dry-run): valida sem gravar");
const preview = await partner.ingest([animal], { preview: true });
show("resposta do preview", preview.response);
console.log("    → nada foi gravado; é o teste de fogo do payload");

step(2, "Ingestão real: o animal ganha um DFID");
const real = await partner.ingest([animal]);
show("dfid", real.dfids[0]);
console.log(
  `\n✔ exporte pra usar nos próximos exemplos:\n  export DEFARM_DFID=${real.dfids[0]}`,
);
