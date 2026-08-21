/**
 * [Folders 5 e 7 da collection] VERIFIQUE VOCÊ MESMO — o roteiro do auditor.
 *
 * Qualquer um — sem conta, sem permissão, sem confiar na DeFarm — verifica um DFID: âncora em
 * rede pública, carimbo de tempo RFC3161 re-verificável, e o campo selado aparecendo como
 * COMMITMENT (prova de que existe e não mudou, sem revelar o valor).
 *
 * Este exemplo usa o agregador (`/verify`). Pra verificação 100% independente (Horizon direto,
 * IPFS em ≥2 gateways, hash de cada evento recalculado do zero), rode o verificador open-source
 * na SUA máquina: github.com/defarm-repo/defarm-verify — esse é o argumento final pro auditor.
 */
import { env, step, show, GATEWAY } from "./lib/setup.js";
import { DefarmClient } from "../src/index.js";

const anon = new DefarmClient({ gateway: GATEWAY }); // repare: NENHUMA credencial

step(1, "GET /verify/{dfid} — público, sem auth");
const report = await anon.verify(env("DEFARM_DFID"));
show("carimbos RFC3161 presentes", report.hasTrustedTimestamps);
show("commitments de campos selados", report.sealedCommitments);

step(2, "O checklist do auditor sobre este relatório");
console.log(
  "    · a âncora on-chain confere no Horizon público (fora da DeFarm)\n" +
    "    · o carimbo RFC3161 re-verifica com openssl ts (a autoridade é externa)\n" +
    "    · o commitment do selado NÃO permite brute-force do valor (HMAC com chave\n" +
    "      derivada da DK — sem a DK, não há o que tentar)\n" +
    "    · nada aqui exigiu conta, permissão, ou confiança na DeFarm",
);
console.log("\n✔ é a resposta à pergunta 'e se a DeFarm mentir?': verifique você mesmo.");
