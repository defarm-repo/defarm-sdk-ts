/**
 * [Folder 1 · passos S9/V12 da collection] O destinatário ABRE — localmente.
 *
 * O frigorífico busca o envelope endereçado a ele, desembrulha a chave de dados com a privada
 * DELE (que nunca saiu da máquina dele) e decifra. Três verificações vêm de graça: o AAD
 * (anti-frankenstein: o envelope só abre no contexto exato em que foi selado), o commitment
 * (o valor é exatamente o que foi ancorado) e a assinatura do selador — re-verificada AQUI,
 * localmente, contra a pública que o servidor devolve. Você não precisa confiar no boolean
 * do servidor: o SDK re-roda a conta.
 */
import { env, recipientClient, step, show } from "./lib/setup.js";

const recipient = recipientClient();

step(1, "Login do destinatário e abertura local");
await recipient.login(env("DEFARM_RECIPIENT_EMAIL"), env("DEFARM_RECIPIENT_PASSWORD"));
const opened = await recipient.open({
  dfid: env("DEFARM_DFID"),
  fieldPath: "preco_venda",
});
show("valor decifrado (só o destinatário vê isto)", opened.value);
show("quem selou", `${opened.sealer.workspaceId} / ${opened.sealer.keyId}`);
show("autoria verificada pelo servidor", opened.authorshipVerified);
show("autoria RE-verificada localmente", opened.sealerSignatureVerifiedLocally);
console.log(
  "\n✔ o valor existiu em claro apenas em duas máquinas: a do produtor (antes de selar)\n" +
    "  e esta (depois de abrir). A DeFarm, no meio, transportou um envelope fechado.",
);
