/**
 * [Folder 1 · passo S8 da collection] SELAR um campo — o coração do modelo.
 *
 * O produtor cifra o preço DO LADO DELE, endereçado ao frigorífico. O que chega à DeFarm é o
 * envelope: ciphertext + um "cadeado" (wrap) por destinatário + um commitment que esconde o
 * valor. A DeFarm guarda e NÃO consegue ler — não tem chave privada nenhuma. 1 cofre, N
 * cadeados: selar pra 5 não copia o dado 5 vezes.
 *
 * Defaults seguros em ação: sua própria chave entra sempre (você não perde acesso ao seu dado);
 * visibility é "private" por default (aqui usamos "public" pra que o ENVELOPE — nunca o valor —
 * apareça no /verify do exemplo 06).
 *
 * Pré-requisitos: 01 (chaves) e 02 (DFID exportado). O campo precisa estar declarado selável
 * pela DeFarm (field_protection, ação de admin — engines#582); se não estiver, o erro é
 * NotSealableFieldError, não um 500 misterioso.
 */
import { env, producerClient, recipientClient, step, show } from "./lib/setup.js";

const producer = producerClient();
const recipient = recipientClient();

step(1, "Destinatário exporta o bundle público (na prática isto viaja por fora, uma vez)");
await recipient.login(env("DEFARM_RECIPIENT_EMAIL"), env("DEFARM_RECIPIENT_PASSWORD"));
const bundle = await recipient.exportRecipient();
show("destinatário", `${bundle.workspaceId} / ${bundle.encKeyId}`);

step(2, "Produtor sela preco_venda PRA ELE (o binding do bundle é re-verificado aqui)");
await producer.login(env("DEFARM_PRODUCER_EMAIL"), env("DEFARM_PRODUCER_PASSWORD"));
const sealed = await producer.seal({
  dfid: env("DEFARM_DFID"),
  fieldPath: "preco_venda",
  value: "R$ 8.500,00",
  circuitId: env("DEFARM_CIRCUIT_ID"),
  to: [bundle],
  visibility: "public", // o envelope (commitment) fica visível no /verify; o VALOR jamais
});
show("commitment (o que o mundo vê)", sealed.commitment);
show("cadeados (wraps)", sealed.recipients); // 2 = destinatário + o próprio produtor
console.log(
  "\n✔ selado. O valor saiu daqui já cifrado; a DeFarm recebeu um envelope que não abre.\n" +
    "  Prove: o 06-verify mostra só o commitment; o 04-open mostra o destinatário lendo.",
);
