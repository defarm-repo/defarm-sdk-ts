# Examples — o passo a passo rodável

Cada script é a versão executável de um folder da collection Postman de onboarding: 1 script =
1 caso de uso, enumerado, com o que esperar impresso no terminal. Rode em ordem na primeira vez.

```bash
npm install
cp examples/.env.example examples/.env   # preencha com SEUS usuários de teste
set -a; source examples/.env; set +a

npm run example:01   # chaves dos dois lados + o bundle do destinatário
npm run example:02   # ingestão (preview + real) → exporte DEFARM_DFID
npm run example:03   # SELAR preco_venda pro destinatário (DeFarm fica cega)
npm run example:04   # o destinatário ABRE, localmente
npm run example:05   # visibilidade: anônimo × autenticado × por identificador
npm run example:06   # verifique-você-mesmo (sem conta, sem confiança)
```

| Script | Folder da collection | O que prova |
|---|---|---|
| `01-setup-keys` | 🔒 1 (S1–S3) | privada nasce e fica no cliente; DeFarm = diretório, não autoridade |
| `02-ingest` | 📥 4 (I2/I3) | X-API-Key, preview dry-run, DFID |
| `03-seal` | 🔒 1 (S8) | cifra client-side, 1 cofre + N cadeados, binding re-verificado |
| `04-open` | 🔒 1 (S9/V12) | só o endereçado decifra; autoria re-verificada LOCALMENTE |
| `05-visibility` | 🔄 2 | membership gate o item, selo gate o campo; 404 uniforme |
| `06-verify` | ✅ 5 + 🔍 7 | âncora + RFC3161 + commitment, sem confiar na DeFarm |

## Pré-requisitos do ambiente (sem eles, os passos falham — e agora dizem o porquê)

Verificados rodando a suíte inteira contra um ambiente real (review do PR #15):

1. **02-ingest**: a API key precisa de um circuito de **staging de parceiro**
   (`partner_staging=true`) — a rota oficial de ingestão recusa key criada pela rota comum.
2. **03-seal**: o destinatário precisa ser **participante do circuito** antes de receber selo
   (convite → aceite; o resolver de participantes exige membro ativo ou key ativa no circuito).
3. **05/06**: as leituras ANÔNIMAS (`/public`, `/verify`) só retornam 200 pra item em circuito
   **PÚBLICO**. Em circuito privado o retorno é o 404 uniforme — que é a regra funcionando, e o
   05 explica isso em vez de morrer.

## ⛔ O que ainda não tem exemplo (bloqueado em backend — não fingimos)

- **Conceder a um participante depois de selado** (re-wrap) — engines#584 → `grant()` lança
  `NotImplementedError`.
- **Liberar por link** (capability token) — engines#574 → `grantLink()`.
- **Resolver destinatários do circuito pela API** — o passo [S6] da collection está quebrado
  atrás do gateway; por isso o 01/03 usam o `exportRecipient()` (bundle fora de banda, com o
  binding re-verificado na selagem — garantia criptográfica idêntica).
- **Prova de presença / consolidação de lote** (folder 📡 3) — exige admin + item LOTE.

## Regras destes exemplos

- **Zero credencial embutida** — tudo vem do seu `.env` (nunca commite o `.env`).
- **Ambiente de teste primeiro** — aponte `DEFARM_GATEWAY` pra staging; produção é decisão
  explícita sua.
- Atores genéricos (Produtor / Frigorífico) — substitua pelo seu domínio.
- Os keystores dos dois atores ficam em `.defarm-example/` (arquivos distintos — na vida real
  são máquinas distintas).
