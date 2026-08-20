# Gerador de vetores (rascunho do engines#591)

`ts_conformance_vector_gen.rs` é o RASCUNHO do gerador de vetores de conformidade — ele **pertence
ao repo engines** (`item-registry/tests/`), não a este: o Rust é o oráculo do formato, então o
gerador tem de viver e evoluir junto com `sealed_field.rs`. A cópia aqui é referência/documentação
até o PR do engines#591 ser aberto e mergeado.

Como o vetor `../test/vectors/rust-oracle-draft.json` foi gerado (2026-08-20, engines @ da23e845):

```bash
# num worktree do engines com este arquivo em item-registry/tests/
VECTOR_OUT=/tmp/vectors.json SQLX_OFFLINE=true \
  cargo test -p item-registry --test ts_conformance_vector_gen -- --nocapture
```

As chaves privadas dentro do vetor são FIXTURES derivadas de seeds constantes (`[7u8;32]`,
`[9u8;32]`, `[11u8;32]`) — descartáveis por construção, jamais chaves reais.
