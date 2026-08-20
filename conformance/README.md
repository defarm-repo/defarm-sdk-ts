# Gerador de vetores (engines#591)

`ts_conformance_vector_gen.rs` **pertence ao repo engines** (`item-registry/tests/`) — o Rust é
o oráculo do formato, então o gerador vive e evolui junto com `sealed_field.rs`. PR canônico:
**engines#606**. A cópia aqui é referência/espelho para quem audita o SDK sem acesso ao engines;
em divergência, o engines manda.

Como regenerar `../test/vectors/rust-oracle.json` — ver `../test/vectors/README.md` (inclui o
passo opcional do vetor cross-key, com o par X25519 gerado por este SDK).

As chaves privadas dentro dos vetores são FIXTURES (seeds determinísticas ou pares descartáveis
gerados só pro vetor) — jamais chaves reais.
