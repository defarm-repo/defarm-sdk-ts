// ============================================================================
// CÓPIA DE LEITURA — NÃO EDITAR AQUI (sugestão da review no engines#607).
// Fonte canônica: defarm-repo/engines →
//   services/layer-2-registry/item-registry/tests/ts_conformance_vector_gen.rs
//   (a única que compila contra o item_registry). Em divergência, o engines manda.
// Esta cópia existe pra quem audita o SDK sem clonar o engines.
// ============================================================================

//! Gerador de vetores de conformidade cross-linguagem do envelope selado (engines#591).
//!
//! O Rust é o ORÁCULO do formato: este teste sela+assina com chaves de teste FIXAS (fixtures
//! descartáveis — as privadas vão DENTRO do vetor de propósito, pra outra implementação abrir)
//! e escreve um `vectors.json` que os SDKs (TS hoje, Python depois) fazem replay byte-a-byte.
//! Nenhuma linguagem vai a produção sem esta suíte verde do lado dela.
//!
//! Lições encodadas (reviews Hetzner no defarm-sdk-ts#1/#7/#10):
//! - **Nome de campo não se batiza à mão** (o bloqueante do sdk-ts#1 nasceu de um nome inventado
//!   que gerador e consumidor concordavam entre si — cegueira simétrica, a classe do #602). A
//!   seção `api_response` daqui sai do **serializer real** (`serde_json` sobre
//!   `RecipientSealedField`), então o SDK pina os nomes no que o servidor de fato manda.
//! - **Ordem de wraps**: um vetor sela pra 3 destinatários passados FORA de ordem — a assinatura
//!   só fecha se o consumidor reproduzir a ordenação canônica por `(workspace, key_id)`.
//! - **Direção inversa (sdk-ts#5)**: com `TS_RECIPIENT_PUB`/`TS_RECIPIENT_PRIV` no ambiente, sai
//!   um vetor selado pra uma chave GERADA PELO SDK — pega divergência de geração/clamping X25519.
//!
//! Rodar:
//! ```bash
//! VECTOR_OUT=/tmp/vectors.json SQLX_OFFLINE=true \
//!   cargo test -p item-registry --test ts_conformance_vector_gen -- --nocapture
//! # opcional (direção SDK→Rust): exportar TS_RECIPIENT_PUB / TS_RECIPIENT_PRIV (base64) antes.
//! ```

use base64::Engine;
use ed25519_dalek::Signer;
use hpke::kem::X25519HkdfSha256;
use hpke::{Kem as KemTrait, Serializable};
use item_registry::api::sealed_field::{
    canonical_enc_key_binding, canonical_sealer_signing_string, open_field, seal_field,
    sign_sealed_field, verify_sealer_signature, Recipient, SealedField,
};
use item_registry::api::trust_encryption_keys::RecipientSealedField;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Par X25519 determinístico a partir de um ikm fixo (fixture, nunca chave real).
fn x25519_fixture(ikm: u8) -> (String, String) {
    let (sk, pk) = X25519HkdfSha256::derive_keypair(&[ikm; 32]);
    (b64(&sk.to_bytes()), b64(&pk.to_bytes()))
}

/// Par Ed25519 determinístico a partir de uma seed fixa (fixture, nunca chave real).
fn ed25519_fixture(seed_byte: u8) -> (ed25519_dalek::SigningKey, String, String) {
    let seed = [seed_byte; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pub_b64 = b64(sk.verifying_key().as_bytes());
    (sk, b64(&seed), pub_b64)
}

struct Sealed {
    sealed: SealedField,
    sealer_pub_b64: String,
}

/// Sela + assina com fixtures — o miolo comum dos vetores de envelope.
#[allow(clippy::too_many_arguments)]
fn seal_and_sign(
    dfid: &str,
    client_event_id: &str,
    field_path: &str,
    content_type: &str,
    plaintext: &[u8],
    recipients: &[Recipient],
    sealer_workspace: &str,
    sealer_seed_byte: u8,
) -> Sealed {
    let mut sealed = seal_field(
        dfid,
        client_event_id,
        field_path,
        content_type,
        plaintext,
        recipients,
    )
    .expect("seal");
    let (_, seed_b64, pub_b64) = ed25519_fixture(sealer_seed_byte);
    sign_sealed_field(&mut sealed, sealer_workspace, "sign-produtor", &seed_b64).expect("sign");
    Sealed {
        sealed,
        sealer_pub_b64: pub_b64,
    }
}

/// #607: o oráculo se auto-checa — cada envelope emitido tem de ABRIR com cada privada que vai
/// no vetor, batendo o plaintext. Sem isto, um refactor que quebre o round-trip escreveria um
/// vectors.json inabrível e a falha apareceria na CI do SDK como "o SDK está quebrado" —
/// diagnóstico invertido, no repo errado.
fn assert_opens(sealed: &SealedField, recipients: &[(&str, &str)], plaintext: &[u8]) {
    for (kid, priv_b64) in recipients {
        let opened = open_field(sealed, kid, priv_b64)
            .unwrap_or_else(|e| panic!("envelope emitido não abre pra {kid}: {e:?}"));
        assert_eq!(opened, plaintext, "plaintext divergiu ao abrir pra {kid}");
    }
}

fn envelope_json(
    s: &Sealed,
    recipients: &[(&str, &str)], // (enc_key_id, privkey_b64)
    plaintext: &[u8],
) -> serde_json::Value {
    assert_opens(&s.sealed, recipients, plaintext);
    serde_json::json!({
        "sealed_field": s.sealed,
        "recipients": recipients.iter().map(|(kid, priv_b64)| serde_json::json!({
            "enc_key_id": kid,
            "privkey_b64": priv_b64,
            "expected_plaintext_b64": b64(plaintext),
        })).collect::<Vec<_>>(),
        "sealer_signing_pubkey_b64": s.sealer_pub_b64,
        "expected_signing_string": canonical_sealer_signing_string(&s.sealed),
    })
}

#[test]
fn generate_ts_conformance_vectors() {
    let out_path = match std::env::var("VECTOR_OUT") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("VECTOR_OUT não setado — geração pulada");
            return;
        }
    };
    let mut vectors: Vec<serde_json::Value> = Vec::new();

    // ── 1. envelope básico: 1 destinatário + aad + binding ──────────────────────────────────────
    let (frigo_priv, frigo_pub) = x25519_fixture(7);
    let plaintext = b"R$ 8.500,00";
    let s1 = seal_and_sign(
        "DFID-DEFARM-BR-2026-000001-000001",
        "11111111-2222-3333-4444-555555555555",
        "preco_venda",
        "text/plain",
        plaintext,
        &[Recipient {
            workspace_id: "ws-frigo".to_string(),
            enc_key_id: "enc-frigo".to_string(),
            enc_pubkey_b64: frigo_pub.clone(),
        }],
        "ws-produtor",
        9,
    );
    let (binding_sk, _, binding_pub) = ed25519_fixture(11);
    let binding_canonical = canonical_enc_key_binding("ws-frigo", "enc-frigo", &frigo_pub);
    vectors.push(serde_json::json!({
        "name": "envelope-basico-1-destinatario",
        "aad": {
            "dfid": s1.sealed.dfid,
            "event_id": s1.sealed.event_id,
            "field_path": s1.sealed.field_path,
            "content_type": s1.sealed.content_type,
            "commitment": s1.sealed.commitment_sha256,
            "expected": s1.sealed.aad,
        },
        "binding": {
            "workspace_id": "ws-frigo",
            "enc_key_id": "enc-frigo",
            "enc_pubkey_b64": frigo_pub,
            "expected_canonical": binding_canonical,
            "sig_b64": b64(&binding_sk.sign(binding_canonical.as_bytes()).to_bytes()),
            "signing_pubkey_b64": binding_pub,
        },
        "envelope": envelope_json(&s1, &[("enc-frigo", &frigo_priv)], plaintext),
    }));

    // ── 2. três destinatários passados FORA de ordem (a assinatura exige ordenação canônica) ────
    let (pc, pubc) = x25519_fixture(23);
    let (pa, puba) = x25519_fixture(21);
    let (pb, pubb) = x25519_fixture(22);
    let recipients = vec![
        // ordem de entrada proposital: ws-c, ws-a, ws-b — o JCS não reordena arrays, então o
        // consumidor só verifica a assinatura se reproduzir o sort por (workspace, key_id).
        Recipient {
            workspace_id: "ws-c".to_string(),
            enc_key_id: "enc-c".to_string(),
            enc_pubkey_b64: pubc,
        },
        Recipient {
            workspace_id: "ws-a".to_string(),
            enc_key_id: "enc-a".to_string(),
            enc_pubkey_b64: puba,
        },
        Recipient {
            workspace_id: "ws-b".to_string(),
            enc_key_id: "enc-b".to_string(),
            enc_pubkey_b64: pubb,
        },
    ];
    let s2 = seal_and_sign(
        "DFID-DEFARM-BR-2026-000003-000003",
        "33333333-4444-5555-6666-777777777777",
        "laudo_sanitario",
        "text/plain",
        b"aftosa: negativo",
        &recipients,
        "ws-produtor",
        9,
    );
    vectors.push(serde_json::json!({
        "name": "envelope-3-destinatarios-fora-de-ordem",
        "envelope": envelope_json(
            &s2,
            &[("enc-c", &pc), ("enc-a", &pa), ("enc-b", &pb)],
            b"aftosa: negativo",
        ),
    }));

    // ── 3. conteúdo JSON com unicode (exercita utf8 + escapes do JCS ponta a ponta) ─────────────
    let json_plain = "{\"raça\":\"Nelore 🐂\",\"preço\":8500.5}".as_bytes();
    let s3 = seal_and_sign(
        "DFID-DEFARM-BR-2026-000004-000004",
        "44444444-5555-6666-7777-888888888888",
        "genética",
        "application/json",
        json_plain,
        &[Recipient {
            workspace_id: "ws-frigo".to_string(),
            enc_key_id: "enc-frigo".to_string(),
            enc_pubkey_b64: x25519_fixture(7).1,
        }],
        "ws-produtor",
        9,
    );
    vectors.push(serde_json::json!({
        "name": "conteudo-json-unicode",
        "envelope": envelope_json(&s3, &[("enc-frigo", &frigo_priv)], json_plain),
    }));

    // ── 4. api_response: a fixture sai do SERIALIZER real (nunca batizada à mão) ────────────────
    let authorship = verify_sealer_signature(&s1.sealed, &s1.sealer_pub_b64);
    assert!(authorship, "fixture deve verificar");
    assert_opens(&s1.sealed, &[("enc-frigo", &frigo_priv)], plaintext);
    let api_field = RecipientSealedField {
        dfid: s1.sealed.dfid.clone(),
        event_id: uuid::Uuid::parse_str("0a0a0a0a-0b0b-0c0c-0d0d-0e0e0e0e0e0e").unwrap(),
        event_type: "item_updated".to_string(),
        occurred_at: "2026-08-20T12:00:00Z".to_string(),
        field_path: s1.sealed.field_path.clone(),
        content_type: s1.sealed.content_type.clone(),
        recipient_enc_key_id: "enc-frigo".to_string(),
        sealed_field: s1.sealed.clone(),
        sealer_workspace_id: s1.sealed.sealer_workspace_id.clone(),
        sealer_key_id: s1.sealed.sealer_key_id.clone(),
        authorship_verified: authorship,
        sealer_public_key_b64: Some(s1.sealer_pub_b64.clone()),
        commitment_alg: "hmac-sha256/hkdf-sha256".to_string(),
        commitment_value: s1.sealed.commitment_sha256.clone(),
    };
    vectors.push(serde_json::json!({
        "name": "api-response-do-serializer",
        "api_response": {
            // serde_json sobre o struct do servidor — o SDK pina os nomes AQUI, não em prosa.
            "recipient_sealed_field": api_field,
            "recipient_privkey_b64": frigo_priv,
            "expected_plaintext_b64": b64(plaintext),
            "expected_local_authorship": true,
        },
    }));

    // ── 5. direção inversa (sdk-ts#5): chave gerada pelo SDK, Rust sela pra ela ─────────────────
    if let (Ok(ts_pub), Ok(ts_priv)) = (
        std::env::var("TS_RECIPIENT_PUB"),
        std::env::var("TS_RECIPIENT_PRIV"),
    ) {
        let s5 = seal_and_sign(
            "DFID-DEFARM-BR-2026-000005-000005",
            "55555555-6666-7777-8888-999999999999",
            "preco_venda",
            "text/plain",
            plaintext,
            &[Recipient {
                workspace_id: "ws-ts".to_string(),
                enc_key_id: "enc-ts".to_string(),
                enc_pubkey_b64: ts_pub,
            }],
            "ws-produtor",
            9,
        );
        vectors.push(serde_json::json!({
            "name": "cross-key-chave-gerada-pelo-sdk",
            "envelope": envelope_json(&s5, &[("enc-ts", &ts_priv)], plaintext),
        }));
    } else {
        eprintln!("TS_RECIPIENT_PUB/PRIV ausentes — vetor cross-key pulado (direção sdk-ts#5)");
    }

    std::fs::write(&out_path, serde_json::to_string_pretty(&vectors).unwrap()).unwrap();
    eprintln!("{} vetores escritos em {out_path}", vectors.len());
}
