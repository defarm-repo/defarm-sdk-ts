//! Gera vetores de conformidade cross-linguagem (rascunho do engines#591).
//!
//! O Rust é o ORÁCULO do formato: sela+assina com chaves de teste FIXAS (fixtures descartáveis,
//! nunca reais — as privadas vão DENTRO do vetor de propósito, pra outra implementação abrir) e
//! escreve um vectors.json que o SDK TS/Python replay byte-a-byte.
//!
//! Rodar: `VECTOR_OUT=/tmp/vectors.json cargo test -p item-registry --test ts_conformance_vector_gen -- --nocapture`

use base64::Engine;
use hpke::kem::X25519HkdfSha256;
use hpke::{Kem as KemTrait, Serializable};
use item_registry::api::sealed_field::{
    canonical_enc_key_binding, canonical_sealer_signing_string, seal_field, sign_sealed_field,
    Recipient,
};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
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

    // Chaves FIXAS de teste (derivadas de ikm/seed constantes) — fixtures, nunca reais.
    let recipient_ikm = [7u8; 32];
    let (recipient_sk, recipient_pk) = X25519HkdfSha256::derive_keypair(&recipient_ikm);
    let recipient_pub_b64 = b64(&recipient_pk.to_bytes());
    let recipient_priv_b64 = b64(&recipient_sk.to_bytes());

    let sealer_seed = [9u8; 32];
    let sealer_signing = ed25519_dalek::SigningKey::from_bytes(&sealer_seed);
    let sealer_pub_b64 = b64(sealer_signing.verifying_key().as_bytes());
    let sealer_seed_b64 = b64(&sealer_seed);

    let dfid = "DFID-DEFARM-BR-2026-000001-000001";
    let client_event_id = "11111111-2222-3333-4444-555555555555";
    let field_path = "preco_venda";
    let content_type = "text/plain";
    let plaintext = b"R$ 8.500,00";

    let recipients = vec![Recipient {
        workspace_id: "ws-frigo".to_string(),
        enc_key_id: "enc-frigo".to_string(),
        enc_pubkey_b64: recipient_pub_b64.clone(),
    }];

    let mut sealed = seal_field(
        dfid,
        client_event_id,
        field_path,
        content_type,
        plaintext,
        &recipients,
    )
    .expect("seal");
    sign_sealed_field(&mut sealed, "ws-produtor", "sign-produtor", &sealer_seed_b64).expect("sign");

    let signing_string = canonical_sealer_signing_string(&sealed);

    // Binding da chave de cifra assinado pela Ed25519 do destinatário (fixture própria).
    let binding_seed = [11u8; 32];
    let binding_signing = ed25519_dalek::SigningKey::from_bytes(&binding_seed);
    let binding_canonical = canonical_enc_key_binding("ws-frigo", "enc-frigo", &recipient_pub_b64);
    use ed25519_dalek::Signer;
    let binding_sig_b64 = b64(&binding_signing.sign(binding_canonical.as_bytes()).to_bytes());
    let binding_pub_b64 = b64(binding_signing.verifying_key().as_bytes());

    let vectors = serde_json::json!([
        {
            "name": "envelope-basico-1-destinatario",
            "aad": {
                "dfid": dfid,
                "event_id": client_event_id,
                "field_path": field_path,
                "content_type": content_type,
                "commitment": sealed.commitment_sha256,
                "expected": sealed.aad,
            },
            "binding": {
                "workspace_id": "ws-frigo",
                "enc_key_id": "enc-frigo",
                "enc_pubkey_b64": recipient_pub_b64,
                "expected_canonical": binding_canonical,
                "sig_b64": binding_sig_b64,
                "signing_pubkey_b64": binding_pub_b64,
            },
            "envelope": {
                "sealed_field": sealed,
                "recipient_enc_key_id": "enc-frigo",
                "recipient_privkey_b64": recipient_priv_b64,
                "expected_plaintext_b64": b64(plaintext),
                "sealer_signing_pubkey_b64": sealer_pub_b64,
                "expected_signing_string": signing_string,
            }
        }
    ]);

    std::fs::write(&out_path, serde_json::to_string_pretty(&vectors).unwrap()).unwrap();
    eprintln!("vetores escritos em {out_path}");
}
