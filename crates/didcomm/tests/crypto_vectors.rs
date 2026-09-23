//! The DIDComm v2.0 spec's Appendix C vectors, checked at the JWS/JWE level
//! with the Appendix A keys. The message-level tests (DID resolution,
//! consistency checks) live in `unpack_vectors.rs`.

#![expect(clippy::unwrap_used, reason = "tests")]

use almena_didcomm::crypto::jwe::Jwe;
use almena_didcomm::crypto::jws::Jws;
use almena_didcomm::{Jwk, SecretKey};
use serde_json::Value;

fn appendix() -> Value {
    serde_json::from_str(include_str!("spec/appendix.json")).unwrap()
}

fn secret(appendix: &Value, kid: &str) -> SecretKey {
    let all = appendix["alice_secrets"]
        .as_array()
        .unwrap()
        .iter()
        .chain(appendix["bob_secrets"].as_array().unwrap());
    let jwk = all.clone().find(|s| s["kid"] == kid).unwrap();
    SecretKey::from_jwk(&serde_json::from_value::<Jwk>(jwk.clone()).unwrap()).unwrap()
}

/// Peels one JWE layer as the first recipient and returns the plaintext.
fn decrypt_as_bob(appendix: &Value, jwe: &Jwe) -> Vec<u8> {
    let header = jwe.protected_header().unwrap();
    let sender = header
        .sender_kid()
        .unwrap()
        .map(|kid| secret(appendix, &kid).public_key());
    let mut plaintexts = jwe.recipient_kids().map(|kid| {
        jwe.decrypt(kid, &secret(appendix, kid), sender.as_ref())
            .unwrap()
    });
    let first = plaintexts.next().unwrap();
    assert!(
        plaintexts.all(|p| p == first),
        "every recipient gets the same plaintext"
    );
    first
}

fn expected_plaintext(appendix: &Value) -> Value {
    appendix["plaintext"].clone()
}

fn assert_is_the_plaintext(appendix: &Value, bytes: &[u8]) {
    let mut message: Value = serde_json::from_slice(bytes).unwrap();
    // The signed vectors carry `typ` inside the payload; the plaintext vector does not.
    message.as_object_mut().unwrap().remove("typ");
    assert_eq!(message, expected_plaintext(appendix));
}

fn verify_signed(appendix: &Value, json: &str) -> Vec<u8> {
    let jws = Jws::parse(json).unwrap();
    let key = secret(appendix, &jws.signer_kid().unwrap()).public_key();
    jws.verify(&key).unwrap()
}

#[test]
fn signed_vectors_verify() {
    let appendix = appendix();
    for vector in appendix["signed"].as_array().unwrap() {
        let payload = verify_signed(&appendix, &vector.to_string());
        assert_is_the_plaintext(&appendix, &payload);
    }
}

#[test]
fn anoncrypt_vectors_decrypt() {
    let appendix = appendix();
    // C.3 #1 X25519 + XC20P, #2 P-384 + A256CBC-HS512, #3 P-521 + A256GCM.
    for vector in &appendix["encrypted"].as_array().unwrap()[..3] {
        let jwe = Jwe::parse(&vector.to_string()).unwrap();
        assert_is_the_plaintext(&appendix, &decrypt_as_bob(&appendix, &jwe));
    }
}

#[test]
fn authcrypt_vector_decrypts() {
    let appendix = appendix();
    let jwe = Jwe::parse(&appendix["encrypted"][3].to_string()).unwrap();
    assert_is_the_plaintext(&appendix, &decrypt_as_bob(&appendix, &jwe));
}

#[test]
fn authcrypt_of_signed_vector_decrypts_and_verifies() {
    let appendix = appendix();
    let jwe = Jwe::parse(&appendix["encrypted"][4].to_string()).unwrap();
    let signed = decrypt_as_bob(&appendix, &jwe);
    let payload = verify_signed(&appendix, std::str::from_utf8(&signed).unwrap());
    assert_is_the_plaintext(&appendix, &payload);
}

#[test]
fn anoncrypt_of_authcrypt_of_signed_vector_peels_all_layers() {
    let appendix = appendix();
    let outer = Jwe::parse(&appendix["encrypted"][5].to_string()).unwrap();
    let inner = decrypt_as_bob(&appendix, &outer);
    let inner = Jwe::parse(std::str::from_utf8(&inner).unwrap()).unwrap();
    let signed = decrypt_as_bob(&appendix, &inner);
    let payload = verify_signed(&appendix, std::str::from_utf8(&signed).unwrap());
    assert_is_the_plaintext(&appendix, &payload);
}
