//! The spec's Appendix C vectors through the full `unpack`: DID resolution,
//! verification relationships and the layer consistency checks.

#![expect(clippy::unwrap_used, reason = "tests")]

use almena_didcomm::{
    ContentEncryption, DidDocument, InMemorySecrets, Jwk, SecretKey, StaticResolver, unpack,
};
use serde_json::Value;

struct Bob {
    resolver: StaticResolver,
    secrets: InMemorySecrets,
    vectors: Value,
}

fn bob() -> Bob {
    let vectors: Value = serde_json::from_str(include_str!("spec/appendix.json")).unwrap();
    let resolver = StaticResolver::new([
        DidDocument::from_json(&vectors["alice_did_doc"]).unwrap(),
        DidDocument::from_json(&vectors["bob_did_doc"]).unwrap(),
    ]);
    let mut secrets = InMemorySecrets::new();
    for jwk in vectors["bob_secrets"].as_array().unwrap() {
        let jwk: Jwk = serde_json::from_value(jwk.clone()).unwrap();
        secrets.insert(jwk.kid.clone().unwrap(), SecretKey::from_jwk(&jwk).unwrap());
    }
    Bob {
        resolver,
        secrets,
        vectors,
    }
}

async fn unpack_vector(
    bob: &Bob,
    vector: &Value,
) -> (almena_didcomm::Message, almena_didcomm::UnpackMetadata) {
    unpack(&vector.to_string(), &bob.resolver, &bob.secrets)
        .await
        .unwrap()
}

#[tokio::test]
async fn signed_vectors() {
    let bob = bob();
    for (vector, kid) in bob.vectors["signed"].as_array().unwrap().iter().zip([
        "did:example:alice#key-1",
        "did:example:alice#key-2",
        "did:example:alice#key-3",
    ]) {
        let (message, meta) = unpack_vector(&bob, vector).await;
        assert_eq!(message.id, "1234567890");
        assert!(meta.non_repudiation && !meta.encrypted);
        assert_eq!(meta.sign_from.as_deref(), Some(kid));
    }
}

#[tokio::test]
async fn anoncrypt_vectors() {
    let bob = bob();
    let expected = [
        ContentEncryption::Xc20p,
        ContentEncryption::A256CbcHs512,
        ContentEncryption::A256Gcm,
    ];
    for (vector, enc) in bob.vectors["encrypted"].as_array().unwrap()[..3]
        .iter()
        .zip(expected)
    {
        let (message, meta) = unpack_vector(&bob, vector).await;
        assert_eq!(message.from.as_deref(), Some("did:example:alice"));
        assert!(meta.encrypted && meta.anonymous_sender && !meta.authenticated);
        assert_eq!(meta.enc_alg_anon, Some(enc));
    }
}

#[tokio::test]
async fn authcrypt_vector() {
    let bob = bob();
    let (_, meta) = unpack_vector(&bob, &bob.vectors["encrypted"][3]).await;
    assert!(meta.authenticated && !meta.non_repudiation);
    assert_eq!(
        meta.encrypted_from_kid.as_deref(),
        Some("did:example:alice#key-x25519-1")
    );
    assert_eq!(meta.encrypted_to_kids.len(), 3);
}

#[tokio::test]
async fn authcrypt_of_signed_vector() {
    let bob = bob();
    let (_, meta) = unpack_vector(&bob, &bob.vectors["encrypted"][4]).await;
    assert!(meta.authenticated && meta.non_repudiation);
    assert_eq!(
        meta.encrypted_from_kid.as_deref(),
        Some("did:example:alice#key-p256-1")
    );
    assert_eq!(meta.sign_from.as_deref(), Some("did:example:alice#key-1"));
}

#[tokio::test]
async fn anoncrypt_of_authcrypt_of_signed_vector() {
    let bob = bob();
    let (_, meta) = unpack_vector(&bob, &bob.vectors["encrypted"][5]).await;
    assert!(meta.authenticated && meta.non_repudiation && !meta.anonymous_sender);
    assert_eq!(meta.enc_alg_anon, Some(ContentEncryption::Xc20p));
    assert_eq!(meta.enc_alg_auth, Some(ContentEncryption::A256CbcHs512));
}

#[tokio::test]
async fn without_our_secrets_nothing_decrypts() {
    let bob = bob();
    let err = unpack(
        &bob.vectors["encrypted"][0].to_string(),
        &bob.resolver,
        &InMemorySecrets::new(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, almena_didcomm::Error::SecretNotFound(_)));
}
