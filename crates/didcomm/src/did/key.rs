//! `did:key` (<https://w3c-ccg.github.io/did-method-key/>).
//!
//! An Ed25519 `did:key` also gets the X25519 key derived from it as its
//! `keyAgreement` key, as most DIDComm implementations expect.

use crate::did::document::{DidDocument, VerificationMethod};
use crate::did::multikey;
use crate::{Curve, Error, PublicKey, Result};

/// The `did:key` for `key`.
pub fn did_key(key: &PublicKey) -> String {
    format!("did:key:{}", multikey::encode(key))
}

pub(crate) fn resolve(did: &str) -> Result<DidDocument> {
    let encoded = did
        .strip_prefix("did:key:")
        .ok_or_else(|| Error::DidNotFound(did.to_owned()))?;
    let key = multikey::decode(encoded)?;
    let method = |key: PublicKey, fragment: &str| VerificationMethod {
        id: format!("{did}#{fragment}"),
        controller: did.to_owned(),
        key,
    };

    let mut doc = DidDocument {
        id: did.to_owned(),
        ..DidDocument::default()
    };
    let main = method(key.clone(), encoded);
    let main_id = main.id.clone();
    doc.verification_method.push(main);

    match key.curve() {
        Curve::Ed25519 => {
            doc.authentication.push(main_id.clone());
            doc.assertion_method.push(main_id);
            if let PublicKey::Ed25519(ed) = &key {
                let x =
                    PublicKey::X25519(x25519_dalek::PublicKey::from(ed.to_montgomery().to_bytes()));
                let derived = method(x.clone(), &multikey::encode(&x));
                doc.key_agreement.push(derived.id.clone());
                doc.verification_method.push(derived);
            }
        }
        Curve::X25519 | Curve::P384 | Curve::P521 => doc.key_agreement.push(main_id),
        Curve::P256 => {
            doc.authentication.push(main_id.clone());
            doc.assertion_method.push(main_id.clone());
            doc.key_agreement.push(main_id);
        }
        Curve::Secp256k1 => {
            doc.authentication.push(main_id.clone());
            doc.assertion_method.push(main_id);
        }
    }
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Example from the did:key spec, with its derived X25519 key.
    #[test]
    fn ed25519_example_derives_the_spec_x25519_key() {
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let doc = resolve(did).unwrap();
        assert_eq!(
            doc.authentication,
            [format!(
                "{did}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            )]
        );
        assert_eq!(
            doc.key_agreement,
            [format!(
                "{did}#z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p"
            )]
        );
    }

    #[test]
    fn round_trip() {
        let key = crate::SecretKey::generate(Curve::P256)
            .unwrap()
            .public_key();
        let doc = resolve(&did_key(&key)).unwrap();
        assert_eq!(doc.verification_method[0].key, key);
    }
}
