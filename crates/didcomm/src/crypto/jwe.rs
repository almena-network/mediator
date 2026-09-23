//! JSON Web Encryption (RFC 7516, general JSON serialization) with the two
//! key-wrapping schemes DIDComm uses:
//!
//! - anoncrypt: `ECDH-ES+A256KW` (RFC 7518 §4.6),
//! - authcrypt: `ECDH-1PU+A256KW` (draft-madden-jose-ecdh-1pu-04).
//!
//! As the spec requires, `epk`, `apu`, `apv` and `alg` are common to all
//! recipients and live in the protected header, and the content is encrypted
//! first so that ECDH-1PU can bind the content tag into the key derivation.

use aes_kw::{KeyInit, KwAes256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::content::ContentEncryption;
use crate::crypto::keys::{PublicKey, SecretKey, random_fill};
use crate::{Error, Jwk, Result, b64};

/// Media type of a DIDComm encrypted message.
pub const ENCRYPTED_TYP: &str = "application/didcomm-encrypted+json";

/// Key-wrapping algorithm (JWE `alg`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyWrap {
    /// Anoncrypt.
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256Kw,
    /// Authcrypt.
    #[serde(rename = "ECDH-1PU+A256KW")]
    Ecdh1PuA256Kw,
}

impl KeyWrap {
    fn name(self) -> &'static str {
        match self {
            Self::EcdhEsA256Kw => "ECDH-ES+A256KW",
            Self::Ecdh1PuA256Kw => "ECDH-1PU+A256KW",
        }
    }
}

/// A JWE in general JSON serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwe {
    pub protected: String,
    pub recipients: Vec<JweRecipient>,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JweRecipient {
    pub header: JweRecipientHeader,
    pub encrypted_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JweRecipientHeader {
    pub kid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JweProtectedHeader {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    pub alg: KeyWrap,
    pub enc: ContentEncryption,
    pub epk: Jwk,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apu: Option<String>,
    pub apv: String,
}

impl JweProtectedHeader {
    /// The sender's key id for authcrypt: `skid`, or else decoded from `apu`
    /// (the spec requires accepting either). If both are present they must agree.
    pub fn sender_kid(&self) -> Result<Option<String>> {
        let from_apu = match &self.apu {
            Some(apu) => Some(
                String::from_utf8(b64::decode(apu)?)
                    .map_err(|_| Error::malformed("apu is not UTF-8"))?,
            ),
            None => None,
        };
        match (&self.skid, from_apu) {
            (Some(skid), Some(apu)) if *skid != apu => {
                Err(Error::inconsistent("skid does not match apu"))
            }
            (Some(skid), _) => Ok(Some(skid.clone())),
            (None, apu) => Ok(apu),
        }
    }
}

/// Where a recipient's content key is wrapped to.
pub struct Recipient<'a> {
    pub kid: &'a str,
    pub key: &'a PublicKey,
}

/// The sender of an authcrypt message.
pub struct Sender<'a> {
    pub kid: &'a str,
    pub key: &'a SecretKey,
}

impl Jwe {
    /// Anonymous encryption (`ECDH-ES+A256KW`) to every recipient.
    pub fn anoncrypt(
        plaintext: &[u8],
        recipients: &[Recipient<'_>],
        enc: ContentEncryption,
    ) -> Result<Self> {
        encrypt(plaintext, None, recipients, enc)
    }

    /// Sender-authenticated encryption (`ECDH-1PU+A256KW`, `A256CBC-HS512`).
    pub fn authcrypt(
        plaintext: &[u8],
        sender: &Sender<'_>,
        recipients: &[Recipient<'_>],
    ) -> Result<Self> {
        encrypt(
            plaintext,
            Some(sender),
            recipients,
            ContentEncryption::A256CbcHs512,
        )
    }

    pub fn parse(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn protected_header(&self) -> Result<JweProtectedHeader> {
        Ok(serde_json::from_slice(&b64::decode(&self.protected)?)?)
    }

    /// Key ids of all recipients, in envelope order.
    pub fn recipient_kids(&self) -> impl Iterator<Item = &str> {
        self.recipients.iter().map(|r| r.header.kid.as_str())
    }

    /// Decrypts as recipient `kid`. `sender` is the sender's public key and is
    /// required for authcrypt (`ECDH-1PU`), ignored for anoncrypt.
    pub fn decrypt(
        &self,
        kid: &str,
        key: &SecretKey,
        sender: Option<&PublicKey>,
    ) -> Result<Vec<u8>> {
        let header = self.protected_header()?;
        let recipient = self
            .recipients
            .iter()
            .find(|r| r.header.kid == kid)
            .ok_or_else(|| Error::SecretNotFound(kid.to_owned()))?;

        if header.apv != apv(self.recipient_kids()) {
            return Err(Error::inconsistent("apv does not match the recipient kids"));
        }
        let epk = PublicKey::from_jwk(&header.epk)?;
        if epk.curve() != key.curve() {
            return Err(Error::inconsistent(
                "epk and recipient key are on different curves",
            ));
        }
        let apu = decode_opt(header.apu.as_deref())?;
        let apv_bytes = b64::decode(&header.apv)?;
        let tag = b64::decode(&self.tag)?;

        let kek = match header.alg {
            KeyWrap::EcdhEsA256Kw => {
                let z = key.diffie_hellman(&epk)?;
                concat_kdf(&z, header.alg, &apu, &apv_bytes, None)
            }
            KeyWrap::Ecdh1PuA256Kw => {
                if header.enc != ContentEncryption::A256CbcHs512 {
                    return Err(Error::unsupported("ECDH-1PU requires A256CBC-HS512"));
                }
                let sender =
                    sender.ok_or_else(|| Error::malformed("authcrypt without sender key"))?;
                if sender.curve() != key.curve() {
                    return Err(Error::inconsistent(
                        "sender and recipient keys are on different curves",
                    ));
                }
                let mut z = key.diffie_hellman(&epk)?;
                z.extend_from_slice(&key.diffie_hellman(sender)?);
                concat_kdf(&z, header.alg, &apu, &apv_bytes, Some(&tag))
            }
        };

        let wrapped = b64::decode(&recipient.encrypted_key)?;
        let cek = unwrap_key(&kek, &wrapped)?;
        header.enc.decrypt(
            &cek,
            &b64::decode(&self.iv)?,
            self.protected.as_bytes(),
            &b64::decode(&self.ciphertext)?,
            &tag,
        )
    }
}

fn encrypt(
    plaintext: &[u8],
    sender: Option<&Sender<'_>>,
    recipients: &[Recipient<'_>],
    enc: ContentEncryption,
) -> Result<Jwe> {
    let first = recipients
        .first()
        .ok_or_else(|| Error::malformed("no recipients"))?;
    let curve = first.key.curve();
    if !curve.is_key_agreement() {
        return Err(Error::unsupported(format!(
            "key agreement with {}",
            curve.jwk_crv()
        )));
    }
    if recipients.iter().any(|r| r.key.curve() != curve) {
        return Err(Error::NoCompatibleKeys(
            "recipient keys on different curves".into(),
        ));
    }
    if let Some(sender) = sender
        && sender.key.curve() != curve
    {
        return Err(Error::NoCompatibleKeys(
            "sender and recipients on different curves".into(),
        ));
    }

    let alg = if sender.is_some() {
        KeyWrap::Ecdh1PuA256Kw
    } else {
        KeyWrap::EcdhEsA256Kw
    };
    let ephemeral = SecretKey::generate(curve)?;
    let apv = apv(recipients.iter().map(|r| r.kid));
    let header = JweProtectedHeader {
        typ: Some(ENCRYPTED_TYP.to_owned()),
        alg,
        enc,
        epk: ephemeral.public_key().to_jwk(),
        skid: sender.map(|s| s.kid.to_owned()),
        apu: sender.map(|s| b64::encode(s.kid)),
        apv,
    };
    let protected = b64::encode(serde_json::to_vec(&header)?);

    let mut cek = Zeroizing::new(vec![0u8; enc.key_len()]);
    random_fill(&mut cek)?;
    let mut iv = vec![0u8; enc.iv_len()];
    random_fill(&mut iv)?;
    let (ciphertext, tag) = enc.encrypt(&cek, &iv, protected.as_bytes(), plaintext)?;

    let apu = decode_opt(header.apu.as_deref())?;
    let apv_bytes = b64::decode(&header.apv)?;
    let recipients = recipients
        .iter()
        .map(|recipient| {
            let mut z = ephemeral.diffie_hellman(recipient.key)?;
            let kek = match sender {
                Some(sender) => {
                    z.extend_from_slice(&sender.key.diffie_hellman(recipient.key)?);
                    concat_kdf(&z, alg, &apu, &apv_bytes, Some(&tag))
                }
                None => concat_kdf(&z, alg, &apu, &apv_bytes, None),
            };
            Ok(JweRecipient {
                header: JweRecipientHeader {
                    kid: recipient.kid.to_owned(),
                },
                encrypted_key: b64::encode(wrap_key(&kek, &cek)?),
            })
        })
        .collect::<Result<_>>()?;

    Ok(Jwe {
        protected,
        recipients,
        iv: b64::encode(iv),
        ciphertext: b64::encode(ciphertext),
        tag: b64::encode(tag),
    })
}

/// `apv`: base64url(SHA-256(recipient kids, sorted, joined with `.`)).
fn apv<'a>(kids: impl Iterator<Item = &'a str>) -> String {
    let mut kids: Vec<&str> = kids.collect();
    kids.sort_unstable();
    b64::encode(Sha256::digest(kids.join(".").as_bytes()))
}

fn decode_opt(value: Option<&str>) -> Result<Vec<u8>> {
    value.map_or(Ok(Vec::new()), b64::decode)
}

/// Concat KDF (NIST SP 800-56A, as profiled by RFC 7518 §4.6.2) deriving the
/// 256-bit A256KW key. ECDH-1PU appends the content tag to `SuppPubInfo`.
fn concat_kdf(
    z: &[u8],
    alg: KeyWrap,
    apu: &[u8],
    apv: &[u8],
    tag: Option<&[u8]>,
) -> Zeroizing<[u8; 32]> {
    fn with_len(hasher: &mut Sha256, data: &[u8]) {
        // Lengths here are bounded by header sizes, far below u32::MAX.
        hasher.update((data.len() as u32).to_be_bytes());
        hasher.update(data);
    }

    let mut hasher = Sha256::new();
    hasher.update(1u32.to_be_bytes()); // round counter: 256 bits need one SHA-256 round
    hasher.update(z);
    with_len(&mut hasher, alg.name().as_bytes());
    with_len(&mut hasher, apu);
    with_len(&mut hasher, apv);
    hasher.update(256u32.to_be_bytes());
    if let Some(tag) = tag {
        with_len(&mut hasher, tag);
    }
    Zeroizing::new(hasher.finalize().into())
}

fn wrap_key(kek: &[u8; 32], cek: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; cek.len() + 8];
    KwAes256::new(kek.into())
        .wrap_key(cek, &mut out)
        .map_err(|_| Error::Crypto("key wrap"))?;
    Ok(out)
}

fn unwrap_key(kek: &[u8; 32], wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let len = wrapped
        .len()
        .checked_sub(8)
        .ok_or_else(|| Error::malformed("encrypted_key too short"))?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    KwAes256::new(kek.into())
        .unwrap_key(wrapped, &mut out)
        .map_err(|_| Error::Crypto("key unwrap"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Curve;

    struct Party {
        kid: String,
        key: SecretKey,
    }

    fn party(kid: &str, curve: Curve) -> Party {
        Party {
            kid: kid.to_owned(),
            key: SecretKey::generate(curve).unwrap(),
        }
    }

    #[test]
    fn anoncrypt_round_trips_for_every_recipient() {
        for curve in [Curve::X25519, Curve::P256, Curve::P384, Curve::P521] {
            for enc in [
                ContentEncryption::A256CbcHs512,
                ContentEncryption::A256Gcm,
                ContentEncryption::Xc20p,
            ] {
                let bobs = [
                    party("did:example:bob#1", curve),
                    party("did:example:bob#2", curve),
                ];
                let publics: Vec<_> = bobs.iter().map(|b| b.key.public_key()).collect();
                let recipients: Vec<_> = bobs
                    .iter()
                    .zip(&publics)
                    .map(|(b, key)| Recipient { kid: &b.kid, key })
                    .collect();
                let jwe = Jwe::anoncrypt(b"hi", &recipients, enc).unwrap();
                let jwe = Jwe::parse(&jwe.to_json().unwrap()).unwrap();
                for bob in &bobs {
                    assert_eq!(jwe.decrypt(&bob.kid, &bob.key, None).unwrap(), b"hi");
                }
            }
        }
    }

    #[test]
    fn authcrypt_round_trips_and_binds_the_sender() {
        for curve in [Curve::X25519, Curve::P256, Curve::P384, Curve::P521] {
            let alice = party("did:example:alice#1", curve);
            let mallory = party("did:example:mallory#1", curve);
            let bob = party("did:example:bob#1", curve);
            let bob_public = bob.key.public_key();
            let jwe = Jwe::authcrypt(
                b"hi",
                &Sender {
                    kid: &alice.kid,
                    key: &alice.key,
                },
                &[Recipient {
                    kid: &bob.kid,
                    key: &bob_public,
                }],
            )
            .unwrap();
            let header = jwe.protected_header().unwrap();
            assert_eq!(
                header.sender_kid().unwrap().as_deref(),
                Some("did:example:alice#1")
            );
            let plain = jwe
                .decrypt(&bob.kid, &bob.key, Some(&alice.key.public_key()))
                .unwrap();
            assert_eq!(plain, b"hi");
            assert!(
                jwe.decrypt(&bob.kid, &bob.key, Some(&mallory.key.public_key()))
                    .is_err()
            );
        }
    }

    #[test]
    fn mixed_curves_are_rejected() {
        let a = party("did:example:bob#1", Curve::X25519);
        let b = party("did:example:bob#2", Curve::P256);
        let (pa, pb) = (a.key.public_key(), b.key.public_key());
        let recipients = [
            Recipient {
                kid: &a.kid,
                key: &pa,
            },
            Recipient {
                kid: &b.kid,
                key: &pb,
            },
        ];
        assert!(Jwe::anoncrypt(b"hi", &recipients, ContentEncryption::A256Gcm).is_err());
    }

    #[test]
    fn a_recipient_list_change_breaks_apv() {
        let bob = party("did:example:bob#1", Curve::X25519);
        let public = bob.key.public_key();
        let mut jwe = Jwe::anoncrypt(
            b"hi",
            &[Recipient {
                kid: &bob.kid,
                key: &public,
            }],
            ContentEncryption::A256Gcm,
        )
        .unwrap();
        let mut extra = jwe.recipients[0].clone();
        extra.header.kid = "did:example:eve#1".into();
        jwe.recipients.push(extra);
        assert!(matches!(
            jwe.decrypt(&bob.kid, &bob.key, None),
            Err(Error::Inconsistent(_))
        ));
    }
}
