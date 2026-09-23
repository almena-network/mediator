//! JSON Web Signatures (RFC 7515) as DIDComm uses them: JSON serialization
//! (general or flattened) with a single signature, and compact JWTs for
//! `from_prior`.

use serde::{Deserialize, Serialize};

use crate::crypto::keys::{PublicKey, SecretKey};
use crate::{Error, Result, b64};

/// Media type of a DIDComm signed message.
pub const SIGNED_TYP: &str = "application/didcomm-signed+json";

/// A JWS in general JSON serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Jws {
    pub payload: String,
    pub signatures: Vec<JwsSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwsSignature {
    pub protected: String,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<JwsUnprotectedHeader>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwsUnprotectedHeader {
    pub kid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwsProtectedHeader {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    pub alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Accepts both JSON serializations on input; the spec requires it.
#[derive(Deserialize)]
#[serde(untagged)]
enum JwsInput {
    General {
        payload: String,
        signatures: Vec<JwsSignature>,
    },
    Flattened {
        payload: String,
        #[serde(flatten)]
        signature: JwsSignature,
    },
}

impl Jws {
    /// Signs `payload` as a DIDComm signed message (`typ` =
    /// `application/didcomm-signed+json`). `kid` goes in both headers: the
    /// protected one so it is covered by the signature, the unprotected one
    /// because that is where the spec's examples put it.
    pub fn sign(payload: &[u8], kid: &str, key: &SecretKey) -> Result<Self> {
        let alg = signature_alg(key.public_key().curve().signature_alg())?;
        let protected = JwsProtectedHeader {
            typ: Some(SIGNED_TYP.to_owned()),
            alg: alg.to_owned(),
            kid: Some(kid.to_owned()),
        };
        let protected = b64::encode(serde_json::to_vec(&protected)?);
        let payload = b64::encode(payload);
        let signature = key.sign(format!("{protected}.{payload}").as_bytes())?;
        Ok(Self {
            payload,
            signatures: vec![JwsSignature {
                protected,
                signature: b64::encode(signature),
                header: Some(JwsUnprotectedHeader {
                    kid: kid.to_owned(),
                }),
            }],
        })
    }

    /// Parses a JWS in general or flattened JSON serialization.
    pub fn parse(json: &str) -> Result<Self> {
        Ok(match serde_json::from_str::<JwsInput>(json)? {
            JwsInput::General {
                payload,
                signatures,
            } => Self {
                payload,
                signatures,
            },
            JwsInput::Flattened { payload, signature } => Self {
                payload,
                signatures: vec![signature],
            },
        })
    }

    /// The one signature DIDComm allows, with its decoded protected header.
    fn single(&self) -> Result<(&JwsSignature, JwsProtectedHeader)> {
        let [signature] = self.signatures.as_slice() else {
            return Err(Error::malformed(
                "a signed message must carry exactly one signature",
            ));
        };
        let header: JwsProtectedHeader =
            serde_json::from_slice(&b64::decode(&signature.protected)?)?;
        Ok((signature, header))
    }

    pub fn protected_header(&self) -> Result<JwsProtectedHeader> {
        Ok(self.single()?.1)
    }

    /// The signer's key id: from the protected header if there, else from the
    /// unprotected one. If both are present they must agree.
    pub fn signer_kid(&self) -> Result<String> {
        let (signature, header) = self.single()?;
        let unprotected = signature.header.as_ref().map(|h| h.kid.as_str());
        match (header.kid.as_deref(), unprotected) {
            (Some(a), Some(b)) if a != b => Err(Error::inconsistent("JWS kid headers differ")),
            (Some(kid), _) | (None, Some(kid)) => Ok(kid.to_owned()),
            (None, None) => Err(Error::malformed("JWS without kid")),
        }
    }

    /// Checks the signature with `key` and returns the decoded payload. The
    /// header `alg` must be the one `key`'s curve signs with.
    pub fn verify(&self, key: &PublicKey) -> Result<Vec<u8>> {
        let (signature, header) = self.single()?;
        let alg = signature_alg(key.curve().signature_alg())?;
        if header.alg != alg {
            return Err(Error::inconsistent(format!(
                "JWS alg {} does not match a {} key",
                header.alg,
                key.curve().jwk_crv()
            )));
        }
        let input = format!("{}.{}", signature.protected, self.payload);
        key.verify(input.as_bytes(), &b64::decode(&signature.signature)?)?;
        b64::decode(&self.payload)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

fn signature_alg(alg: Option<&'static str>) -> Result<&'static str> {
    alg.ok_or_else(|| Error::unsupported("key cannot sign"))
}

/// Signs a compact JWT (`header.payload.signature`) with `typ` = `JWT`.
pub(crate) fn sign_compact(payload: &[u8], kid: &str, key: &SecretKey) -> Result<String> {
    let alg = signature_alg(key.public_key().curve().signature_alg())?;
    let header = JwsProtectedHeader {
        typ: Some("JWT".to_owned()),
        alg: alg.to_owned(),
        kid: Some(kid.to_owned()),
    };
    let input = format!(
        "{}.{}",
        b64::encode(serde_json::to_vec(&header)?),
        b64::encode(payload)
    );
    let signature = key.sign(input.as_bytes())?;
    Ok(format!("{input}.{}", b64::encode(signature)))
}

/// A parsed, not yet verified, compact JWT.
pub(crate) struct Compact<'a> {
    pub header: JwsProtectedHeader,
    pub payload: Vec<u8>,
    signing_input: &'a str,
    signature: Vec<u8>,
}

impl<'a> Compact<'a> {
    pub fn parse(token: &'a str) -> Result<Self> {
        let malformed = || Error::malformed("compact JWS");
        let (signing_input, signature) = token.rsplit_once('.').ok_or_else(malformed)?;
        let (header, payload) = signing_input.split_once('.').ok_or_else(malformed)?;
        Ok(Self {
            header: serde_json::from_slice(&b64::decode(header)?)?,
            payload: b64::decode(payload)?,
            signing_input,
            signature: b64::decode(signature)?,
        })
    }

    pub fn verify(&self, key: &PublicKey) -> Result<()> {
        let alg = signature_alg(key.curve().signature_alg())?;
        if self.header.alg != alg {
            return Err(Error::inconsistent("JWT alg does not match the key"));
        }
        key.verify(self.signing_input.as_bytes(), &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Curve;

    #[test]
    fn sign_then_verify() {
        for curve in [Curve::Ed25519, Curve::P256, Curve::Secp256k1] {
            let key = SecretKey::generate(curve).unwrap();
            let jws = Jws::sign(b"{}", "did:example:a#1", &key).unwrap();
            let parsed = Jws::parse(&jws.to_json().unwrap()).unwrap();
            assert_eq!(parsed.signer_kid().unwrap(), "did:example:a#1");
            assert_eq!(parsed.verify(&key.public_key()).unwrap(), b"{}");
        }
    }

    #[test]
    fn verify_fails_with_another_key() {
        let key = SecretKey::generate(Curve::Ed25519).unwrap();
        let other = SecretKey::generate(Curve::Ed25519).unwrap();
        let jws = Jws::sign(b"{}", "did:example:a#1", &key).unwrap();
        assert!(jws.verify(&other.public_key()).is_err());
    }

    #[test]
    fn flattened_form_is_accepted() {
        let key = SecretKey::generate(Curve::Ed25519).unwrap();
        let jws = Jws::sign(b"{}", "did:example:a#1", &key).unwrap();
        let s = &jws.signatures[0];
        let flat = serde_json::json!({
            "payload": jws.payload, "protected": s.protected, "signature": s.signature,
            "header": {"kid": "did:example:a#1"}
        });
        let parsed = Jws::parse(&flat.to_string()).unwrap();
        assert_eq!(parsed.verify(&key.public_key()).unwrap(), b"{}");
    }

    #[test]
    fn compact_round_trip() {
        let key = SecretKey::generate(Curve::Ed25519).unwrap();
        let token = sign_compact(br#"{"sub":"a"}"#, "did:example:a#1", &key).unwrap();
        let parsed = Compact::parse(&token).unwrap();
        parsed.verify(&key.public_key()).unwrap();
        assert_eq!(parsed.payload, br#"{"sub":"a"}"#);
        assert_eq!(parsed.header.kid.as_deref(), Some("did:example:a#1"));
    }
}
