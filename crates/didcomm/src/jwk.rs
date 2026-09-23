//! JSON Web Keys (RFC 7517) for the key types DIDComm uses.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A JWK as it appears on the wire: `OKP` (Ed25519, X25519) or `EC` (P-256,
/// P-384, P-521, secp256k1). `d` is present only for private keys.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl fmt::Debug for Jwk {
    // Hand-written so a private key never ends up in logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jwk")
            .field("kty", &self.kty)
            .field("crv", &self.crv)
            .field("x", &self.x)
            .field("y", &self.y)
            .field("d", &self.d.as_ref().map(|_| "<redacted>"))
            .field("kid", &self.kid)
            .finish()
    }
}
