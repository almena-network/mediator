//! Typed public and private keys and the primitive operations DIDComm needs
//! from them: signing, verification and Diffie-Hellman.

use std::fmt;

use p256::elliptic_curve::sec1::ToSec1Point;
use zeroize::Zeroizing;

use crate::{Error, Result, b64, jwk::Jwk};

/// The curves DIDComm v2.0 uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Curve {
    /// Signatures (`EdDSA`).
    Ed25519,
    /// Key agreement.
    X25519,
    /// Key agreement and signatures (`ES256`).
    P256,
    /// Key agreement.
    P384,
    /// Key agreement (optional in the spec).
    P521,
    /// Signatures (`ES256K`).
    Secp256k1,
}

impl Curve {
    /// Parses the JWK `crv` value.
    pub fn from_jwk_crv(crv: &str) -> Result<Self> {
        Ok(match crv {
            "Ed25519" => Self::Ed25519,
            "X25519" => Self::X25519,
            "P-256" => Self::P256,
            "P-384" => Self::P384,
            "P-521" => Self::P521,
            "secp256k1" => Self::Secp256k1,
            other => return Err(Error::unsupported(format!("curve {other}"))),
        })
    }

    /// The JWK `crv` value.
    pub fn jwk_crv(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::X25519 => "X25519",
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
            Self::Secp256k1 => "secp256k1",
        }
    }

    /// The JWK `kty` value.
    pub fn jwk_kty(self) -> &'static str {
        match self {
            Self::Ed25519 | Self::X25519 => "OKP",
            _ => "EC",
        }
    }

    /// Whether DIDComm uses this curve for ECDH key agreement.
    pub fn is_key_agreement(self) -> bool {
        matches!(self, Self::X25519 | Self::P256 | Self::P384 | Self::P521)
    }

    /// The JWS `alg` for signatures made with this curve, if it signs.
    pub fn signature_alg(self) -> Option<&'static str> {
        match self {
            Self::Ed25519 => Some("EdDSA"),
            Self::P256 => Some("ES256"),
            Self::Secp256k1 => Some("ES256K"),
            _ => None,
        }
    }

    /// Length in bytes of a private scalar and of each public coordinate.
    fn field_len(self) -> usize {
        match self {
            Self::P384 => 48,
            Self::P521 => 66,
            _ => 32,
        }
    }
}

/// A public key on one of the supported curves.
#[derive(Clone, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    X25519(x25519_dalek::PublicKey),
    P256(p256::PublicKey),
    P384(p384::PublicKey),
    P521(p521::PublicKey),
    Secp256k1(k256::PublicKey),
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKey({:?}, {})",
            self.curve(),
            b64::encode(self.to_bytes())
        )
    }
}

impl PublicKey {
    pub fn curve(&self) -> Curve {
        match self {
            Self::Ed25519(_) => Curve::Ed25519,
            Self::X25519(_) => Curve::X25519,
            Self::P256(_) => Curve::P256,
            Self::P384(_) => Curve::P384,
            Self::P521(_) => Curve::P521,
            Self::Secp256k1(_) => Curve::Secp256k1,
        }
    }

    /// Decodes a key from its raw bytes: the 32-byte key for Ed25519 and
    /// X25519, a SEC1 point (compressed or not) for the EC curves. EC points
    /// are checked to be on the curve.
    pub fn from_bytes(curve: Curve, bytes: &[u8]) -> Result<Self> {
        let bad = || Error::invalid_key(format!("{} public key", curve.jwk_crv()));
        Ok(match curve {
            Curve::Ed25519 => {
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| bad())?;
                Self::Ed25519(ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| bad())?)
            }
            Curve::X25519 => {
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| bad())?;
                Self::X25519(x25519_dalek::PublicKey::from(bytes))
            }
            Curve::P256 => Self::P256(p256::PublicKey::from_sec1_bytes(bytes).map_err(|_| bad())?),
            Curve::P384 => Self::P384(p384::PublicKey::from_sec1_bytes(bytes).map_err(|_| bad())?),
            Curve::P521 => Self::P521(p521::PublicKey::from_sec1_bytes(bytes).map_err(|_| bad())?),
            Curve::Secp256k1 => {
                Self::Secp256k1(k256::PublicKey::from_sec1_bytes(bytes).map_err(|_| bad())?)
            }
        })
    }

    /// The inverse of [`PublicKey::from_bytes`]; EC points come out compressed.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(k) => k.to_bytes().to_vec(),
            Self::X25519(k) => k.to_bytes().to_vec(),
            Self::P256(k) => k.to_sec1_point(true).as_bytes().to_vec(),
            Self::P384(k) => k.to_sec1_point(true).as_bytes().to_vec(),
            Self::P521(k) => k.to_sec1_point(true).as_bytes().to_vec(),
            Self::Secp256k1(k) => k.to_sec1_point(true).as_bytes().to_vec(),
        }
    }

    /// Uncompressed SEC1 point (`0x04 || x || y`) for EC keys.
    fn uncompressed(&self) -> Option<Vec<u8>> {
        Some(match self {
            Self::P256(k) => k.to_sec1_point(false).as_bytes().to_vec(),
            Self::P384(k) => k.to_sec1_point(false).as_bytes().to_vec(),
            Self::P521(k) => k.to_sec1_point(false).as_bytes().to_vec(),
            Self::Secp256k1(k) => k.to_sec1_point(false).as_bytes().to_vec(),
            Self::Ed25519(_) | Self::X25519(_) => return None,
        })
    }

    pub fn from_jwk(jwk: &Jwk) -> Result<Self> {
        let curve = Curve::from_jwk_crv(&jwk.crv)?;
        if jwk.kty != curve.jwk_kty() {
            return Err(Error::invalid_key(format!(
                "kty {} with crv {}",
                jwk.kty, jwk.crv
            )));
        }
        let x = b64::decode(&jwk.x)?;
        if curve.jwk_kty() == "OKP" {
            return Self::from_bytes(curve, &x);
        }
        let y = jwk
            .y
            .as_deref()
            .ok_or_else(|| Error::invalid_key("EC JWK without y"))
            .and_then(b64::decode)?;
        let len = curve.field_len();
        if x.len() != len || y.len() != len {
            return Err(Error::invalid_key(format!("{} coordinate length", jwk.crv)));
        }
        let mut point = Vec::with_capacity(1 + 2 * len);
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        Self::from_bytes(curve, &point)
    }

    /// Public JWK, without `kid`.
    pub fn to_jwk(&self) -> Jwk {
        let curve = self.curve();
        let (x, y) = match self.uncompressed() {
            Some(point) => {
                let len = curve.field_len();
                (
                    b64::encode(&point[1..=len]),
                    Some(b64::encode(&point[1 + len..])),
                )
            }
            None => (b64::encode(self.to_bytes()), None),
        };
        Jwk {
            kty: curve.jwk_kty().to_owned(),
            crv: curve.jwk_crv().to_owned(),
            x,
            y,
            d: None,
            kid: None,
        }
    }

    /// Verifies `signature` over `message` with the algorithm this key's
    /// curve implies (see [`Curve::signature_alg`]). ECDSA signatures are the
    /// JOSE fixed-size `r || s`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        use p256::ecdsa::signature::Verifier;

        let failed = || Error::Crypto("signature");
        match self {
            Self::Ed25519(key) => {
                let signature =
                    ed25519_dalek::Signature::from_slice(signature).map_err(|_| failed())?;
                key.verify_strict(message, &signature).map_err(|_| failed())
            }
            Self::P256(key) => {
                let signature =
                    p256::ecdsa::Signature::from_slice(signature).map_err(|_| failed())?;
                p256::ecdsa::VerifyingKey::from(key)
                    .verify(message, &signature)
                    .map_err(|_| failed())
            }
            Self::Secp256k1(key) => {
                // JOSE does not require low-S; k256 does, and both forms are valid ECDSA.
                let signature = k256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| failed())?
                    .normalize_s();
                k256::ecdsa::VerifyingKey::from(key)
                    .verify(message, &signature)
                    .map_err(|_| failed())
            }
            Self::X25519(_) | Self::P384(_) | Self::P521(_) => Err(Error::unsupported(format!(
                "signatures with {}",
                self.curve().jwk_crv()
            ))),
        }
    }
}

/// A private key on one of the supported curves. Wiped from memory on drop.
#[derive(Clone)]
pub enum SecretKey {
    Ed25519(ed25519_dalek::SigningKey),
    X25519(x25519_dalek::StaticSecret),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
    Secp256k1(k256::SecretKey),
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey({:?})", self.curve())
    }
}

impl SecretKey {
    /// Generates a fresh key from the operating system's CSPRNG.
    pub fn generate(curve: Curve) -> Result<Self> {
        loop {
            let mut bytes = Zeroizing::new(vec![0u8; curve.field_len()]);
            random_fill(&mut bytes)?;
            if curve == Curve::P521 {
                // The P-521 order is just under 2^521: keep the top 7 bits clear
                // so almost every draw is a valid scalar.
                bytes[0] &= 0x01;
            }
            // EC draws outside [1, n) are rejected and redrawn.
            if let Ok(key) = Self::from_bytes(curve, &bytes) {
                return Ok(key);
            }
        }
    }

    pub fn curve(&self) -> Curve {
        match self {
            Self::Ed25519(_) => Curve::Ed25519,
            Self::X25519(_) => Curve::X25519,
            Self::P256(_) => Curve::P256,
            Self::P384(_) => Curve::P384,
            Self::P521(_) => Curve::P521,
            Self::Secp256k1(_) => Curve::Secp256k1,
        }
    }

    /// Decodes a private key from its raw bytes (seed for Ed25519, scalar otherwise).
    pub fn from_bytes(curve: Curve, bytes: &[u8]) -> Result<Self> {
        let bad = || Error::invalid_key(format!("{} private key", curve.jwk_crv()));
        Ok(match curve {
            Curve::Ed25519 => {
                let bytes: &[u8; 32] = bytes.try_into().map_err(|_| bad())?;
                Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(bytes))
            }
            Curve::X25519 => {
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| bad())?;
                Self::X25519(x25519_dalek::StaticSecret::from(bytes))
            }
            Curve::P256 => Self::P256(p256::SecretKey::from_slice(bytes).map_err(|_| bad())?),
            Curve::P384 => Self::P384(p384::SecretKey::from_slice(bytes).map_err(|_| bad())?),
            Curve::P521 => Self::P521(p521::SecretKey::from_slice(bytes).map_err(|_| bad())?),
            Curve::Secp256k1 => {
                Self::Secp256k1(k256::SecretKey::from_slice(bytes).map_err(|_| bad())?)
            }
        })
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(match self {
            Self::Ed25519(k) => k.to_bytes().to_vec(),
            Self::X25519(k) => k.to_bytes().to_vec(),
            Self::P256(k) => k.to_bytes().to_vec(),
            Self::P384(k) => k.to_bytes().to_vec(),
            Self::P521(k) => k.to_bytes().to_vec(),
            Self::Secp256k1(k) => k.to_bytes().to_vec(),
        })
    }

    /// Reads a private JWK. If it carries public coordinates they must match `d`.
    pub fn from_jwk(jwk: &Jwk) -> Result<Self> {
        let curve = Curve::from_jwk_crv(&jwk.crv)?;
        let d = jwk
            .d
            .as_deref()
            .ok_or_else(|| Error::invalid_key("JWK without d"))?;
        let key = Self::from_bytes(curve, &Zeroizing::new(b64::decode(d)?))?;
        let public = key.public_key().to_jwk();
        if public.x != jwk.x || (jwk.y.is_some() && public.y != jwk.y) {
            return Err(Error::invalid_key("JWK public part does not match d"));
        }
        Ok(key)
    }

    /// Private JWK (with `d`), without `kid`.
    pub fn to_jwk(&self) -> Jwk {
        Jwk {
            d: Some(b64::encode(self.to_bytes())),
            ..self.public_key().to_jwk()
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Ed25519(k) => PublicKey::Ed25519(k.verifying_key()),
            Self::X25519(k) => PublicKey::X25519(x25519_dalek::PublicKey::from(k)),
            Self::P256(k) => PublicKey::P256(k.public_key()),
            Self::P384(k) => PublicKey::P384(k.public_key()),
            Self::P521(k) => PublicKey::P521(k.public_key()),
            Self::Secp256k1(k) => PublicKey::Secp256k1(k.public_key()),
        }
    }

    /// Signs `message` with the algorithm this key's curve implies (see
    /// [`Curve::signature_alg`]). ECDSA signatures are deterministic (RFC 6979)
    /// and returned as the JOSE fixed-size `r || s`.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::signature::Signer;

        let failed = |_| Error::Crypto("signing");
        match self {
            Self::Ed25519(key) => {
                let signature: ed25519_dalek::Signature = key.try_sign(message).map_err(failed)?;
                Ok(signature.to_bytes().to_vec())
            }
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature = p256::ecdsa::SigningKey::from(key)
                    .try_sign(message)
                    .map_err(failed)?;
                Ok(signature.to_bytes().to_vec())
            }
            Self::Secp256k1(key) => {
                let signature: k256::ecdsa::Signature = k256::ecdsa::SigningKey::from(key)
                    .try_sign(message)
                    .map_err(failed)?;
                Ok(signature.to_bytes().to_vec())
            }
            Self::X25519(_) | Self::P384(_) | Self::P521(_) => Err(Error::unsupported(format!(
                "signatures with {}",
                self.curve().jwk_crv()
            ))),
        }
    }

    /// Raw ECDH shared secret (`Z`) with `public`, which must be on the same
    /// curve. Low-order X25519 points, which give an all-zero secret, are rejected.
    pub(crate) fn diffie_hellman(&self, public: &PublicKey) -> Result<Zeroizing<Vec<u8>>> {
        let secret = match (self, public) {
            (Self::X25519(sk), PublicKey::X25519(pk)) => {
                let shared = sk.diffie_hellman(pk);
                if !shared.was_contributory() {
                    return Err(Error::invalid_key("low-order X25519 public key"));
                }
                shared.as_bytes().to_vec()
            }
            (Self::P256(sk), PublicKey::P256(pk)) => {
                sk.diffie_hellman(pk).raw_secret_bytes().to_vec()
            }
            (Self::P384(sk), PublicKey::P384(pk)) => {
                sk.diffie_hellman(pk).raw_secret_bytes().to_vec()
            }
            (Self::P521(sk), PublicKey::P521(pk)) => {
                sk.diffie_hellman(pk).raw_secret_bytes().to_vec()
            }
            _ => {
                return Err(Error::unsupported(format!(
                    "key agreement between {} and {}",
                    self.curve().jwk_crv(),
                    public.curve().jwk_crv()
                )));
            }
        };
        Ok(Zeroizing::new(secret))
    }
}

/// Fills `buf` from the operating system's CSPRNG.
pub(crate) fn random_fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Crypto("random number generator"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Curve; 6] = [
        Curve::Ed25519,
        Curve::X25519,
        Curve::P256,
        Curve::P384,
        Curve::P521,
        Curve::Secp256k1,
    ];

    #[test]
    fn jwk_round_trips_on_every_curve() {
        for curve in ALL {
            let secret = SecretKey::generate(curve).unwrap();
            let public = secret.public_key();
            assert_eq!(PublicKey::from_jwk(&public.to_jwk()).unwrap(), public);
            let again = SecretKey::from_jwk(&secret.to_jwk()).unwrap();
            assert_eq!(again.public_key(), public, "{curve:?}");
        }
    }

    #[test]
    fn raw_bytes_round_trip_on_every_curve() {
        for curve in ALL {
            let public = SecretKey::generate(curve).unwrap().public_key();
            assert_eq!(
                PublicKey::from_bytes(curve, &public.to_bytes()).unwrap(),
                public
            );
        }
    }

    #[test]
    fn sign_and_verify() {
        for curve in [Curve::Ed25519, Curve::P256, Curve::Secp256k1] {
            let secret = SecretKey::generate(curve).unwrap();
            let signature = secret.sign(b"hello").unwrap();
            secret.public_key().verify(b"hello", &signature).unwrap();
            assert!(secret.public_key().verify(b"hellO", &signature).is_err());
        }
    }

    #[test]
    fn ecdh_agrees_on_every_key_agreement_curve() {
        for curve in [Curve::X25519, Curve::P256, Curve::P384, Curve::P521] {
            let a = SecretKey::generate(curve).unwrap();
            let b = SecretKey::generate(curve).unwrap();
            assert_eq!(
                *a.diffie_hellman(&b.public_key()).unwrap(),
                *b.diffie_hellman(&a.public_key()).unwrap()
            );
        }
    }

    #[test]
    fn ecdh_rejects_mixed_curves() {
        let a = SecretKey::generate(Curve::X25519).unwrap();
        let b = SecretKey::generate(Curve::P256).unwrap();
        assert!(a.diffie_hellman(&b.public_key()).is_err());
    }

    #[test]
    fn ec_jwk_off_curve_is_rejected() {
        let mut jwk = SecretKey::generate(Curve::P256)
            .unwrap()
            .public_key()
            .to_jwk();
        jwk.y = Some(jwk.x.clone());
        assert!(PublicKey::from_jwk(&jwk).is_err());
    }

    #[test]
    fn debug_never_shows_private_material() {
        let secret = SecretKey::generate(Curve::Ed25519).unwrap();
        let d = secret.to_jwk().d.unwrap();
        assert!(!format!("{secret:?} {:?}", secret.to_jwk()).contains(&d));
    }
}
