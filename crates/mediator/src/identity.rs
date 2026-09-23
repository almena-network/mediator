//! The mediator's own DIDComm identity: the `did:web` of its public origin, its
//! keys and the DID document it serves at `/.well-known/did.json`.

use std::fs;
use std::io::Write;
use std::path::Path;

use almena_didcomm::did::web::did_from_origin;
use almena_didcomm::did::{DidDocument, Service, VerificationMethod};
use almena_didcomm::{Curve, InMemorySecrets, Jwk, SecretKey};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Path of the DIDComm endpoint, relative to the public origin.
pub const DIDCOMM_PATH: &str = "/didcomm";
/// Path of the DIDComm WebSocket endpoint, relative to the public origin.
pub const WS_PATH: &str = "/ws";

/// On-disk form of the mediator's private keys.
#[derive(Serialize, Deserialize)]
struct KeyFile {
    /// Signing (`authentication`).
    ed25519: Jwk,
    /// Key agreement.
    x25519: Jwk,
    /// Key agreement, for peers that do not do X25519.
    p384: Jwk,
}

struct Keys {
    ed25519: SecretKey,
    x25519: SecretKey,
    p384: SecretKey,
}

impl Keys {
    fn generate() -> Result<Self> {
        Ok(Self {
            ed25519: SecretKey::generate(Curve::Ed25519)?,
            x25519: SecretKey::generate(Curve::X25519)?,
            p384: SecretKey::generate(Curve::P384)?,
        })
    }

    fn read(path: &Path) -> Result<Self> {
        let file: KeyFile = serde_json::from_slice(&fs::read(path)?)?;
        let key = |jwk: &Jwk, curve: Curve| -> Result<SecretKey> {
            let key = SecretKey::from_jwk(jwk)?;
            anyhow::ensure!(key.curve() == curve, "expected a {} key", curve.jwk_crv());
            Ok(key)
        };
        Ok(Self {
            ed25519: key(&file.ed25519, Curve::Ed25519)?,
            x25519: key(&file.x25519, Curve::X25519)?,
            p384: key(&file.p384, Curve::P384)?,
        })
    }

    /// Writes the key file readable by the owner only, via a temporary file
    /// so a crash never leaves a half-written file behind.
    fn write(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir)?;
        }
        let file = KeyFile {
            ed25519: self.ed25519.to_jwk(),
            x25519: self.x25519.to_jwk(),
            p384: self.p384.to_jwk(),
        };
        let tmp = path.with_extension("tmp");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options
            .open(&tmp)?
            .write_all(&serde_json::to_vec_pretty(&file)?)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// The mediator's DID, DID document and private keys.
pub struct Identity {
    pub did: String,
    pub document: DidDocument,
    secrets: InMemorySecrets,
}

impl Identity {
    /// Loads the keys from `path`, or generates and saves new ones if the file
    /// does not exist.
    pub fn load_or_create(path: &Path, public_url: &str) -> Result<Self> {
        let keys = if path.exists() {
            Keys::read(path)
                .with_context(|| format!("reading mediator keys from {}", path.display()))?
        } else {
            let keys = Keys::generate()?;
            keys.write(path)
                .with_context(|| format!("writing mediator keys to {}", path.display()))?;
            tracing::info!(path = %path.display(), "generated new mediator keys");
            keys
        };
        Self::new(keys, public_url)
    }

    /// Replaces the keys in `path` with fresh ones (`almena-mediator
    /// rotate-keys`). The DID stays; its key ids now name the new keys, so
    /// whatever was encrypted to the old ones stops opening at once. A
    /// running mediator keeps the old keys until it restarts.
    pub fn rotate(path: &Path) -> Result<()> {
        anyhow::ensure!(
            path.exists(),
            "no mediator keys at {} to rotate",
            path.display()
        );
        Keys::generate()?
            .write(path)
            .with_context(|| format!("writing mediator keys to {}", path.display()))
    }

    /// An identity with fresh keys that are not saved anywhere.
    pub fn ephemeral(public_url: &str) -> Result<Self> {
        Self::new(Keys::generate()?, public_url)
    }

    fn new(keys: Keys, public_url: &str) -> Result<Self> {
        let did = did_from_origin(public_url)?;
        let kid = |fragment: &str| format!("{did}#{fragment}");
        let method = |fragment: &str, key: &SecretKey| VerificationMethod {
            id: kid(fragment),
            controller: did.clone(),
            key: key.public_key(),
        };

        let document = DidDocument {
            id: did.clone(),
            verification_method: vec![
                method("key-ed25519", &keys.ed25519),
                method("key-x25519", &keys.x25519),
                method("key-p384", &keys.p384),
            ],
            authentication: vec![kid("key-ed25519")],
            assertion_method: vec![kid("key-ed25519")],
            key_agreement: vec![kid("key-x25519"), kid("key-p384")],
            service: vec![Service {
                id: kid("didcomm"),
                kind: "DIDCommMessaging".to_owned(),
                endpoint: json!([
                    {
                        "uri": format!("{public_url}{DIDCOMM_PATH}"),
                        "accept": ["didcomm/v2"],
                    },
                    {
                        // https → wss, http → ws
                        "uri": format!("ws{}{WS_PATH}", public_url.trim_start_matches("http")),
                        "accept": ["didcomm/v2"],
                    }
                ]),
            }],
            ..DidDocument::default()
        };

        let mut secrets = InMemorySecrets::new();
        secrets.insert(kid("key-ed25519"), keys.ed25519);
        secrets.insert(kid("key-x25519"), keys.x25519);
        secrets.insert(kid("key-p384"), keys.p384);
        Ok(Self {
            did,
            document,
            secrets,
        })
    }

    pub fn secrets(&self) -> &InMemorySecrets {
        &self.secrets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_created_once_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/keys.json");
        let first = Identity::load_or_create(&path, "https://mediator.example.com").unwrap();
        let second = Identity::load_or_create(&path, "https://mediator.example.com").unwrap();
        assert_eq!(first.document, second.document);
        assert_eq!(first.did, "did:web:mediator.example.com");
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        Identity::load_or_create(&path, "https://mediator.example.com").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn document_advertises_the_didcomm_endpoint_and_keys() {
        let identity = Identity::ephemeral("http://localhost:8080").unwrap();
        let doc = &identity.document;
        assert_eq!(doc.id, "did:web:localhost%3A8080");
        assert_eq!(doc.key_agreement.len(), 2);
        let endpoints = doc.service[0].didcomm_endpoints().unwrap();
        assert_eq!(endpoints[0].uri, "http://localhost:8080/didcomm");
        assert_eq!(endpoints[0].accept, ["didcomm/v2"]);
        assert_eq!(endpoints[1].uri, "ws://localhost:8080/ws");
    }

    #[test]
    fn rotation_replaces_every_key_and_keeps_the_did() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        assert!(Identity::rotate(&path).is_err(), "nothing to rotate yet");
        let before = Identity::load_or_create(&path, "https://mediator.example.com").unwrap();
        Identity::rotate(&path).unwrap();
        let after = Identity::load_or_create(&path, "https://mediator.example.com").unwrap();
        assert_eq!(before.did, after.did);
        for (old, new) in before
            .document
            .verification_method
            .iter()
            .zip(&after.document.verification_method)
        {
            assert_eq!(old.id, new.id);
            assert_ne!(old.key, new.key, "{} was not rotated", old.id);
        }
    }

    #[test]
    fn a_corrupt_key_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        fs::write(&path, "{}").unwrap();
        assert!(Identity::load_or_create(&path, "https://mediator.example.com").is_err());
    }
}
