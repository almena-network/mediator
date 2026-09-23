//! Access to our own private keys.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::{Result, SecretKey};

/// Looks up our private keys by key id (a DID URL).
#[async_trait]
pub trait SecretsResolver: Send + Sync {
    /// `Ok(None)` when we hold no secret for `kid`.
    async fn get_secret(&self, kid: &str) -> Result<Option<SecretKey>>;
}

/// Secrets held in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemorySecrets {
    secrets: HashMap<String, SecretKey>,
}

impl InMemorySecrets {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, kid: impl Into<String>, key: SecretKey) {
        self.secrets.insert(kid.into(), key);
    }
}

#[async_trait]
impl SecretsResolver for InMemorySecrets {
    async fn get_secret(&self, kid: &str) -> Result<Option<SecretKey>> {
        Ok(self.secrets.get(kid).cloned())
    }
}
