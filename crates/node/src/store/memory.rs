//! In-process [`Store`]: everything is lost on restart. For tests and local
//! development only.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Mutex;

use anyhow::{Result, anyhow};
use async_trait::async_trait;

use super::{AddRecipient, QueueLimits, QueueSummary, Queued, RemoveRecipient, Store, id_millis};

#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    mediations: HashSet<String>,
    /// Recipient DID → mediation.
    owners: HashMap<String, String>,
    recipients: HashMap<String, BTreeSet<String>>,
    queues: HashMap<String, Vec<Queued>>,
    /// Key → (window, hits).
    hits: HashMap<String, (u64, u64)>,
    seq: u64,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| anyhow!("memory store poisoned"))
    }
}

impl Inner {
    /// The mediation's queue with expired messages dropped.
    fn queue(&mut self, mediation: &str, now: u64, ttl_secs: u64) -> &mut Vec<Queued> {
        let queue = self.queues.entry(mediation.to_owned()).or_default();
        let cutoff = now.saturating_sub(ttl_secs);
        queue.retain(|q| q.received >= cutoff);
        queue
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn ping(&self) -> Result<()> {
        self.lock().map(|_| ())
    }

    fn kind(&self) -> &'static str {
        "memory"
    }

    async fn grant_mediation(&self, mediation: &str, _now: u64) -> Result<()> {
        self.lock()?.mediations.insert(mediation.to_owned());
        Ok(())
    }

    async fn has_mediation(&self, mediation: &str) -> Result<bool> {
        Ok(self.lock()?.mediations.contains(mediation))
    }

    async fn add_recipient(
        &self,
        mediation: &str,
        recipient: &str,
        max: usize,
    ) -> Result<AddRecipient> {
        let mut inner = self.lock()?;
        match inner.owners.get(recipient) {
            Some(owner) if owner == mediation => return Ok(AddRecipient::AlreadyYours),
            Some(_) => return Ok(AddRecipient::TakenByOther),
            None => {}
        }
        let set = inner.recipients.entry(mediation.to_owned()).or_default();
        if set.len() >= max {
            return Ok(AddRecipient::LimitReached);
        }
        set.insert(recipient.to_owned());
        inner
            .owners
            .insert(recipient.to_owned(), mediation.to_owned());
        Ok(AddRecipient::Added)
    }

    async fn remove_recipient(&self, mediation: &str, recipient: &str) -> Result<RemoveRecipient> {
        let mut inner = self.lock()?;
        match inner.owners.get(recipient) {
            None => Ok(RemoveRecipient::NotRegistered),
            Some(owner) if owner != mediation => Ok(RemoveRecipient::NotYours),
            Some(_) => {
                inner.owners.remove(recipient);
                if let Some(set) = inner.recipients.get_mut(mediation) {
                    set.remove(recipient);
                }
                Ok(RemoveRecipient::Removed)
            }
        }
    }

    async fn recipients(&self, mediation: &str) -> Result<Vec<String>> {
        Ok(self
            .lock()?
            .recipients
            .get(mediation)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default())
    }

    async fn mediation_of(&self, recipient: &str) -> Result<Option<String>> {
        Ok(self.lock()?.owners.get(recipient).cloned())
    }

    async fn enqueue(
        &self,
        mediation: &str,
        recipient: &str,
        message: &str,
        now: u64,
        limits: QueueLimits,
    ) -> Result<Option<String>> {
        let mut inner = self.lock()?;
        inner.seq += 1;
        let id = format!("{}-{}", now * 1000, inner.seq);
        let queue = inner.queue(mediation, now, limits.ttl_secs);
        if queue.len() >= limits.max_messages {
            return Ok(None);
        }
        queue.push(Queued {
            id: id.clone(),
            recipient: recipient.to_owned(),
            received: id_millis(&id) / 1000,
            message: message.to_owned(),
        });
        Ok(Some(id))
    }

    async fn summary(
        &self,
        mediation: &str,
        recipient: Option<&str>,
        now: u64,
        ttl_secs: u64,
    ) -> Result<QueueSummary> {
        let mut inner = self.lock()?;
        let mut summary = QueueSummary::default();
        for q in inner
            .queue(mediation, now, ttl_secs)
            .iter()
            .filter(|q| recipient.is_none_or(|r| q.recipient == r))
        {
            summary.count += 1;
            summary.total_bytes += q.message.len() as u64;
            summary.oldest = Some(summary.oldest.map_or(q.received, |o| o.min(q.received)));
            summary.newest = Some(summary.newest.map_or(q.received, |n| n.max(q.received)));
        }
        Ok(summary)
    }

    async fn peek(
        &self,
        mediation: &str,
        recipient: Option<&str>,
        limit: usize,
        now: u64,
        ttl_secs: u64,
    ) -> Result<Vec<Queued>> {
        let mut inner = self.lock()?;
        Ok(inner
            .queue(mediation, now, ttl_secs)
            .iter()
            .filter(|q| recipient.is_none_or(|r| q.recipient == r))
            .take(limit)
            .cloned()
            .collect())
    }

    async fn remove(&self, mediation: &str, ids: &[String]) -> Result<usize> {
        let mut inner = self.lock()?;
        let Some(queue) = inner.queues.get_mut(mediation) else {
            return Ok(0);
        };
        let before = queue.len();
        queue.retain(|q| !ids.contains(&q.id));
        Ok(before - queue.len())
    }

    async fn hit(&self, key: &str, window_secs: u64, now: u64) -> Result<u64> {
        let window = now / window_secs.max(1);
        let mut inner = self.lock()?;
        if inner.hits.len() > 100_000 {
            inner.hits.retain(|_, (w, _)| *w == window);
        }
        let entry = inner.hits.entry(key.to_owned()).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 += 1;
        Ok(entry.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn contract() {
        super::super::contract::run(&MemoryStore::new()).await;
    }

    #[tokio::test]
    async fn expired_messages_disappear() {
        let store = MemoryStore::new();
        let limits = QueueLimits {
            ttl_secs: 60,
            max_messages: 10,
        };
        store.enqueue("m", "r", "old", 1_000, limits).await.unwrap();
        store.enqueue("m", "r", "new", 1_050, limits).await.unwrap();
        let left = store.peek("m", None, 10, 1_070, 60).await.unwrap();
        assert_eq!(
            left.iter().map(|q| q.message.as_str()).collect::<Vec<_>>(),
            ["new"]
        );
    }
}
