//! Mediation state and message queues.
//!
//! [`Store`] is what the mediator needs from storage. Production uses Redis
//! ([`RedisStore`]); [`MemoryStore`] keeps everything in the process, for
//! tests and for `ALMENA_REDIS_URL=memory://` during development.
//!
//! A *mediation* is keyed by the DID the wallet used to request it. It owns a
//! set of recipient DIDs (the ones `forward` messages may name as `next`) and
//! one queue holding the messages for all of them, oldest first. Queue ids
//! look like Redis stream ids (`<ms>-<seq>`) and are the attachment ids of
//! Message Pickup deliveries.

mod memory;
mod redis;

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

pub use self::memory::MemoryStore;
pub use self::redis::RedisStore;

/// Result of registering a recipient DID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddRecipient {
    Added,
    /// Already registered by this mediation.
    AlreadyYours,
    /// Registered by another mediation.
    TakenByOther,
    /// The mediation has as many recipient DIDs as it may.
    LimitReached,
}

/// Result of removing a recipient DID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveRecipient {
    Removed,
    NotRegistered,
    /// Registered by another mediation.
    NotYours,
}

/// A queued message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queued {
    pub id: String,
    pub recipient: String,
    /// Epoch seconds.
    pub received: u64,
    pub message: String,
}

/// Counts over a queue (or the part of it for one recipient).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueSummary {
    pub count: usize,
    /// Epoch seconds of the oldest and newest message.
    pub oldest: Option<u64>,
    pub newest: Option<u64>,
    pub total_bytes: u64,
}

/// Queue limits, from the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueLimits {
    /// Messages older than this (seconds) are dropped.
    pub ttl_secs: u64,
    /// Per mediation.
    pub max_messages: usize,
}

#[async_trait]
pub trait Store: Send + Sync {
    /// Checks the store is reachable.
    async fn ping(&self) -> Result<()>;
    /// `"redis"` or `"memory"`, for logs.
    fn kind(&self) -> &'static str;

    /// Records a granted mediation (idempotent).
    async fn grant_mediation(&self, mediation: &str, now: u64) -> Result<()>;
    async fn has_mediation(&self, mediation: &str) -> Result<bool>;

    /// Registers `recipient` for `mediation`, first come first served.
    async fn add_recipient(
        &self,
        mediation: &str,
        recipient: &str,
        max: usize,
    ) -> Result<AddRecipient>;
    /// Unregisters `recipient`. Its queued messages stay until picked up or expired.
    async fn remove_recipient(&self, mediation: &str, recipient: &str) -> Result<RemoveRecipient>;
    /// The mediation's recipient DIDs, sorted.
    async fn recipients(&self, mediation: &str) -> Result<Vec<String>>;
    /// The mediation that registered `recipient`, if any.
    async fn mediation_of(&self, recipient: &str) -> Result<Option<String>>;

    /// Appends a message to the mediation's queue. `None` when the queue is full.
    async fn enqueue(
        &self,
        mediation: &str,
        recipient: &str,
        message: &str,
        now: u64,
        limits: QueueLimits,
    ) -> Result<Option<String>>;
    /// Counts over the queue, or over `recipient`'s messages in it.
    async fn summary(
        &self,
        mediation: &str,
        recipient: Option<&str>,
        now: u64,
        ttl_secs: u64,
    ) -> Result<QueueSummary>;
    /// Up to `limit` messages, oldest first, without removing them.
    async fn peek(
        &self,
        mediation: &str,
        recipient: Option<&str>,
        limit: usize,
        now: u64,
        ttl_secs: u64,
    ) -> Result<Vec<Queued>>;
    /// Removes messages by id; unknown ids are ignored. Returns how many went.
    async fn remove(&self, mediation: &str, ids: &[String]) -> Result<usize>;

    /// Counts a hit on `key` in the current fixed window of `window_secs`
    /// and returns the hits in that window so far.
    async fn hit(&self, key: &str, window_secs: u64, now: u64) -> Result<u64>;
}

/// Opens the store named by `url`: `memory://` for the in-process store,
/// anything else is a Redis URL.
pub async fn open(url: &str) -> Result<Arc<dyn Store>> {
    if url == "memory://" {
        Ok(Arc::new(MemoryStore::new()))
    } else {
        Ok(Arc::new(RedisStore::connect(url).await?))
    }
}

/// Whether `id` has the `<ms>-<seq>` shape of a queue id.
fn is_queue_id(id: &str) -> bool {
    id.split_once('-').is_some_and(|(ms, seq)| {
        !ms.is_empty()
            && !seq.is_empty()
            && ms.bytes().chain(seq.bytes()).all(|b| b.is_ascii_digit())
    })
}

/// Epoch milliseconds of a queue id.
fn id_millis(id: &str) -> u64 {
    id.split_once('-')
        .and_then(|(ms, _)| ms.parse().ok())
        .unwrap_or(0)
}

/// Shared behaviour tests, run against every [`Store`] implementation.
#[cfg(test)]
pub(crate) mod contract {
    use super::*;

    const LIMITS: QueueLimits = QueueLimits {
        ttl_secs: 3600,
        max_messages: 3,
    };

    pub async fn run(store: &dyn Store) {
        // Unique names so the Redis run does not trip over earlier runs.
        let tag = uuid();
        let (m1, m2) = (format!("did:peer:m1-{tag}"), format!("did:peer:m2-{tag}"));
        let (r1, r2, r3) = (
            format!("did:peer:r1-{tag}"),
            format!("did:peer:r2-{tag}"),
            format!("did:peer:r3-{tag}"),
        );
        store.ping().await.unwrap();

        assert!(!store.has_mediation(&m1).await.unwrap());
        store.grant_mediation(&m1, 100).await.unwrap();
        store.grant_mediation(&m1, 100).await.unwrap();
        store.grant_mediation(&m2, 100).await.unwrap();
        assert!(store.has_mediation(&m1).await.unwrap());

        assert_eq!(
            store.add_recipient(&m1, &r2, 2).await.unwrap(),
            AddRecipient::Added
        );
        assert_eq!(
            store.add_recipient(&m1, &r1, 2).await.unwrap(),
            AddRecipient::Added
        );
        assert_eq!(
            store.add_recipient(&m1, &r1, 2).await.unwrap(),
            AddRecipient::AlreadyYours
        );
        assert_eq!(
            store.add_recipient(&m1, &r3, 2).await.unwrap(),
            AddRecipient::LimitReached
        );
        assert_eq!(
            store.add_recipient(&m2, &r1, 2).await.unwrap(),
            AddRecipient::TakenByOther
        );
        assert_eq!(
            store.recipients(&m1).await.unwrap(),
            [r1.clone(), r2.clone()]
        );
        assert_eq!(store.mediation_of(&r1).await.unwrap(), Some(m1.clone()));
        assert_eq!(store.mediation_of(&r3).await.unwrap(), None);

        assert_eq!(
            store.remove_recipient(&m2, &r2).await.unwrap(),
            RemoveRecipient::NotYours
        );
        assert_eq!(
            store.remove_recipient(&m1, &r3).await.unwrap(),
            RemoveRecipient::NotRegistered
        );

        let now = now_for_tests();
        let a = store
            .enqueue(&m1, &r1, "a", now - 10, LIMITS)
            .await
            .unwrap()
            .unwrap();
        let b = store
            .enqueue(&m1, &r2, "bb", now - 5, LIMITS)
            .await
            .unwrap()
            .unwrap();
        let c = store
            .enqueue(&m1, &r1, "ccc", now, LIMITS)
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .enqueue(&m1, &r1, "full", now, LIMITS)
                .await
                .unwrap()
                .is_none()
        );
        assert!(is_queue_id(&a) && is_queue_id(&b) && is_queue_id(&c));

        let all = store
            .summary(&m1, None, now, LIMITS.ttl_secs)
            .await
            .unwrap();
        assert_eq!((all.count, all.total_bytes), (3, 6));
        assert!(all.oldest <= all.newest);
        let only_r1 = store
            .summary(&m1, Some(&r1), now, LIMITS.ttl_secs)
            .await
            .unwrap();
        assert_eq!((only_r1.count, only_r1.total_bytes), (2, 4));
        assert_eq!(
            store
                .summary(&m2, None, now, LIMITS.ttl_secs)
                .await
                .unwrap()
                .count,
            0
        );

        let first_two = store
            .peek(&m1, None, 2, now, LIMITS.ttl_secs)
            .await
            .unwrap();
        let bodies: Vec<_> = first_two.iter().map(|q| q.message.as_str()).collect();
        assert_eq!(bodies, ["a", "bb"]);
        let r1_msgs = store
            .peek(&m1, Some(&r1), 10, now, LIMITS.ttl_secs)
            .await
            .unwrap();
        assert_eq!(
            r1_msgs.iter().map(|q| q.id.clone()).collect::<Vec<_>>(),
            [a.clone(), c.clone()]
        );

        // Another mediation cannot remove these; bad ids are ignored.
        assert_eq!(
            store.remove(&m2, std::slice::from_ref(&a)).await.unwrap(),
            0
        );
        let removed = store
            .remove(&m1, &[a.clone(), "bogus".into(), "1-1:x".into()])
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert_eq!(
            store
                .summary(&m1, None, now, LIMITS.ttl_secs)
                .await
                .unwrap()
                .count,
            2
        );

        assert_eq!(
            store.remove_recipient(&m1, &r1).await.unwrap(),
            RemoveRecipient::Removed
        );
        assert_eq!(store.mediation_of(&r1).await.unwrap(), None);
        assert_eq!(
            store.recipients(&m1).await.unwrap(),
            std::slice::from_ref(&r2)
        );

        let key = format!("rate-{tag}");
        assert_eq!(store.hit(&key, 60, now).await.unwrap(), 1);
        assert_eq!(store.hit(&key, 60, now).await.unwrap(), 2);
        assert_eq!(store.hit(&key, 60, now + 60).await.unwrap(), 1);
    }

    fn uuid() -> String {
        almena_didcomm::Message::new("t", serde_json::json!({})).id
    }
}

#[cfg(test)]
pub(crate) fn now_for_tests() -> u64 {
    almena_didcomm::message::now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_ids() {
        assert!(is_queue_id("1695460000000-0"));
        assert!(!is_queue_id("1695460000000"));
        assert!(!is_queue_id("a-1"));
        assert!(!is_queue_id("1-1:x"));
        assert_eq!(id_millis("1695460000000-3"), 1_695_460_000_000);
    }
}
