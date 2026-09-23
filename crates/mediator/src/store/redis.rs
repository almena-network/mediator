//! Redis [`Store`].
//!
//! Keys (`M` = mediation DID, `R` = recipient DID):
//!
//! | Key | Type | Holds |
//! |---|---|---|
//! | `mediation:{M}` | string | Grant time (epoch seconds) |
//! | `mediation:{M}:recipients` | set | Recipient DIDs registered by `M` |
//! | `recipient:{R}` | string | The mediation that registered `R` |
//! | `mediation:{M}:queue` | stream | One entry per queued message: `r` recipient, `s` size in bytes |
//! | `mediation:{M}:msg:{id}` | string | Body of queue entry `id`, expiring with the queue TTL |
//! | `rate:{key}:{window}` | string | Hit counter of one rate-limit window |
//!
//! Bodies live outside the stream so that status queries read only the small
//! entries. Multi-key updates run as Lua scripts, so they are atomic.

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use redis::streams::StreamRangeReply;

use super::{
    AddRecipient, QueueLimits, QueueSummary, Queued, RemoveRecipient, Store, id_millis, is_queue_id,
};

const ADD_RECIPIENT: &str = r"
local owner = redis.call('GET', KEYS[1])
if owner == ARGV[1] then return 'mine' end
if owner then return 'taken' end
if redis.call('SCARD', KEYS[2]) >= tonumber(ARGV[3]) then return 'limit' end
redis.call('SET', KEYS[1], ARGV[1])
redis.call('SADD', KEYS[2], ARGV[2])
return 'added'
";

const REMOVE_RECIPIENT: &str = r"
local owner = redis.call('GET', KEYS[1])
if not owner then return 'none' end
if owner ~= ARGV[1] then return 'theirs' end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[2])
return 'removed'
";

/// KEYS[1] queue; ARGV: min id, max messages, recipient, size, body, ttl, body key prefix.
const ENQUEUE: &str = r"
redis.call('XTRIM', KEYS[1], 'MINID', ARGV[1])
if redis.call('XLEN', KEYS[1]) >= tonumber(ARGV[2]) then return false end
local id = redis.call('XADD', KEYS[1], '*', 'r', ARGV[3], 's', ARGV[4])
redis.call('SET', ARGV[7] .. id, ARGV[5], 'EX', ARGV[6])
redis.call('EXPIRE', KEYS[1], ARGV[6])
return id
";

pub struct RedisStore {
    conn: ConnectionManager,
}

impl RedisStore {
    /// Connects to `url`. Fails if Redis cannot be reached at start-up.
    pub async fn connect(url: &str) -> Result<Self> {
        let client =
            redis::Client::open(url).with_context(|| format!("invalid Redis URL {url}"))?;
        let conn = ConnectionManager::new(client)
            .await
            .with_context(|| format!("connecting to Redis at {url}"))?;
        Ok(Self { conn })
    }

    fn conn(&self) -> ConnectionManager {
        self.conn.clone()
    }

    /// Drops expired entries, then returns the queue's entries (without bodies).
    async fn entries(
        &self,
        mediation: &str,
        now: u64,
        ttl_secs: u64,
    ) -> Result<Vec<(String, String, u64)>> {
        let key = queue_key(mediation);
        let mut conn = self.conn();
        let _: () = redis::cmd("XTRIM")
            .arg(&key)
            .arg("MINID")
            .arg(min_id(now, ttl_secs))
            .query_async(&mut conn)
            .await?;
        let reply: StreamRangeReply = conn.xrange_all(&key).await?;
        Ok(reply
            .ids
            .into_iter()
            .map(|entry| {
                let recipient = entry.get::<String>("r").unwrap_or_default();
                let size = entry.get::<u64>("s").unwrap_or_default();
                (entry.id, recipient, size)
            })
            .collect())
    }
}

fn mediation_key(mediation: &str) -> String {
    format!("mediation:{mediation}")
}

fn recipients_key(mediation: &str) -> String {
    format!("mediation:{mediation}:recipients")
}

fn recipient_key(recipient: &str) -> String {
    format!("recipient:{recipient}")
}

fn queue_key(mediation: &str) -> String {
    format!("mediation:{mediation}:queue")
}

fn body_prefix(mediation: &str) -> String {
    format!("mediation:{mediation}:msg:")
}

/// Stream id below which entries are older than the TTL.
fn min_id(now: u64, ttl_secs: u64) -> String {
    format!("{}-0", now.saturating_sub(ttl_secs) * 1000)
}

#[async_trait]
impl Store for RedisStore {
    async fn ping(&self) -> Result<()> {
        let _: String = redis::cmd("PING").query_async(&mut self.conn()).await?;
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "redis"
    }

    async fn grant_mediation(&self, mediation: &str, now: u64) -> Result<()> {
        let _: bool = redis::cmd("SET")
            .arg(mediation_key(mediation))
            .arg(now)
            .arg("NX")
            .query_async(&mut self.conn())
            .await
            .map(|reply: Option<String>| reply.is_some())?;
        Ok(())
    }

    async fn has_mediation(&self, mediation: &str) -> Result<bool> {
        Ok(self.conn().exists(mediation_key(mediation)).await?)
    }

    async fn add_recipient(
        &self,
        mediation: &str,
        recipient: &str,
        max: usize,
    ) -> Result<AddRecipient> {
        let result: String = redis::Script::new(ADD_RECIPIENT)
            .key(recipient_key(recipient))
            .key(recipients_key(mediation))
            .arg(mediation)
            .arg(recipient)
            .arg(max)
            .invoke_async(&mut self.conn())
            .await?;
        Ok(match result.as_str() {
            "added" => AddRecipient::Added,
            "mine" => AddRecipient::AlreadyYours,
            "taken" => AddRecipient::TakenByOther,
            "limit" => AddRecipient::LimitReached,
            other => bail!("unexpected add-recipient result {other}"),
        })
    }

    async fn remove_recipient(&self, mediation: &str, recipient: &str) -> Result<RemoveRecipient> {
        let result: String = redis::Script::new(REMOVE_RECIPIENT)
            .key(recipient_key(recipient))
            .key(recipients_key(mediation))
            .arg(mediation)
            .arg(recipient)
            .invoke_async(&mut self.conn())
            .await?;
        Ok(match result.as_str() {
            "removed" => RemoveRecipient::Removed,
            "none" => RemoveRecipient::NotRegistered,
            "theirs" => RemoveRecipient::NotYours,
            other => bail!("unexpected remove-recipient result {other}"),
        })
    }

    async fn recipients(&self, mediation: &str) -> Result<Vec<String>> {
        let set: std::collections::HashSet<String> =
            self.conn().smembers(recipients_key(mediation)).await?;
        let mut list: Vec<String> = set.into_iter().collect();
        list.sort();
        Ok(list)
    }

    async fn mediation_of(&self, recipient: &str) -> Result<Option<String>> {
        Ok(self.conn().get(recipient_key(recipient)).await?)
    }

    async fn enqueue(
        &self,
        mediation: &str,
        recipient: &str,
        message: &str,
        now: u64,
        limits: QueueLimits,
    ) -> Result<Option<String>> {
        Ok(redis::Script::new(ENQUEUE)
            .key(queue_key(mediation))
            .arg(min_id(now, limits.ttl_secs))
            .arg(limits.max_messages)
            .arg(recipient)
            .arg(message.len())
            .arg(message)
            .arg(limits.ttl_secs.max(1))
            .arg(body_prefix(mediation))
            .invoke_async(&mut self.conn())
            .await?)
    }

    async fn summary(
        &self,
        mediation: &str,
        recipient: Option<&str>,
        now: u64,
        ttl_secs: u64,
    ) -> Result<QueueSummary> {
        let mut summary = QueueSummary::default();
        for (id, r, size) in self.entries(mediation, now, ttl_secs).await? {
            if recipient.is_some_and(|want| want != r) {
                continue;
            }
            let received = id_millis(&id) / 1000;
            summary.count += 1;
            summary.total_bytes += size;
            summary.oldest = Some(summary.oldest.map_or(received, |o| o.min(received)));
            summary.newest = Some(summary.newest.map_or(received, |n| n.max(received)));
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
        let entries: Vec<_> = self
            .entries(mediation, now, ttl_secs)
            .await?
            .into_iter()
            .filter(|(_, r, _)| recipient.is_none_or(|want| want == r))
            .take(limit)
            .collect();
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let prefix = body_prefix(mediation);
        let keys: Vec<String> = entries
            .iter()
            .map(|(id, _, _)| format!("{prefix}{id}"))
            .collect();
        let bodies: Vec<Option<String>> = self.conn().mget(&keys).await?;

        let mut queued = Vec::with_capacity(entries.len());
        let mut orphans = Vec::new();
        for ((id, recipient, _), body) in entries.into_iter().zip(bodies) {
            match body {
                Some(message) => queued.push(Queued {
                    received: id_millis(&id) / 1000,
                    id,
                    recipient,
                    message,
                }),
                // The body expired before its entry was trimmed.
                None => orphans.push(id),
            }
        }
        if !orphans.is_empty() {
            self.remove(mediation, &orphans).await?;
        }
        Ok(queued)
    }

    async fn remove(&self, mediation: &str, ids: &[String]) -> Result<usize> {
        let ids: Vec<&String> = ids.iter().filter(|id| is_queue_id(id)).collect();
        if ids.is_empty() {
            return Ok(0);
        }
        let prefix = body_prefix(mediation);
        let mut conn = self.conn();
        let removed: usize = conn.xdel(queue_key(mediation), &ids).await?;
        let keys: Vec<String> = ids.iter().map(|id| format!("{prefix}{id}")).collect();
        let _: usize = conn.del(&keys).await?;
        Ok(removed)
    }

    async fn hit(&self, key: &str, window_secs: u64, now: u64) -> Result<u64> {
        let window_secs = window_secs.max(1);
        let key = format!("rate:{key}:{}", now / window_secs);
        let (hits,): (u64,) = redis::pipe()
            .atomic()
            .incr(&key, 1)
            .expire(&key, i64::try_from(window_secs).unwrap_or(i64::MAX))
            .ignore()
            .query_async(&mut self.conn())
            .await?;
        Ok(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs against a real Redis when `ALMENA_TEST_REDIS_URL` is set
    /// (e.g. `redis://127.0.0.1:6379` after `task redis`); skipped otherwise.
    #[tokio::test]
    async fn contract() {
        let Ok(url) = std::env::var("ALMENA_TEST_REDIS_URL") else {
            eprintln!("ALMENA_TEST_REDIS_URL not set; skipping the Redis store test");
            return;
        };
        let store = RedisStore::connect(&url).await.unwrap();
        super::super::contract::run(&store).await;
    }
}
