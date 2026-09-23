//! DIDComm plaintext messages (spec: "Plaintext Message Structure").

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{Error, Result};

/// Media type of a DIDComm plaintext message.
pub const PLAINTEXT_TYP: &str = "application/didcomm-plain+json";

/// A DIDComm plaintext message. Headers this struct does not name are kept
/// in `extra_headers` (the spec requires ignoring unknown headers, not
/// dropping them).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pthid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_time: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_time: Option<u64>,
    /// Required in v2.0, even when empty (`{}`).
    pub body: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<Attachment>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_prior: Option<String>,
    #[serde(flatten)]
    pub extra_headers: Map<String, Value>,
}

/// Seconds since the Unix epoch, as DIDComm timestamps are written.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Message {
    /// A new message with a random UUID `id` and `created_time` set to now.
    pub fn new(type_: impl Into<String>, body: Value) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            type_: type_.into(),
            typ: None,
            from: None,
            to: None,
            thid: None,
            pthid: None,
            created_time: Some(now()),
            expires_time: None,
            body,
            attachments: None,
            from_prior: None,
            extra_headers: Map::new(),
        }
    }

    pub fn from(mut self, did: impl Into<String>) -> Self {
        self.from = Some(did.into());
        self
    }

    pub fn to(mut self, dids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.to = Some(dids.into_iter().map(Into::into).collect());
        self
    }

    /// Makes this message a reply in the thread of `parent`.
    pub fn reply_to(mut self, parent: &Message) -> Self {
        self.thid = Some(parent.thid().to_owned());
        self.pthid.clone_from(&parent.pthid);
        self
    }

    pub fn attachment(mut self, attachment: Attachment) -> Self {
        self.attachments
            .get_or_insert_with(Vec::new)
            .push(attachment);
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: Value) -> Self {
        self.extra_headers.insert(name.into(), value);
        self
    }

    /// The thread id: `thid`, or `id` when absent.
    pub fn thid(&self) -> &str {
        self.thid.as_deref().unwrap_or(&self.id)
    }

    /// Whether `expires_time` has passed at `now` (epoch seconds).
    pub fn is_expired_at(&self, now: u64) -> bool {
        self.expires_time.is_some_and(|t| t <= now)
    }

    /// Structural checks from the spec: required headers, DID (not DID URL)
    /// addresses, object body and attachment rules.
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(Error::malformed("message without id"));
        }
        if self.type_.is_empty() {
            return Err(Error::malformed("message without type"));
        }
        if !self.body.is_object() {
            return Err(Error::malformed("body must be a JSON object"));
        }
        if let Some(typ) = &self.typ
            && !media_type_is(typ, PLAINTEXT_TYP)
        {
            return Err(Error::malformed(format!("plaintext with typ {typ}")));
        }
        if let Some(from) = &self.from {
            check_did(from, "from")?;
        }
        for to in self.to.iter().flatten() {
            check_did(to, "to")?;
        }
        for attachment in self.attachments.iter().flatten() {
            attachment.validate()?;
        }
        Ok(())
    }

    /// JSON with `typ` set to the plaintext media type.
    pub fn to_plaintext_json(&self) -> Result<String> {
        let mut message = self.clone();
        message.typ = Some(PLAINTEXT_TYP.to_owned());
        Ok(serde_json::to_string(&message)?)
    }
}

/// `to` and `from` hold DIDs or DID URLs without a fragment.
fn check_did(value: &str, header: &str) -> Result<()> {
    if !value.starts_with("did:") || value.contains('#') {
        return Err(Error::malformed(format!(
            "{header} must be a DID without fragment: {value}"
        )));
    }
    Ok(())
}

/// Media types may omit the `application/` prefix (spec: IANA Media Types).
pub(crate) fn media_type_is(value: &str, expected: &str) -> bool {
    value == expected || expected.strip_prefix("application/") == Some(value)
}

/// An attachment (spec: "Attachments").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lastmod_time: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_count: Option<u64>,
    pub data: AttachmentData,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AttachmentData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jws: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<Value>,
}

impl Attachment {
    /// An attachment carrying inline JSON.
    pub fn json(value: Value) -> Self {
        Self::with_data(AttachmentData {
            json: Some(value),
            ..AttachmentData::default()
        })
    }

    /// An attachment carrying inline bytes, base64url-encoded.
    pub fn base64(bytes: &[u8]) -> Self {
        Self::with_data(AttachmentData {
            base64: Some(crate::b64::encode(bytes)),
            ..AttachmentData::default()
        })
    }

    fn with_data(data: AttachmentData) -> Self {
        Self {
            id: None,
            description: None,
            filename: None,
            media_type: None,
            format: None,
            lastmod_time: None,
            byte_count: None,
            data,
        }
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn with_media_type(mut self, media_type: impl Into<String>) -> Self {
        self.media_type = Some(media_type.into());
        self
    }

    fn validate(&self) -> Result<()> {
        if let Some(id) = &self.id
            && !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
        {
            return Err(Error::malformed(
                "attachment id must be unreserved URI characters",
            ));
        }
        let data = &self.data;
        if data.jws.is_none()
            && data.hash.is_none()
            && data.links.is_none()
            && data.base64.is_none()
            && data.json.is_none()
        {
            return Err(Error::malformed("attachment without data"));
        }
        if data.links.as_ref().is_some_and(|l| !l.is_empty()) && data.hash.is_none() {
            return Err(Error::malformed("linked attachment without hash"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unknown_headers_survive_a_round_trip() {
        let json = json!({"id": "1", "type": "t", "body": {}, "return_route": "all"});
        let message: Message = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(message.extra_headers["return_route"], "all");
        assert_eq!(serde_json::to_value(&message).unwrap(), json);
    }

    #[test]
    fn missing_body_is_rejected() {
        assert!(serde_json::from_value::<Message>(json!({"id": "1", "type": "t"})).is_err());
    }

    #[test]
    fn empty_body_is_accepted() {
        let message: Message =
            serde_json::from_value(json!({"id": "1", "type": "t", "body": {}})).unwrap();
        message.validate().unwrap();
    }

    #[test]
    fn validation_rejects_did_urls_in_to() {
        let message = Message::new("t", json!({})).to(["did:example:bob#key-1"]);
        assert!(message.validate().is_err());
    }

    #[test]
    fn validation_rejects_empty_or_unhashed_link_attachments() {
        let empty = Message::new("t", json!({}))
            .attachment(Attachment::with_data(AttachmentData::default()));
        assert!(empty.validate().is_err());
        let unhashed =
            Message::new("t", json!({})).attachment(Attachment::with_data(AttachmentData {
                links: Some(vec!["https://x".into()]),
                ..AttachmentData::default()
            }));
        assert!(unhashed.validate().is_err());
    }

    #[test]
    fn replies_inherit_the_thread() {
        let first = Message::new("t", json!({}));
        let reply = Message::new("t", json!({})).reply_to(&first);
        assert_eq!(reply.thid(), first.id);
    }
}
