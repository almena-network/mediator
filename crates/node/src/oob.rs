//! Out-of-Band 2.0 invitation to use this node as a mediator.
//!
//! A wallet that scans the invitation (as a URL or QR code) learns the node's
//! DID, resolves it, and sends `mediate-request` with the invitation `id` as
//! `pthid`. The invitation is the same on every request and across restarts:
//! its `id` derives from the node's DID, so a printed QR code keeps working.

use almena_didcomm::{Message, b64};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::identity::Identity;

pub const INVITATION: &str = "https://didcomm.org/out-of-band/2.0/invitation";
/// Path of the human-readable page the invitation URL points at.
pub const OOB_PATH: &str = "/oob";
/// Goal code of the node's invitation.
pub const GOAL_CODE: &str = "request-mediate";

/// The node's mediation invitation.
pub fn invitation(identity: &Identity) -> Message {
    let digest = Sha256::digest(identity.did.as_bytes());
    let id: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    let mut message = Message::new(
        INVITATION,
        json!({
            "goal_code": GOAL_CODE,
            "goal": "Use this node as your DIDComm mediator",
            "accept": ["didcomm/v2"],
        }),
    )
    .from(&identity.did);
    message.id = id;
    message.created_time = None;
    message
}

/// The invitation as a URL: `<origin>/oob?_oob=<base64url(JSON)>`.
pub fn invitation_url(public_url: &str, invitation: &Message) -> String {
    // Serialising a Message cannot fail: it is plain JSON data.
    let json = serde_json::to_string(invitation).unwrap_or_default();
    format!("{public_url}{OOB_PATH}?_oob={}", b64::encode(json))
}

/// The page shown when someone opens the invitation URL in a browser.
pub fn page(did: &str, url: &str) -> String {
    let escape = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Almena node</title>
<style>body{{font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5}}code{{word-break:break-all}}</style></head>
<body>
<h1>Almena node</h1>
<p>This is an invitation to use this node as your mediator on Almena Network.
Open it with the Almena wallet: scan it as a QR code or paste this link into the app.</p>
<p><a href="{url}">Invitation link</a></p>
<p>Node DID: <code>{did}</code></p>
</body></html>
"#,
        url = escape(url),
        did = escape(did),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_is_stable_and_round_trips_through_the_url() {
        let identity = Identity::ephemeral("https://node.example.com").unwrap();
        let first = invitation(&identity);
        assert_eq!(first, invitation(&identity));
        assert_eq!(first.id.len(), 32);
        assert_eq!(first.from.as_deref(), Some("did:web:node.example.com"));

        let url = invitation_url("https://node.example.com", &first);
        let encoded = url.split_once("?_oob=").unwrap().1;
        let decoded: Message = serde_json::from_slice(&b64::decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, first);
    }

    #[test]
    fn page_escapes_html() {
        assert!(page("did:x", "https://x/?a=1&b=<2>").contains("a=1&amp;b=&lt;2&gt;"));
    }
}
