//! `did:web` (<https://w3c-ccg.github.io/did-method-web/>): the mapping
//! between a DID and the URL of its document. Fetching the document needs
//! HTTP and is left to the caller; this crate stays transport-free.

use crate::{Error, Result};

/// The `did:web` DID of a site root, e.g. `https://node.example.com` →
/// `did:web:node.example.com`, `http://localhost:8080` →
/// `did:web:localhost%3A8080`. The URL must have no path, query or fragment,
/// because the document is then served at `/.well-known/did.json`.
pub fn did_from_origin(origin: &str) -> Result<String> {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or_else(|| Error::malformed("did:web origin must be an http(s) URL"))?;
    let host = rest.strip_suffix('/').unwrap_or(rest);
    if host.is_empty() || host.contains(['/', '?', '#', '@']) {
        return Err(Error::malformed(
            "did:web origin must be scheme://host[:port] only",
        ));
    }
    Ok(format!(
        "did:web:{}",
        host.to_ascii_lowercase().replace(':', "%3A")
    ))
}

/// The HTTPS URL of a `did:web` document.
pub fn document_url(did: &str) -> Result<String> {
    let id = did
        .strip_prefix("did:web:")
        .ok_or_else(|| Error::malformed("not a did:web"))?;
    let mut parts = id.split(':');
    let host = parts
        .next()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| Error::malformed("did:web without host"))?
        .replace("%3A", ":")
        .replace("%3a", ":");
    let path: Vec<&str> = parts.collect();
    if path.iter().any(|p| p.is_empty()) {
        return Err(Error::malformed("did:web with an empty path segment"));
    }
    Ok(if path.is_empty() {
        format!("https://{host}/.well-known/did.json")
    } else {
        format!("https://{host}/{}/did.json", path.join("/"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_become_dids() {
        assert_eq!(
            did_from_origin("https://node.example.com").unwrap(),
            "did:web:node.example.com"
        );
        assert_eq!(
            did_from_origin("https://Node.Example.com/").unwrap(),
            "did:web:node.example.com"
        );
        assert_eq!(
            did_from_origin("http://localhost:8080").unwrap(),
            "did:web:localhost%3A8080"
        );
    }

    #[test]
    fn origins_with_paths_are_rejected() {
        assert!(did_from_origin("https://example.com/node").is_err());
        assert!(did_from_origin("ftp://example.com").is_err());
        assert!(did_from_origin("https://").is_err());
    }

    /// Examples from the did:web spec.
    #[test]
    fn dids_map_to_document_urls() {
        assert_eq!(
            document_url("did:web:w3c-ccg.github.io").unwrap(),
            "https://w3c-ccg.github.io/.well-known/did.json"
        );
        assert_eq!(
            document_url("did:web:w3c-ccg.github.io:user:alice").unwrap(),
            "https://w3c-ccg.github.io/user/alice/did.json"
        );
        assert_eq!(
            document_url("did:web:example.com%3A3000:user:alice").unwrap(),
            "https://example.com:3000/user/alice/did.json"
        );
    }
}
