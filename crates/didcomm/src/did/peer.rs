//! `did:peer` numalgo 2 and 4 (<https://identity.foundation/peer-did-method-spec/>).

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::did::document::{DIDCOMM_SERVICE_TYPE, DidDocument};
use crate::did::multikey::{
    self, decode_base58btc, decode_varint, encode_base58btc, encode_varint,
};
use crate::{Error, PublicKey, Result, b64};

/// Verification relationship of a key in a `did:peer:2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// `A`
    Assertion,
    /// `E` — key agreement.
    Encryption,
    /// `V` — authentication.
    Verification,
    /// `I`
    CapabilityInvocation,
    /// `D`
    CapabilityDelegation,
}

impl Purpose {
    fn code(self) -> char {
        match self {
            Self::Assertion => 'A',
            Self::Encryption => 'E',
            Self::Verification => 'V',
            Self::CapabilityInvocation => 'I',
            Self::CapabilityDelegation => 'D',
        }
    }

    fn from_code(code: char) -> Option<Self> {
        Some(match code {
            'A' => Self::Assertion,
            'E' => Self::Encryption,
            'V' => Self::Verification,
            'I' => Self::CapabilityInvocation,
            'D' => Self::CapabilityDelegation,
            _ => return None,
        })
    }
}

const ABBREVIATIONS: [(&str, &str); 4] = [
    ("type", "t"),
    ("serviceEndpoint", "s"),
    ("routingKeys", "r"),
    ("accept", "a"),
];

/// Builds a `did:peer:2` from keys (in order: they become `#key-1`,
/// `#key-2`, …) and services (full DID Core JSON; abbreviated here).
pub fn peer2(keys: &[(Purpose, &PublicKey)], services: &[Value]) -> Result<String> {
    let mut did = String::from("did:peer:2");
    for (purpose, key) in keys {
        did.push('.');
        did.push(purpose.code());
        did.push_str(&multikey::encode(key));
    }
    for service in services {
        let abbreviated = rename_keys(service, true);
        did.push_str(".S");
        did.push_str(&b64::encode(serde_json::to_vec(&abbreviated)?));
    }
    Ok(did)
}

pub(crate) fn resolve_peer2(did: &str) -> Result<DidDocument> {
    let elements = did
        .strip_prefix("did:peer:2.")
        .ok_or_else(|| Error::DidNotFound(did.to_owned()))?;

    let mut vms = Vec::new();
    let mut relationships: [(Purpose, Vec<Value>); 3] = [
        (Purpose::Verification, Vec::new()),
        (Purpose::Assertion, Vec::new()),
        (Purpose::Encryption, Vec::new()),
    ];
    let mut services = Vec::new();

    for element in elements.split('.') {
        let mut chars = element.chars();
        let code = chars
            .next()
            .ok_or_else(|| Error::malformed("empty did:peer:2 element"))?;
        let value = chars.as_str();
        if code == 'S' {
            let service: Value =
                serde_json::from_slice(&b64::decode(value.trim_end_matches('='))?)?;
            let mut service = rename_keys(&service, false);
            normalize_didcomm_service(&mut service);
            if let Some(obj) = service.as_object_mut()
                && !obj.contains_key("id")
            {
                let id = match services.len() {
                    0 => "#service".to_owned(),
                    n => format!("#service-{n}"),
                };
                obj.insert("id".into(), Value::String(id));
            }
            services.push(service);
            continue;
        }
        let purpose = Purpose::from_code(code)
            .ok_or_else(|| Error::malformed(format!("did:peer:2 purpose {code}")))?;
        multikey::decode(value)?; // fail early on a bad key
        let id = format!("#key-{}", vms.len() + 1);
        vms.push(serde_json::json!({
            "id": id, "type": "Multikey", "controller": did, "publicKeyMultibase": value,
        }));
        if let Some((_, ids)) = relationships.iter_mut().find(|(p, _)| *p == purpose) {
            ids.push(Value::String(id));
        }
    }

    let [(_, authentication), (_, assertion), (_, key_agreement)] = relationships;
    DidDocument::from_json(&serde_json::json!({
        "id": did,
        "verificationMethod": vms,
        "authentication": authentication,
        "assertionMethod": assertion,
        "keyAgreement": key_agreement,
        "service": services,
    }))
}

/// Recursively swaps the long and short forms of key names and of the
/// `DIDCommMessaging` type value.
fn rename_keys(value: &Value, abbreviate: bool) -> Value {
    let swap = |s: &str| -> Option<&'static str> {
        ABBREVIATIONS.iter().find_map(|(long, short)| {
            if abbreviate {
                (*long == s).then_some(*short)
            } else {
                (*short == s).then_some(*long)
            }
        })
    };
    match value {
        Value::Object(obj) => {
            let mut out = Map::new();
            for (k, v) in obj {
                let key = swap(k).map_or_else(|| k.clone(), str::to_owned);
                let v = match (key.as_str(), v.as_str()) {
                    ("t" | "type", Some("DIDCommMessaging")) if abbreviate => Value::from("dm"),
                    ("t" | "type", Some("dm")) if !abbreviate => Value::from(DIDCOMM_SERVICE_TYPE),
                    _ => rename_keys(v, abbreviate),
                };
                out.insert(key, v);
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(|v| rename_keys(v, abbreviate)).collect())
        }
        other => other.clone(),
    }
}

/// Older peer DIDs put a URI string in `serviceEndpoint` with `routingKeys`
/// and `accept` next to it; DIDComm v2.0 wants them inside endpoint objects.
fn normalize_didcomm_service(service: &mut Value) {
    let Some(obj) = service.as_object_mut() else {
        return;
    };
    if obj.get("type").and_then(Value::as_str) != Some(DIDCOMM_SERVICE_TYPE) {
        return;
    }
    if let Some(Value::String(uri)) = obj.get("serviceEndpoint").cloned() {
        let mut endpoint = Map::new();
        endpoint.insert("uri".into(), Value::String(uri));
        for field in ["accept", "routingKeys"] {
            if let Some(v) = obj.remove(field) {
                endpoint.insert(field.into(), v);
            }
        }
        obj.insert("serviceEndpoint".into(), Value::Object(endpoint));
    }
}

/// Multicodec code for JSON.
const JSON_CODEC: u64 = 0x0200;

/// Builds the long-form `did:peer:4` for an input document (a DID document
/// without `id`, using only relative references).
pub fn peer4(input_document: &Value) -> Result<String> {
    if input_document.get("id").is_some() {
        return Err(Error::malformed(
            "did:peer:4 input document must not have an id",
        ));
    }
    let mut bytes = Vec::new();
    encode_varint(JSON_CODEC, &mut bytes);
    bytes.extend_from_slice(&serde_json::to_vec(input_document)?);
    let encoded = encode_base58btc(&bytes);
    Ok(format!("did:peer:4{}:{encoded}", peer4_hash(&encoded)))
}

/// The short form of a long-form `did:peer:4`.
pub fn peer4_short(long: &str) -> Result<&str> {
    long.rsplit_once(':')
        .map(|(short, _)| short)
        .filter(|short| short.starts_with("did:peer:4z"))
        .ok_or_else(|| Error::malformed("not a long-form did:peer:4"))
}

fn peer4_hash(encoded_document: &str) -> String {
    let mut multihash = vec![0x12, 0x20];
    multihash.extend_from_slice(&Sha256::digest(encoded_document.as_bytes()));
    encode_base58btc(&multihash)
}

/// Resolves a long-form `did:peer:4` as `as_did` (the long form itself, or
/// its short form when resolving the short one).
pub(crate) fn resolve_peer4(long: &str, as_did: &str) -> Result<DidDocument> {
    let short = peer4_short(long)?;
    let (hash, encoded) = long
        .strip_prefix("did:peer:4")
        .and_then(|rest| rest.split_once(':'))
        .ok_or_else(|| Error::malformed("did:peer:4"))?;
    if peer4_hash(encoded) != hash {
        return Err(Error::malformed(
            "did:peer:4 hash does not match its document",
        ));
    }
    let bytes = decode_base58btc(encoded)?;
    let (codec, json) = decode_varint(&bytes)?;
    if codec != JSON_CODEC {
        return Err(Error::malformed("did:peer:4 document is not JSON"));
    }
    let mut doc: Value = serde_json::from_slice(json)?;
    let obj = doc
        .as_object_mut()
        .ok_or_else(|| Error::malformed("did:peer:4 document is not an object"))?;
    obj.insert("id".into(), Value::from(as_did));
    let other_form = if as_did == long { short } else { long };
    let also = obj
        .entry("alsoKnownAs")
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Value::Array(list) = also {
        list.push(Value::from(other_form));
    }
    DidDocument::from_json(&doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Curve, SecretKey};

    const SPEC_PEER2: &str = "did:peer:2.Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc.Ez6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9hbm90aGVyIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0yIl19fQ";

    #[test]
    fn resolves_the_spec_peer2_example() {
        let doc = resolve_peer2(SPEC_PEER2).unwrap();
        assert_eq!(doc.authentication, [format!("{SPEC_PEER2}#key-1")]);
        assert_eq!(doc.key_agreement, [format!("{SPEC_PEER2}#key-2")]);
        let ids: Vec<_> = doc.service.iter().map(|s| s.id.clone()).collect();
        assert_eq!(
            ids,
            [
                format!("{SPEC_PEER2}#service"),
                format!("{SPEC_PEER2}#service-1")
            ]
        );
        let endpoint = &doc.service[0].didcomm_endpoints().unwrap()[0];
        assert_eq!(endpoint.uri, "http://example.com/didcomm");
        assert_eq!(
            endpoint.routing_keys,
            ["did:example:123456789abcdefghi#key-1"]
        );
    }

    #[test]
    fn encodes_the_spec_peer2_example() {
        let doc = resolve_peer2(SPEC_PEER2).unwrap();
        let keys: Vec<_> = doc
            .verification_method
            .iter()
            .map(|m| m.key.clone())
            .collect();
        let services: Vec<Value> = doc
            .service
            .iter()
            .map(|s| serde_json::json!({"t": "dm", "s": s.endpoint[0]}))
            .map(|s| rename_keys(&s, false)) // the did:peer example uses the single-object form
            .collect();
        let did = peer2(
            &[
                (Purpose::Verification, &keys[0]),
                (Purpose::Encryption, &keys[1]),
            ],
            &services,
        )
        .unwrap();
        assert_eq!(did, SPEC_PEER2);
    }

    #[test]
    fn peer2_round_trip() {
        let ed = SecretKey::generate(Curve::Ed25519).unwrap().public_key();
        let x = SecretKey::generate(Curve::X25519).unwrap().public_key();
        let did = peer2(
            &[(Purpose::Encryption, &x), (Purpose::Verification, &ed)],
            &[],
        )
        .unwrap();
        let doc = resolve_peer2(&did).unwrap();
        assert_eq!(doc.key_agreement_key(&format!("{did}#key-1")).unwrap(), &x);
        assert_eq!(
            doc.authentication_key(&format!("{did}#key-2")).unwrap(),
            &ed
        );
    }

    const SPEC_PEER4_SHORT: &str = "did:peer:4zQmd8CpeFPci817KDsbSAKWcXAE2mjvCQSasRewvbSF54Bd";

    fn spec_input_document() -> Value {
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/x25519-2020/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
            "verificationMethod": [
                {"id": "#6LSqPZfn", "type": "X25519KeyAgreementKey2020", "publicKeyMultibase": "z6LSqPZfn9krvgXma2icTMKf2uVcYhKXsudCmPoUzqGYW24U"},
                {"id": "#6MkrCD1c", "type": "Ed25519VerificationKey2020", "publicKeyMultibase": "z6MkrCD1csqtgdj8sjrsu8jxcbeyP6m7LiK87NzhfWqio5yr"}
            ],
            "authentication": ["#6MkrCD1c"], "assertionMethod": ["#6MkrCD1c"], "keyAgreement": ["#6LSqPZfn"],
            "capabilityInvocation": ["#6MkrCD1c"], "capabilityDelegation": ["#6MkrCD1c"],
            "service": [{"id": "#didcommmessaging-0", "type": "DIDCommMessaging",
                "serviceEndpoint": {"uri": "didcomm:transport/queue", "accept": ["didcomm/v2"], "routingKeys": []}}]
        })
    }

    #[test]
    fn peer4_matches_the_spec_example() {
        let long = peer4(&spec_input_document()).unwrap();
        assert_eq!(peer4_short(&long).unwrap(), SPEC_PEER4_SHORT);
    }

    #[test]
    fn peer4_long_and_short_forms_resolve() {
        let long = peer4(&spec_input_document()).unwrap();
        let doc = resolve_peer4(&long, &long).unwrap();
        assert_eq!(doc.id, long);
        assert_eq!(doc.also_known_as, [SPEC_PEER4_SHORT]);
        assert_eq!(doc.key_agreement, [format!("{long}#6LSqPZfn")]);

        let short = resolve_peer4(&long, SPEC_PEER4_SHORT).unwrap();
        assert_eq!(short.id, SPEC_PEER4_SHORT);
        assert_eq!(
            short.authentication,
            [format!("{SPEC_PEER4_SHORT}#6MkrCD1c")]
        );
    }

    #[test]
    fn peer4_with_a_tampered_document_is_rejected() {
        let long = peer4(&spec_input_document()).unwrap();
        let mut tampered = long.clone();
        tampered.pop();
        tampered.push('x');
        assert!(resolve_peer4(&tampered, &tampered).is_err());
    }
}
