//! DID documents (W3C DID Core), reduced to what DIDComm needs: verification
//! methods with typed keys, the `authentication` and `keyAgreement`
//! relationships, and services.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::did::multikey;
use crate::{Curve, Error, Jwk, PublicKey, Result};

/// A verification method with its key decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationMethod {
    /// Absolute DID URL, e.g. `did:example:alice#key-1`.
    pub id: String,
    pub controller: String,
    pub key: PublicKey,
}

/// A service entry. `endpoint` is kept as JSON because its shape depends on
/// the service type; [`Service::didcomm_endpoints`] reads the DIDComm one.
/// A `DIDCommMessaging` endpoint is always held as a list of endpoint
/// objects, the form DIDComm v2.0 requires; a single object read from a
/// document is wrapped in a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// Absolute DID URL, e.g. `did:example:alice#didcomm`.
    pub id: String,
    pub kind: String,
    pub endpoint: Value,
}

/// Service type of DIDComm v2 endpoints.
pub const DIDCOMM_SERVICE_TYPE: &str = "DIDCommMessaging";

/// One `serviceEndpoint` object of a `DIDCommMessaging` service.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidCommEndpoint {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accept: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routing_keys: Vec<String>,
}

impl Service {
    /// The endpoints of a `DIDCommMessaging` service, in the owner's order of
    /// preference. Empty for other service types.
    pub fn didcomm_endpoints(&self) -> Result<Vec<DidCommEndpoint>> {
        if self.kind != DIDCOMM_SERVICE_TYPE {
            return Ok(Vec::new());
        }
        match &self.endpoint {
            Value::Array(items) => items
                .iter()
                .map(|v| Ok(serde_json::from_value(v.clone())?))
                .collect(),
            Value::Object(_) => Ok(vec![serde_json::from_value(self.endpoint.clone())?]),
            _ => Err(Error::malformed("DIDCommMessaging serviceEndpoint")),
        }
    }
}

/// A resolved DID document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DidDocument {
    pub id: String,
    pub also_known_as: Vec<String>,
    pub verification_method: Vec<VerificationMethod>,
    /// Absolute DID URLs of methods in `verification_method`.
    pub authentication: Vec<String>,
    pub assertion_method: Vec<String>,
    pub key_agreement: Vec<String>,
    pub service: Vec<Service>,
}

impl DidDocument {
    pub fn method(&self, id: &str) -> Option<&VerificationMethod> {
        self.verification_method.iter().find(|m| m.id == id)
    }

    /// Methods listed under `keyAgreement`, in document order.
    pub fn key_agreement_methods(&self) -> impl Iterator<Item = &VerificationMethod> {
        self.key_agreement.iter().filter_map(|id| self.method(id))
    }

    /// Methods listed under `authentication`, in document order.
    pub fn authentication_methods(&self) -> impl Iterator<Item = &VerificationMethod> {
        self.authentication.iter().filter_map(|id| self.method(id))
    }

    /// The key of `kid` if it is a `keyAgreement` method of this document.
    pub fn key_agreement_key(&self, kid: &str) -> Result<&PublicKey> {
        if !self.key_agreement.iter().any(|id| id == kid) {
            return Err(Error::DidUrlNotFound(format!("{kid} (keyAgreement)")));
        }
        self.method(kid)
            .map(|m| &m.key)
            .ok_or_else(|| Error::DidUrlNotFound(kid.to_owned()))
    }

    /// The key of `kid` if it is an `authentication` method of this document.
    pub fn authentication_key(&self, kid: &str) -> Result<&PublicKey> {
        if !self.authentication.iter().any(|id| id == kid) {
            return Err(Error::DidUrlNotFound(format!("{kid} (authentication)")));
        }
        self.method(kid)
            .map(|m| &m.key)
            .ok_or_else(|| Error::DidUrlNotFound(kid.to_owned()))
    }

    pub fn didcomm_services(&self) -> impl Iterator<Item = &Service> {
        self.service
            .iter()
            .filter(|s| s.kind == DIDCOMM_SERVICE_TYPE)
    }

    /// Reads a DID document from JSON. Verification methods may be embedded
    /// in relationships or referenced; relative references (`#key-1`) are
    /// made absolute against `id`. Supported key formats: `publicKeyJwk`,
    /// `publicKeyMultibase` (Multikey) and `publicKeyBase58` for the 2018/2019
    /// Ed25519 and X25519 suites. Methods in other formats are skipped.
    pub fn from_json(value: &Value) -> Result<Self> {
        let obj = value
            .as_object()
            .ok_or_else(|| Error::malformed("DID document is not an object"))?;
        let id = obj
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::malformed("DID document without id"))?
            .to_owned();
        let mut doc = Self {
            also_known_as: string_list(obj.get("alsoKnownAs")),
            id,
            ..Self::default()
        };

        for vm in array(obj.get("verificationMethod")) {
            if let Some(method) = doc.parse_method(vm)? {
                doc.verification_method.push(method);
            }
        }
        doc.authentication = doc.parse_relationship(obj.get("authentication"))?;
        doc.assertion_method = doc.parse_relationship(obj.get("assertionMethod"))?;
        doc.key_agreement = doc.parse_relationship(obj.get("keyAgreement"))?;

        for (i, service) in array(obj.get("service")).iter().enumerate() {
            let kind = service
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::malformed("service without type"))?;
            let id = match service.get("id").and_then(Value::as_str) {
                Some(id) => doc.absolute(id),
                None => doc.absolute(&format!("#service-{i}")),
            };
            let mut endpoint = service
                .get("serviceEndpoint")
                .cloned()
                .unwrap_or(Value::Null);
            if kind == DIDCOMM_SERVICE_TYPE && endpoint.is_object() {
                endpoint = Value::Array(vec![endpoint]);
            }
            doc.service.push(Service {
                id,
                kind: kind.to_owned(),
                endpoint,
            });
        }
        Ok(doc)
    }

    /// Writes the document as JSON, with every key as a `JsonWebKey2020`
    /// method and relationships as references.
    pub fn to_json(&self) -> Value {
        let methods: Vec<Value> = self
            .verification_method
            .iter()
            .map(|m| {
                json!({
                    "id": m.id,
                    "type": "JsonWebKey2020",
                    "controller": m.controller,
                    "publicKeyJwk": m.key.to_jwk(),
                })
            })
            .collect();
        let services: Vec<Value> = self
            .service
            .iter()
            .map(|s| json!({"id": s.id, "type": s.kind, "serviceEndpoint": s.endpoint}))
            .collect();

        let mut doc = Map::new();
        doc.insert(
            "@context".into(),
            json!([
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1"
            ]),
        );
        doc.insert("id".into(), json!(self.id));
        if !self.also_known_as.is_empty() {
            doc.insert("alsoKnownAs".into(), json!(self.also_known_as));
        }
        doc.insert("verificationMethod".into(), Value::Array(methods));
        for (name, ids) in [
            ("authentication", &self.authentication),
            ("assertionMethod", &self.assertion_method),
            ("keyAgreement", &self.key_agreement),
        ] {
            if !ids.is_empty() {
                doc.insert(name.into(), json!(ids));
            }
        }
        if !services.is_empty() {
            doc.insert("service".into(), Value::Array(services));
        }
        Value::Object(doc)
    }

    fn absolute(&self, id: &str) -> String {
        if id.starts_with('#') {
            format!("{}{id}", self.id)
        } else {
            id.to_owned()
        }
    }

    /// References become absolute ids; embedded methods are added to
    /// `verification_method` (unless already there) and referenced.
    fn parse_relationship(&mut self, value: Option<&Value>) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        for entry in array(value) {
            match entry {
                Value::String(reference) => ids.push(self.absolute(reference)),
                Value::Object(_) => {
                    if let Some(method) = self.parse_method(entry)? {
                        ids.push(method.id.clone());
                        if self.method(&method.id).is_none() {
                            self.verification_method.push(method);
                        }
                    }
                }
                _ => return Err(Error::malformed("verification relationship entry")),
            }
        }
        Ok(ids)
    }

    fn parse_method(&self, vm: &Value) -> Result<Option<VerificationMethod>> {
        let field = |name: &str| vm.get(name).and_then(Value::as_str);
        let id = field("id").ok_or_else(|| Error::malformed("verification method without id"))?;
        let kind = field("type").unwrap_or_default();

        let key = if let Some(jwk) = vm.get("publicKeyJwk") {
            PublicKey::from_jwk(&serde_json::from_value::<Jwk>(jwk.clone())?)?
        } else if let Some(multibase) = field("publicKeyMultibase") {
            multikey::decode(multibase)?
        } else if let Some(base58) = field("publicKeyBase58") {
            let curve = match kind {
                "Ed25519VerificationKey2018" => Curve::Ed25519,
                "X25519KeyAgreementKey2019" => Curve::X25519,
                _ => return Ok(None),
            };
            let raw = bs58::decode(base58)
                .into_vec()
                .map_err(|_| Error::malformed("publicKeyBase58"))?;
            PublicKey::from_bytes(curve, &raw)?
        } else {
            return Ok(None);
        };

        Ok(Some(VerificationMethod {
            id: self.absolute(id),
            controller: field("controller").map_or_else(|| self.id.clone(), str::to_owned),
            key,
        }))
    }
}

fn array(value: Option<&Value>) -> &[Value] {
    value.and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    array(value)
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// The DID part of a DID URL (everything before `#`, `?` or `/` after the method-specific id).
pub fn did_of(did_url: &str) -> &str {
    let end = did_url.find(['#', '?', '/']).unwrap_or(did_url.len());
    &did_url[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    const APPENDIX: &str = include_str!("../../tests/spec/appendix.json");

    fn alice() -> DidDocument {
        let appendix: Value = serde_json::from_str(APPENDIX).unwrap();
        DidDocument::from_json(&appendix["alice_did_doc"]).unwrap()
    }

    #[test]
    fn reads_embedded_methods_from_the_spec_appendix() {
        let doc = alice();
        assert_eq!(doc.authentication.len(), 3);
        assert_eq!(doc.key_agreement.len(), 3);
        assert_eq!(doc.verification_method.len(), 6);
        assert_eq!(
            doc.key_agreement_key("did:example:alice#key-x25519-1")
                .unwrap()
                .curve(),
            Curve::X25519
        );
    }

    #[test]
    fn relationships_are_enforced() {
        let doc = alice();
        assert!(doc.key_agreement_key("did:example:alice#key-1").is_err());
        assert!(
            doc.authentication_key("did:example:alice#key-x25519-1")
                .is_err()
        );
    }

    #[test]
    fn json_round_trip() {
        let doc = alice();
        assert_eq!(DidDocument::from_json(&doc.to_json()).unwrap(), doc);
    }

    #[test]
    fn didcomm_endpoints_accept_object_or_array() {
        let doc = DidDocument::from_json(&json!({
            "id": "did:example:x",
            "service": [
                {"id": "#a", "type": "DIDCommMessaging", "serviceEndpoint": {"uri": "https://a", "accept": ["didcomm/v2"]}},
                {"id": "#b", "type": "DIDCommMessaging", "serviceEndpoint": [{"uri": "https://b", "routingKeys": ["did:example:m#k"]}]},
                {"id": "#c", "type": "LinkedDomains", "serviceEndpoint": "https://c"}
            ]
        }))
        .unwrap();
        assert_eq!(doc.service[0].id, "did:example:x#a");
        assert!(doc.to_json()["service"][0]["serviceEndpoint"].is_array());
        let all: Vec<_> = doc
            .didcomm_services()
            .flat_map(|s| s.didcomm_endpoints().unwrap())
            .collect();
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].routing_keys, ["did:example:m#k"]);
    }

    #[test]
    fn did_of_strips_fragment_and_query() {
        assert_eq!(did_of("did:example:a#key-1"), "did:example:a");
        assert_eq!(did_of("did:example:a?x=1#k"), "did:example:a");
        assert_eq!(did_of("did:example:a"), "did:example:a");
    }
}
