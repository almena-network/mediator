//! Unpacking envelopes, with the spec's layering and consistency rules.

use serde_json::Value;

use crate::crypto::content::ContentEncryption;
use crate::crypto::jwe::{ENCRYPTED_TYP, Jwe, KeyWrap};
use crate::crypto::jws::{Jws, SIGNED_TYP};
use crate::did::{DidResolver, did_of};
use crate::from_prior::FromPrior;
use crate::message::{Message, media_type_is};
use crate::secrets::SecretsResolver;
use crate::{Error, Result};

/// What unpacking found out about a message's envelopes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UnpackMetadata {
    /// At least one encryption layer.
    pub encrypted: bool,
    /// An authcrypt layer: the sender is authenticated to us.
    pub authenticated: bool,
    /// A signature: the sender is provable to third parties.
    pub non_repudiation: bool,
    /// Encrypted, but without an authcrypt layer.
    pub anonymous_sender: bool,
    /// The sender key of the authcrypt layer.
    pub encrypted_from_kid: Option<String>,
    /// All recipient key ids of the innermost encryption layer.
    pub encrypted_to_kids: Vec<String>,
    /// The key we decrypted with.
    pub decrypted_by_kid: Option<String>,
    pub enc_alg_anon: Option<ContentEncryption>,
    pub enc_alg_auth: Option<ContentEncryption>,
    /// The signing key, if signed.
    pub sign_from: Option<String>,
    /// The signed message as received, kept for non-repudiation.
    pub signed_message: Option<String>,
    /// Verified DID rotation, and the key that signed it.
    pub from_prior: Option<FromPrior>,
    pub from_prior_issuer_kid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layer {
    Anoncrypt,
    Authcrypt,
    Signed,
}

/// Unpacks a DIDComm message in any of its forms and checks it.
///
/// Accepted layerings, outermost first: plaintext; signed; anoncrypt and
/// authcrypt, each optionally around a signed message; and anoncrypt around
/// authcrypt (with or without a signed message inside, as the spec's own test
/// vectors do). A decrypted envelope must be for a key we hold; an authcrypt
/// sender key must be a `keyAgreement` key of its DID and a signing key an
/// `authentication` key of its DID; and the plaintext `from`/`to` must agree
/// with the envelopes.
pub async fn unpack(
    packed: &str,
    resolver: &dyn DidResolver,
    secrets: &dyn SecretsResolver,
) -> Result<(Message, UnpackMetadata)> {
    let mut meta = UnpackMetadata::default();
    let mut layers: Vec<Layer> = Vec::new();
    let mut current = packed.to_owned();
    // Each layer's recipient DID, to check against the plaintext `to`.
    let mut recipient_dids: Vec<String> = Vec::new();

    let message = loop {
        let value: Value = serde_json::from_str(&current)?;
        let obj = value
            .as_object()
            .ok_or_else(|| Error::malformed("message is not a JSON object"))?;

        if obj.contains_key("ciphertext") {
            let jwe = Jwe::parse(&current)?;
            let header = jwe.protected_header()?;
            check_typ(header.typ.as_deref(), ENCRYPTED_TYP)?;
            let layer = match header.alg {
                KeyWrap::EcdhEsA256Kw => Layer::Anoncrypt,
                KeyWrap::Ecdh1PuA256Kw => Layer::Authcrypt,
            };
            let allowed = match layer {
                Layer::Anoncrypt => layers.is_empty(),
                _ => layers.is_empty() || layers == [Layer::Anoncrypt],
            };
            if !allowed {
                return Err(Error::malformed("unsupported envelope layering"));
            }

            let (kid, key) = find_decryption_key(&jwe, secrets).await?;
            let sender = match layer {
                Layer::Authcrypt => {
                    let skid = header
                        .sender_kid()?
                        .ok_or_else(|| Error::malformed("authcrypt without skid or apu"))?;
                    let doc = resolver.resolve(did_of(&skid)).await?;
                    let sender_key = doc.key_agreement_key(&skid)?.clone();
                    meta.authenticated = true;
                    meta.encrypted_from_kid = Some(skid);
                    meta.enc_alg_auth = Some(header.enc);
                    Some(sender_key)
                }
                _ => {
                    meta.enc_alg_anon = Some(header.enc);
                    None
                }
            };
            let plaintext = jwe.decrypt(&kid, &key, sender.as_ref())?;

            meta.encrypted = true;
            meta.encrypted_to_kids = jwe.recipient_kids().map(str::to_owned).collect();
            recipient_dids.push(did_of(&kid).to_owned());
            meta.decrypted_by_kid = Some(kid);
            layers.push(layer);
            current = utf8(plaintext)?;
        } else if obj.contains_key("payload") {
            if layers.contains(&Layer::Signed) {
                return Err(Error::malformed("nested signatures"));
            }
            let jws = Jws::parse(&current)?;
            check_typ(jws.protected_header()?.typ.as_deref(), SIGNED_TYP)?;
            let kid = jws.signer_kid()?;
            let doc = resolver.resolve(did_of(&kid)).await?;
            let payload = jws.verify(doc.authentication_key(&kid)?)?;

            meta.non_repudiation = true;
            meta.signed_message = Some(current.clone());
            meta.sign_from = Some(kid);
            layers.push(Layer::Signed);
            current = utf8(payload)?;
        } else {
            let message: Message = serde_json::from_value(value)?;
            message.validate()?;
            break message;
        }
    };
    meta.anonymous_sender = meta.encrypted && !meta.authenticated;

    check_consistency(&message, &meta, &recipient_dids)?;
    if let Some(token) = &message.from_prior {
        let (claims, kid) = FromPrior::unpack(token, resolver).await?;
        if message.from.as_deref() != Some(claims.sub.as_str()) {
            return Err(Error::inconsistent(
                "from_prior sub is not the message's from",
            ));
        }
        meta.from_prior = Some(claims);
        meta.from_prior_issuer_kid = Some(kid);
    }
    Ok((message, meta))
}

/// Spec: "Message Layer Addressing Consistency".
fn check_consistency(
    message: &Message,
    meta: &UnpackMetadata,
    recipient_dids: &[String],
) -> Result<()> {
    let from = message.from.as_deref();
    if let Some(skid) = &meta.encrypted_from_kid
        && from != Some(did_of(skid))
    {
        return Err(Error::inconsistent(
            "from does not match the authcrypt sender",
        ));
    }
    if let Some(signer) = &meta.sign_from
        && from != Some(did_of(signer))
    {
        return Err(Error::inconsistent("from does not match the signer"));
    }
    if let Some(to) = &message.to {
        for did in recipient_dids {
            if !to.iter().any(|t| t == did) {
                return Err(Error::inconsistent("to does not contain the recipient"));
            }
        }
    }
    Ok(())
}

/// The first recipient of `jwe` we hold a secret for.
async fn find_decryption_key(
    jwe: &Jwe,
    secrets: &dyn SecretsResolver,
) -> Result<(String, crate::SecretKey)> {
    for kid in jwe.recipient_kids() {
        if let Some(key) = secrets.get_secret(kid).await? {
            return Ok((kid.to_owned(), key));
        }
    }
    Err(Error::SecretNotFound("none of the recipient keys".into()))
}

fn check_typ(typ: Option<&str>, expected: &str) -> Result<()> {
    match typ {
        Some(typ) if !media_type_is(typ, expected) => {
            Err(Error::malformed(format!("typ {typ}, expected {expected}")))
        }
        _ => Ok(()),
    }
}

fn utf8(bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes).map_err(|_| Error::malformed("payload is not UTF-8"))
}
