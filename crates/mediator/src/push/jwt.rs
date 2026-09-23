//! The compact JWTs FCM (RS256) and APNs (ES256) authenticate with.

use almena_didcomm::b64;
use anyhow::Result;
use serde_json::Value;

/// `header.claims.signature`, each part base64url; `sign` signs the first two.
pub fn encode(
    header: &Value,
    claims: &Value,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
) -> Result<String> {
    let input = format!(
        "{}.{}",
        b64::encode(header.to_string()),
        b64::encode(claims.to_string())
    );
    let signature = sign(input.as_bytes())?;
    Ok(format!("{input}.{}", b64::encode(signature)))
}

/// Splits a JWT into its signed input, header and claims, and signature.
#[cfg(test)]
pub fn decode(jwt: &str) -> (String, Value, Value, Vec<u8>) {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "a compact JWT");
    let json = |part: &str| serde_json::from_slice(&b64::decode(part).unwrap()).unwrap();
    (
        format!("{}.{}", parts[0], parts[1]),
        json(parts[0]),
        json(parts[1]),
        b64::decode(parts[2]).unwrap(),
    )
}
