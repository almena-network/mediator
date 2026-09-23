//! Content encryption algorithms (JWE `enc`).

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use aes_gcm::aead::{AeadInOut, KeyInit};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use subtle::ConstantTimeEq;

use crate::{Error, Result};

/// JWE content encryption algorithms DIDComm allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentEncryption {
    /// AES-256-CBC + HMAC-SHA-512 (RFC 7518 §5.2.5). Required; the only one
    /// allowed for authcrypt.
    #[serde(rename = "A256CBC-HS512")]
    A256CbcHs512,
    /// AES-256-GCM. Recommended for anoncrypt.
    #[serde(rename = "A256GCM")]
    A256Gcm,
    /// XChaCha20-Poly1305. Optional, anoncrypt only.
    #[serde(rename = "XC20P")]
    Xc20p,
}

impl ContentEncryption {
    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::A256CbcHs512 => 64,
            Self::A256Gcm | Self::Xc20p => 32,
        }
    }

    pub(crate) fn iv_len(self) -> usize {
        match self {
            Self::A256CbcHs512 => 16,
            Self::A256Gcm => 12,
            Self::Xc20p => 24,
        }
    }

    /// Returns `(ciphertext, tag)`.
    pub(crate) fn encrypt(
        self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        self.check_lengths(key, iv)?;
        match self {
            Self::A256CbcHs512 => {
                let (mac_key, enc_key) = key.split_at(32);
                let ciphertext = cbc::Encryptor::<aes::Aes256>::new_from_slices(enc_key, iv)
                    .map_err(|_| Error::Crypto("A256CBC key or iv"))?
                    .encrypt_padded_vec::<Pkcs7>(plaintext);
                let tag = cbc_hs512_tag(mac_key, iv, aad, &ciphertext)?;
                Ok((ciphertext, tag))
            }
            Self::A256Gcm => aead_encrypt::<aes_gcm::Aes256Gcm>(key, iv, aad, plaintext),
            Self::Xc20p => {
                aead_encrypt::<chacha20poly1305::XChaCha20Poly1305>(key, iv, aad, plaintext)
            }
        }
    }

    pub(crate) fn decrypt(
        self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>> {
        self.check_lengths(key, iv)?;
        match self {
            Self::A256CbcHs512 => {
                let (mac_key, enc_key) = key.split_at(32);
                let expected = cbc_hs512_tag(mac_key, iv, aad, ciphertext)?;
                if !bool::from(expected.ct_eq(tag)) {
                    return Err(Error::Crypto("content tag"));
                }
                cbc::Decryptor::<aes::Aes256>::new_from_slices(enc_key, iv)
                    .map_err(|_| Error::Crypto("A256CBC key or iv"))?
                    .decrypt_padded_vec::<Pkcs7>(ciphertext)
                    .map_err(|_| Error::Crypto("content padding"))
            }
            Self::A256Gcm => aead_decrypt::<aes_gcm::Aes256Gcm>(key, iv, aad, ciphertext, tag),
            Self::Xc20p => {
                aead_decrypt::<chacha20poly1305::XChaCha20Poly1305>(key, iv, aad, ciphertext, tag)
            }
        }
    }

    fn check_lengths(self, key: &[u8], iv: &[u8]) -> Result<()> {
        if key.len() != self.key_len() || iv.len() != self.iv_len() {
            return Err(Error::malformed("content key or iv length"));
        }
        Ok(())
    }
}

/// RFC 7518 §5.2.2.1: HMAC-SHA-512 over `AAD || IV || ciphertext || AL`,
/// truncated to 32 bytes; `AL` is the AAD length in bits, 64-bit big-endian.
fn cbc_hs512_tag(mac_key: &[u8], iv: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut mac = <Hmac<Sha512> as hmac::KeyInit>::new_from_slice(mac_key)
        .map_err(|_| Error::Crypto("HMAC key"))?;
    mac.update(aad);
    mac.update(iv);
    mac.update(ciphertext);
    let aad_bits = u64::try_from(aad.len())
        .ok()
        .and_then(|len| len.checked_mul(8))
        .ok_or_else(|| Error::malformed("AAD too long"))?;
    mac.update(&aad_bits.to_be_bytes());
    Ok(mac.finalize().into_bytes()[..32].to_vec())
}

fn aead_encrypt<A: AeadInOut + KeyInit>(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = A::new_from_slice(key).map_err(|_| Error::Crypto("content key"))?;
    let nonce = aes_gcm::aead::Nonce::<A>::try_from(iv).map_err(|_| Error::Crypto("iv"))?;
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into())
        .map_err(|_| Error::Crypto("content encryption"))?;
    Ok((buffer, tag.to_vec()))
}

fn aead_decrypt<A: AeadInOut + KeyInit>(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    let cipher = A::new_from_slice(key).map_err(|_| Error::Crypto("content key"))?;
    let nonce = aes_gcm::aead::Nonce::<A>::try_from(iv).map_err(|_| Error::Crypto("iv"))?;
    let tag = aes_gcm::aead::Tag::<A>::try_from(tag).map_err(|_| Error::Crypto("content tag"))?;
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into(), &tag)
        .map_err(|_| Error::Crypto("content tag"))?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [ContentEncryption; 3] = [
        ContentEncryption::A256CbcHs512,
        ContentEncryption::A256Gcm,
        ContentEncryption::Xc20p,
    ];

    #[test]
    fn round_trips_and_detects_tampering() {
        for enc in ALL {
            let key = vec![7u8; enc.key_len()];
            let iv = vec![9u8; enc.iv_len()];
            let (mut ciphertext, tag) = enc.encrypt(&key, &iv, b"aad", b"secret message").unwrap();
            assert_eq!(
                enc.decrypt(&key, &iv, b"aad", &ciphertext, &tag).unwrap(),
                b"secret message"
            );
            assert!(enc.decrypt(&key, &iv, b"aaD", &ciphertext, &tag).is_err());
            ciphertext[0] ^= 1;
            assert!(
                enc.decrypt(&key, &iv, b"aad", &ciphertext, &tag).is_err(),
                "{enc:?}"
            );
        }
    }

    /// RFC 7518 Appendix B.3 (AES_256_CBC_HMAC_SHA_512) test case.
    #[test]
    fn a256cbc_hs512_matches_rfc7518() {
        let hex = |s: &str| -> Vec<u8> {
            let s: String = s.split_whitespace().collect();
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let key = hex("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
                       20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f");
        let plaintext = hex("41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20 6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75
            69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65 74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62
            65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69 6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66
            20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f 75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65");
        let iv = hex("1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04");
        let aad = hex("54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63 69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20
            4b 65 72 63 6b 68 6f 66 66 73");
        let tag = hex(
            "4d d3 b4 c0 88 a7 f4 5c 21 68 39 64 5b 20 12 bf 2e 62 69 a8 c5 6a 81 6d bc 1b 26 77 61 95 5b c5",
        );
        let (ciphertext, computed) = ContentEncryption::A256CbcHs512
            .encrypt(&key, &iv, &aad, &plaintext)
            .unwrap();
        assert_eq!(computed, tag);
        assert_eq!(&ciphertext[..8], &hex("4a ff aa ad b7 8c 31 c5")[..]);
    }
}
