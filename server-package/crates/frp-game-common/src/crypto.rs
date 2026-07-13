use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const PROTOCOL_VERSION: u8 = 1;
const MAX_CLOCK_SKEW_SECONDS: i64 = 300;
const API_HKDF_INFO: &[u8] = b"frp-game-tool-api-v1";
const STORAGE_HKDF_INFO: &[u8] = b"frp-game-tool-storage-v1";
const STORED_TEXT_VERSION: u8 = 1;
const NONCE_LENGTH: usize = 12;
const AUTH_TAG_LENGTH: usize = 16;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("invalid base64 field")]
    InvalidBase64,
    #[error("invalid encrypted payload")]
    InvalidPayload,
    #[error("invalid encryption salt")]
    InvalidSalt,
    #[error("invalid nonce length")]
    InvalidNonce,
    #[error("invalid ciphertext length")]
    InvalidCiphertext,
    #[error("missing timestamp")]
    MissingTimestamp,
    #[error("request timestamp expired")]
    ExpiredTimestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u8,
    pub nonce: String,
    pub payload: String,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn b64encode(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

fn b64decode(value: &str) -> Result<Vec<u8>, CryptoError> {
    URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| CryptoError::InvalidBase64)
}

fn derive_key(secret: &str, salt: &[u8], info: &[u8]) -> Result<[u8; 32], CryptoError> {
    if !(16..=64).contains(&salt.len()) || secret.is_empty() {
        return Err(CryptoError::InvalidSalt);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(salt), secret.as_bytes());
    let mut key = [0_u8; 32];
    hkdf.expand(info, &mut key)
        .map_err(|_| CryptoError::InvalidPayload)?;
    Ok(key)
}

pub fn encrypt_payload(
    secret: &str,
    salt_b64: &str,
    payload: Value,
) -> Result<Envelope, CryptoError> {
    let salt = b64decode(salt_b64)?;
    let mut data = match payload {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    data.entry("ts".to_string())
        .or_insert_with(|| Value::from(now_unix()));

    let plaintext =
        serde_json::to_vec(&Value::Object(data)).map_err(|_| CryptoError::InvalidPayload)?;
    let mut nonce_bytes = [0_u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(secret, &salt, API_HKDF_INFO)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::InvalidPayload)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_slice())
        .map_err(|_| CryptoError::InvalidPayload)?;

    Ok(Envelope {
        version: PROTOCOL_VERSION,
        nonce: b64encode(&nonce_bytes),
        payload: b64encode(&ciphertext),
    })
}

pub fn decrypt_payload(
    secret: &str,
    salt_b64: &str,
    envelope: &Envelope,
) -> Result<Value, CryptoError> {
    if envelope.version != PROTOCOL_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }

    let salt = b64decode(salt_b64)?;
    let nonce = b64decode(&envelope.nonce)?;
    let ciphertext = b64decode(&envelope.payload)?;
    if nonce.len() != NONCE_LENGTH {
        return Err(CryptoError::InvalidNonce);
    }
    if ciphertext.len() < AUTH_TAG_LENGTH {
        return Err(CryptoError::InvalidCiphertext);
    }
    let key = derive_key(secret, &salt, API_HKDF_INFO)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::InvalidPayload)?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())
        .map_err(|_| CryptoError::InvalidPayload)?;
    let data: Value =
        serde_json::from_slice(&plaintext).map_err(|_| CryptoError::InvalidPayload)?;

    let timestamp = data
        .get("ts")
        .and_then(Value::as_i64)
        .ok_or(CryptoError::MissingTimestamp)?;
    if (now_unix() - timestamp).abs() > MAX_CLOCK_SKEW_SECONDS {
        return Err(CryptoError::ExpiredTimestamp);
    }

    Ok(data)
}

pub fn encrypt_stored_text(
    secret: &str,
    salt_b64: &str,
    plaintext: &str,
) -> Result<String, CryptoError> {
    let salt = b64decode(salt_b64)?;
    let mut nonce_bytes = [0_u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce_bytes);
    let key = derive_key(secret, &salt, STORAGE_HKDF_INFO)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::InvalidPayload)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
        .map_err(|_| CryptoError::InvalidPayload)?;

    let mut stored = Vec::with_capacity(1 + NONCE_LENGTH + ciphertext.len());
    stored.push(STORED_TEXT_VERSION);
    stored.extend_from_slice(&nonce_bytes);
    stored.extend_from_slice(&ciphertext);
    Ok(b64encode(&stored))
}

pub fn decrypt_stored_text(
    secret: &str,
    salt_b64: &str,
    stored_b64: &str,
) -> Result<String, CryptoError> {
    let stored = b64decode(stored_b64)?;
    if stored.first().copied() != Some(STORED_TEXT_VERSION) {
        return Err(CryptoError::UnsupportedVersion);
    }
    if stored.len() < 1 + NONCE_LENGTH + AUTH_TAG_LENGTH {
        return Err(CryptoError::InvalidCiphertext);
    }
    let nonce = &stored[1..1 + NONCE_LENGTH];
    let ciphertext = &stored[1 + NONCE_LENGTH..];
    let salt = b64decode(salt_b64)?;
    let key = derive_key(secret, &salt, STORAGE_HKDF_INFO)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::InvalidPayload)?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::InvalidPayload)?;
    String::from_utf8(plaintext).map_err(|_| CryptoError::InvalidPayload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_salt() -> String {
        b64encode(&[7_u8; 32])
    }

    #[test]
    fn round_trip_payload() {
        let salt = test_salt();
        let envelope = encrypt_payload("secret", &salt, json!({"op": "login"})).unwrap();
        let decoded = decrypt_payload("secret", &salt, &envelope).unwrap();
        assert_eq!(decoded.get("op").and_then(Value::as_str), Some("login"));
    }

    #[test]
    fn rejects_wrong_nonce_length_without_panicking() {
        let envelope = Envelope {
            version: PROTOCOL_VERSION,
            nonce: b64encode(&[1_u8; 3]),
            payload: b64encode(&[2_u8; 16]),
        };
        let result =
            std::panic::catch_unwind(|| decrypt_payload("secret", &test_salt(), &envelope));
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Err(CryptoError::InvalidNonce)));
    }

    #[test]
    fn rejects_short_ciphertext() {
        let envelope = Envelope {
            version: PROTOCOL_VERSION,
            nonce: b64encode(&[1_u8; 12]),
            payload: b64encode(&[2_u8; 8]),
        };
        assert!(matches!(
            decrypt_payload("secret", &test_salt(), &envelope),
            Err(CryptoError::InvalidCiphertext)
        ));
    }

    #[test]
    fn round_trip_stored_text() {
        let salt = test_salt();
        let encrypted = encrypt_stored_text("user-secret", &salt, "stored-password-123").unwrap();
        assert_ne!(encrypted, "stored-password-123");
        assert_eq!(
            decrypt_stored_text("user-secret", &salt, &encrypted).unwrap(),
            "stored-password-123"
        );
        assert!(decrypt_stored_text("wrong-secret", &salt, &encrypted).is_err());
    }
}
