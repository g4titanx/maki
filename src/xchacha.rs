//! XChaCha20-Poly1305 authenticated encryption and nonce generation.

use std::fmt;

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use crate::{KEY_LENGTH, RandomnessError, random_array};

/// Number of bytes in an XChaCha20-Poly1305 nonce.
pub const NONCE_LENGTH: usize = 24;

/// Number of bytes in a Poly1305 authentication tag.
pub const TAG_LENGTH: usize = 16;

/// Errors produced by authenticated encryption and recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionError {
    EncryptionFailed,
    AuthenticationFailed,
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncryptionFailed => formatter.write_str("encryption failed"),
            Self::AuthenticationFailed => {
                formatter.write_str("encrypted content failed authentication")
            }
        }
    }
}

impl std::error::Error for EncryptionError {}

/// Generates a fresh 192-bit XChaCha20-Poly1305 nonce using the operating
/// system's secure random number generator.
pub fn generate_nonce() -> Result<[u8; NONCE_LENGTH], RandomnessError> {
    random_array()
}

/// Encrypts `secret` with a 256-bit key and a 192-bit nonce.
///
/// `authenticated_metadata` is not encrypted, but it is covered by the
/// Poly1305 authentication tag. Recovery fails if the metadata differs from
/// the value supplied here. The returned bytes contain the ciphertext followed
/// by the 16-byte authentication tag.
pub fn encrypt_with_key(
    secret: &[u8],
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    authenticated_metadata: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| EncryptionError::EncryptionFailed)?;
    let payload = Payload {
        msg: secret,
        aad: authenticated_metadata,
    };
    let nonce: &XNonce = nonce.into();

    cipher
        .encrypt(nonce, payload)
        .map_err(|_| EncryptionError::EncryptionFailed)
}

/// Authenticates and recovers content produced by [`encrypt_with_key`].
///
/// Recovery returns one error for every authentication failure. A caller
/// cannot use the error to distinguish a wrong key from changed ciphertext,
/// nonce, or authenticated metadata. Recovered content is zeroized when it is
/// dropped.
pub fn decrypt_with_key(
    encrypted_content: &[u8],
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    authenticated_metadata: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EncryptionError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| EncryptionError::AuthenticationFailed)?;
    let payload = Payload {
        msg: encrypted_content,
        aad: authenticated_metadata,
    };
    let nonce: &XNonce = nonce.into();

    cipher
        .decrypt(nonce, payload)
        .map(Zeroizing::new)
        .map_err(|_| EncryptionError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LENGTH] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    const NONCE: [u8; NONCE_LENGTH] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ];
    const AAD: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: \
        If I could offer you only one tip for the future, sunscreen would be it.";
    const CIPHERTEXT: &[u8] = &[
        0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94, 0x93, 0xc0, 0xe9,
        0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc, 0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39,
        0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3, 0xa8, 0x2f, 0x4e,
        0xda, 0x7e, 0x39, 0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16, 0xcb, 0x96, 0xb7, 0x2e,
        0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45, 0xb1, 0x1b, 0x69,
        0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b, 0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2,
        0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9, 0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76,
        0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13, 0xb5, 0x2e,
    ];
    const TAG: [u8; TAG_LENGTH] = [
        0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79, 0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a, 0xcf,
        0x49,
    ];

    #[test]
    fn matches_the_xchacha20_poly1305_known_answer() {
        // Published in draft-irtf-cfrg-xchacha-03, Appendix A.3.1.
        let mut expected = Vec::from(CIPHERTEXT);
        expected.extend_from_slice(&TAG);

        let encrypted = encrypt_with_key(PLAINTEXT, &KEY, &NONCE, &AAD).unwrap();

        assert_eq!(encrypted, expected);
    }

    #[test]
    fn encryption_round_trip_recovers_the_secret() {
        let secret =
            b"abandon ability able about above absent absorb abstract absurd abuse access accident";
        let metadata = b"maki authenticated metadata";
        let encrypted = encrypt_with_key(secret, &KEY, &NONCE, metadata).unwrap();
        let recovered = decrypt_with_key(&encrypted, &KEY, &NONCE, metadata).unwrap();

        assert_eq!(recovered.as_slice(), secret);
        assert_eq!(encrypted.len(), secret.len() + TAG_LENGTH);
    }

    #[test]
    fn changed_ciphertext_fails_authentication() {
        let mut encrypted = encrypt_test_secret();
        encrypted[0] ^= 1;

        assert_authentication_fails(&encrypted, &KEY, &NONCE, b"metadata");
    }

    #[test]
    fn changed_key_fails_authentication() {
        let encrypted = encrypt_test_secret();
        let mut changed_key = KEY;
        changed_key[0] ^= 1;

        assert_authentication_fails(&encrypted, &changed_key, &NONCE, b"metadata");
    }

    #[test]
    fn changed_nonce_fails_authentication() {
        let encrypted = encrypt_test_secret();
        let mut changed_nonce = NONCE;
        changed_nonce[0] ^= 1;

        assert_authentication_fails(&encrypted, &KEY, &changed_nonce, b"metadata");
    }

    #[test]
    fn changed_metadata_fails_authentication() {
        let encrypted = encrypt_test_secret();

        assert_authentication_fails(&encrypted, &KEY, &NONCE, b"changed metadata");
    }

    fn encrypt_test_secret() -> Vec<u8> {
        encrypt_with_key(b"test secret", &KEY, &NONCE, b"metadata").unwrap()
    }

    fn assert_authentication_fails(
        encrypted_content: &[u8],
        key: &[u8; KEY_LENGTH],
        nonce: &[u8; NONCE_LENGTH],
        metadata: &[u8],
    ) {
        assert_eq!(
            decrypt_with_key(encrypted_content, key, nonce, metadata),
            Err(EncryptionError::AuthenticationFailed)
        );
    }
}
