//! Maki's cryptographic core.

use std::fmt;

use base64ct::{Base64UrlUnpadded, Encoding};
use zeroize::Zeroizing;

mod argon;
mod xchacha;

pub use argon::{
    Argon2Settings, KEY_LENGTH, KeyDerivationError, SALT_LENGTH, derive_key, generate_salt,
};
pub use xchacha::{
    EncryptionError, NONCE_LENGTH, TAG_LENGTH, decrypt_with_key, encrypt_with_key, generate_nonce,
};

use argon::{derive_key_with_settings, settings_are_safe};

/// Recommended maximum size of a secret, in bytes.
pub const DEFAULT_MAX_SECRET_SIZE: usize = 4 * 1024;

/// Prefix identifying text produced by Maki.
pub const TEXT_PREFIX: &str = "maki:";

const MEMORY_END: usize = size_of::<u32>();
const PASSES_END: usize = MEMORY_END + size_of::<u32>();
const LANES_END: usize = PASSES_END + size_of::<u32>();
const SALT_END: usize = LANES_END + SALT_LENGTH;
const NONCE_END: usize = SALT_END + NONCE_LENGTH;
const HEADER_LENGTH: usize = NONCE_END;

/// Errors produced while requesting random bytes from the operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomnessError {
    Unavailable,
}

impl fmt::Display for RandomnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secure operating-system randomness is unavailable")
    }
}

impl std::error::Error for RandomnessError {}

/// Errors produced by Maki's complete protection and recovery workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MakiError {
    EmptySecret,
    EmptyPassword,
    SecretTooLarge,
    InvalidSecretLimit,
    InvalidText,
    UnsafeParameters,
    RandomnessUnavailable,
    KeyDerivationFailed,
    EncryptionFailed,
    AuthenticationFailed,
}

impl fmt::Display for MakiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySecret => formatter.write_str("secret cannot be empty"),
            Self::EmptyPassword => formatter.write_str("password cannot be empty"),
            Self::SecretTooLarge => formatter.write_str("secret exceeds the configured size limit"),
            Self::InvalidSecretLimit => formatter.write_str("invalid secret size limit"),
            Self::InvalidText => formatter.write_str("invalid Maki encrypted text"),
            Self::UnsafeParameters => formatter.write_str("unsafe Argon2id parameters"),
            Self::RandomnessUnavailable => {
                formatter.write_str("secure operating-system randomness is unavailable")
            }
            Self::KeyDerivationFailed => formatter.write_str("Argon2id key derivation failed"),
            Self::EncryptionFailed => formatter.write_str("encryption failed"),
            Self::AuthenticationFailed => {
                formatter.write_str("password is incorrect or encrypted content was changed")
            }
        }
    }
}

impl std::error::Error for MakiError {}

fn random_array<const N: usize>() -> Result<[u8; N], RandomnessError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| RandomnessError::Unavailable)?;
    Ok(bytes)
}

/// Protects a secret using Maki's recommended 4-KiB secret-size limit.
///
/// `password` is arbitrary binary data and has no Maki-imposed size limit.
pub fn protect(secret: &[u8], password: &[u8]) -> Result<String, MakiError> {
    protect_with_limit(secret, password, DEFAULT_MAX_SECRET_SIZE)
}

/// Protects a secret using a caller-selected secret-size limit.
///
/// The result starts with [`TEXT_PREFIX`] and contains URL-safe Base64 without
/// padding. A fresh salt and nonce are generated for every call.
pub fn protect_with_limit(
    secret: &[u8],
    password: &[u8],
    max_secret_size: usize,
) -> Result<String, MakiError> {
    validate_protection_input(secret, password, max_secret_size)?;
    let salt = generate_salt().map_err(|_| MakiError::RandomnessUnavailable)?;
    let nonce = generate_nonce().map_err(|_| MakiError::RandomnessUnavailable)?;

    protect_with_settings_and_material(
        secret,
        password,
        max_secret_size,
        Argon2Settings::default(),
        salt,
        nonce,
    )
}

/// Recovers a secret using Maki's recommended 4-KiB secret-size limit.
pub fn recover(encrypted_text: &str, password: &[u8]) -> Result<Zeroizing<Vec<u8>>, MakiError> {
    recover_with_limit(encrypted_text, password, DEFAULT_MAX_SECRET_SIZE)
}

/// Recovers a secret using a caller-selected secret-size limit.
///
/// `password` must contain the exact bytes supplied during protection. Text
/// normalization, whitespace removal, and file conversion are not performed.
pub fn recover_with_limit(
    encrypted_text: &str,
    password: &[u8],
    max_secret_size: usize,
) -> Result<Zeroizing<Vec<u8>>, MakiError> {
    let max_text_length = maximum_text_length(max_secret_size)?;
    if password.is_empty() {
        return Err(MakiError::EmptyPassword);
    }
    if encrypted_text.len() > max_text_length {
        return Err(MakiError::SecretTooLarge);
    }

    let encoded = encrypted_text
        .strip_prefix(TEXT_PREFIX)
        .ok_or(MakiError::InvalidText)?;
    if encoded.is_empty() {
        return Err(MakiError::InvalidText);
    }

    let decoded = Base64UrlUnpadded::decode_vec(encoded).map_err(|_| MakiError::InvalidText)?;
    let minimum_length = HEADER_LENGTH
        .checked_add(TAG_LENGTH)
        .and_then(|length| length.checked_add(1))
        .ok_or(MakiError::InvalidSecretLimit)?;
    if decoded.len() < minimum_length {
        return Err(MakiError::InvalidText);
    }

    let maximum_encrypted_length = max_secret_size
        .checked_add(TAG_LENGTH)
        .ok_or(MakiError::InvalidSecretLimit)?;
    if decoded.len() - HEADER_LENGTH > maximum_encrypted_length {
        return Err(MakiError::SecretTooLarge);
    }

    let header = &decoded[..HEADER_LENGTH];
    let encrypted_content = &decoded[HEADER_LENGTH..];
    let settings = parse_settings(header)?;
    validate_settings(settings)?;

    let mut salt = [0_u8; SALT_LENGTH];
    salt.copy_from_slice(&header[LANES_END..SALT_END]);
    let mut nonce = [0_u8; NONCE_LENGTH];
    nonce.copy_from_slice(&header[SALT_END..NONCE_END]);

    let key = derive_key_with_settings(password, &salt, settings)
        .map_err(|_| MakiError::KeyDerivationFailed)?;
    let metadata = authenticated_metadata(header);

    decrypt_with_key(encrypted_content, &key, &nonce, &metadata)
        .map_err(|_| MakiError::AuthenticationFailed)
}

fn protect_with_settings_and_material(
    secret: &[u8],
    password: &[u8],
    max_secret_size: usize,
    settings: Argon2Settings,
    salt: [u8; SALT_LENGTH],
    nonce: [u8; NONCE_LENGTH],
) -> Result<String, MakiError> {
    validate_protection_input(secret, password, max_secret_size)?;
    validate_settings(settings)?;

    let key = derive_key_with_settings(password, &salt, settings)
        .map_err(|_| MakiError::KeyDerivationFailed)?;
    let header = build_header(settings, &salt, &nonce);
    let metadata = authenticated_metadata(&header);
    let encrypted_content = encrypt_with_key(secret, &key, &nonce, &metadata)
        .map_err(|_| MakiError::EncryptionFailed)?;

    let mut data = Vec::with_capacity(HEADER_LENGTH + encrypted_content.len());
    data.extend_from_slice(&header);
    data.extend_from_slice(&encrypted_content);

    let encoded = Base64UrlUnpadded::encode_string(&data);
    let mut encrypted_text = String::with_capacity(TEXT_PREFIX.len() + encoded.len());
    encrypted_text.push_str(TEXT_PREFIX);
    encrypted_text.push_str(&encoded);
    Ok(encrypted_text)
}

fn validate_protection_input(
    secret: &[u8],
    password: &[u8],
    max_secret_size: usize,
) -> Result<(), MakiError> {
    maximum_text_length(max_secret_size)?;
    if secret.is_empty() {
        return Err(MakiError::EmptySecret);
    }
    if password.is_empty() {
        return Err(MakiError::EmptyPassword);
    }
    if secret.len() > max_secret_size {
        return Err(MakiError::SecretTooLarge);
    }
    Ok(())
}

fn validate_settings(settings: Argon2Settings) -> Result<(), MakiError> {
    settings_are_safe(settings)
        .then_some(())
        .ok_or(MakiError::UnsafeParameters)
}

fn build_header(
    settings: Argon2Settings,
    salt: &[u8; SALT_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
) -> [u8; HEADER_LENGTH] {
    // Permanent header layout, using big-endian integers:
    // [memory:4][passes:4][lanes:4][salt:16][nonce:24]
    let mut header = [0_u8; HEADER_LENGTH];
    header[0..MEMORY_END].copy_from_slice(&settings.memory_kib.to_be_bytes());
    header[MEMORY_END..PASSES_END].copy_from_slice(&settings.passes.to_be_bytes());
    header[PASSES_END..LANES_END].copy_from_slice(&settings.lanes.to_be_bytes());
    header[LANES_END..SALT_END].copy_from_slice(salt);
    header[SALT_END..NONCE_END].copy_from_slice(nonce);
    header
}

fn parse_settings(header: &[u8]) -> Result<Argon2Settings, MakiError> {
    let memory_kib = u32::from_be_bytes(
        header[0..MEMORY_END]
            .try_into()
            .map_err(|_| MakiError::InvalidText)?,
    );
    let passes = u32::from_be_bytes(
        header[MEMORY_END..PASSES_END]
            .try_into()
            .map_err(|_| MakiError::InvalidText)?,
    );
    let lanes = u32::from_be_bytes(
        header[PASSES_END..LANES_END]
            .try_into()
            .map_err(|_| MakiError::InvalidText)?,
    );
    Ok(Argon2Settings {
        memory_kib,
        passes,
        lanes,
    })
}

fn authenticated_metadata(header: &[u8]) -> Vec<u8> {
    let mut metadata = Vec::with_capacity(TEXT_PREFIX.len() + header.len());
    metadata.extend_from_slice(TEXT_PREFIX.as_bytes());
    metadata.extend_from_slice(header);
    metadata
}

fn maximum_text_length(max_secret_size: usize) -> Result<usize, MakiError> {
    if max_secret_size == 0 {
        return Err(MakiError::InvalidSecretLimit);
    }

    let maximum_data_length = HEADER_LENGTH
        .checked_add(TAG_LENGTH)
        .and_then(|length| length.checked_add(max_secret_size))
        .ok_or(MakiError::InvalidSecretLimit)?;
    if maximum_data_length > usize::MAX / 4 {
        return Err(MakiError::InvalidSecretLimit);
    }
    let encoded_length =
        base64_unpadded_length(maximum_data_length).ok_or(MakiError::InvalidSecretLimit)?;
    TEXT_PREFIX
        .len()
        .checked_add(encoded_length)
        .ok_or(MakiError::InvalidSecretLimit)
}

fn base64_unpadded_length(byte_length: usize) -> Option<usize> {
    let full_groups = (byte_length / 3).checked_mul(4)?;
    let remainder = match byte_length % 3 {
        0 => 0,
        1 => 2,
        _ => 3,
    };
    full_groups.checked_add(remainder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operating_system_random_generation_succeeds() {
        generate_salt().unwrap();
        generate_nonce().unwrap();
    }

    #[test]
    fn password_derived_key_encrypts_and_recovers_the_secret() {
        let password = b"correct horse battery staple";
        let secret =
            b"abandon ability able about above absent absorb abstract absurd abuse access accident";
        let salt = [0x2a; SALT_LENGTH];
        let nonce = [0x7c; NONCE_LENGTH];
        let metadata = b"maki authenticated metadata";
        let settings = lightweight_test_settings();

        let encryption_key = derive_key_with_settings(password, &salt, settings).unwrap();
        let encrypted = encrypt_with_key(secret, &encryption_key, &nonce, metadata).unwrap();

        let recovery_key = derive_key_with_settings(password, &salt, settings).unwrap();
        let recovered = decrypt_with_key(&encrypted, &recovery_key, &nonce, metadata).unwrap();

        assert_eq!(recovered.as_slice(), secret);
    }

    #[test]
    fn wrong_password_fails_authentication() {
        let salt = [0x2a; SALT_LENGTH];
        let nonce = [0x7c; NONCE_LENGTH];
        let metadata = b"maki authenticated metadata";
        let settings = lightweight_test_settings();
        let encryption_key =
            derive_key_with_settings(b"correct password", &salt, settings).unwrap();
        let encrypted =
            encrypt_with_key(b"test secret", &encryption_key, &nonce, metadata).unwrap();

        let wrong_key = derive_key_with_settings(b"wrong password", &salt, settings).unwrap();

        assert_authentication_fails(&encrypted, &wrong_key, &nonce, metadata);
    }

    #[test]
    fn complete_workflow_protects_and_recovers_the_secret() {
        let secret =
            b"abandon ability able about above absent absorb abstract absurd abuse access accident";
        let password = b"correct horse battery staple";
        let encrypted_text = protect_test_secret(secret, password, DEFAULT_MAX_SECRET_SIZE);

        let recovered = recover(&encrypted_text, password).unwrap();

        assert_eq!(recovered.as_slice(), secret);
        assert!(encrypted_text.starts_with(TEXT_PREFIX));
        assert!(
            encrypted_text[TEXT_PREFIX.len()..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
    }

    #[test]
    fn complete_workflow_rejects_the_wrong_password() {
        let encrypted_text =
            protect_test_secret(b"test secret", b"correct password", DEFAULT_MAX_SECRET_SIZE);

        assert_eq!(
            recover(&encrypted_text, b"wrong password"),
            Err(MakiError::AuthenticationFailed)
        );
    }

    #[test]
    fn custom_secret_limit_allows_a_larger_secret() {
        let secret = vec![0x5a; DEFAULT_MAX_SECRET_SIZE + 1];
        let custom_limit = secret.len();

        assert_eq!(
            protect_with_settings_and_material(
                &secret,
                b"password",
                DEFAULT_MAX_SECRET_SIZE,
                lightweight_test_settings(),
                [0x2a; SALT_LENGTH],
                [0x7c; NONCE_LENGTH],
            ),
            Err(MakiError::SecretTooLarge)
        );

        let encrypted_text = protect_test_secret(&secret, b"password", custom_limit);
        assert_eq!(
            recover(&encrypted_text, b"password"),
            Err(MakiError::SecretTooLarge)
        );

        let recovered = recover_with_limit(&encrypted_text, b"password", custom_limit).unwrap();
        assert_eq!(recovered.as_slice(), secret);
    }

    #[test]
    fn arbitrary_binary_password_has_no_maki_size_limit() {
        let password: Vec<u8> = (0..128 * 1024_usize)
            .map(|index| (index.wrapping_mul(31) & 0xff) as u8)
            .collect();
        let encrypted_text =
            protect_test_secret(b"test secret", &password, DEFAULT_MAX_SECRET_SIZE);

        let recovered = recover(&encrypted_text, &password).unwrap();

        assert_eq!(recovered.as_slice(), b"test secret");
    }

    #[test]
    fn empty_inputs_are_rejected_before_cryptography() {
        assert_eq!(protect(b"", b"password"), Err(MakiError::EmptySecret));
        assert_eq!(protect(b"secret", b""), Err(MakiError::EmptyPassword));
        assert_eq!(recover("", b"password"), Err(MakiError::InvalidText));
        assert_eq!(recover("maki:", b"password"), Err(MakiError::InvalidText));
        assert_eq!(
            recover("maki:not+base64", b"password"),
            Err(MakiError::InvalidText)
        );
        assert_eq!(recover("maki:AAAA", b""), Err(MakiError::EmptyPassword));
    }

    #[test]
    fn complete_header_uses_the_agreed_layout() {
        let settings = lightweight_test_settings();
        let salt = [0x2a; SALT_LENGTH];
        let nonce = [0x7c; NONCE_LENGTH];
        let encrypted_text = protect_with_settings_and_material(
            b"test secret",
            b"password",
            DEFAULT_MAX_SECRET_SIZE,
            settings,
            salt,
            nonce,
        )
        .unwrap();
        let decoded = decode_encrypted_text(&encrypted_text);

        assert_eq!(&decoded[0..4], &settings.memory_kib.to_be_bytes());
        assert_eq!(&decoded[4..8], &settings.passes.to_be_bytes());
        assert_eq!(&decoded[8..12], &settings.lanes.to_be_bytes());
        assert_eq!(&decoded[12..28], &salt);
        assert_eq!(&decoded[28..52], &nonce);
        assert_eq!(
            decoded.len(),
            HEADER_LENGTH + b"test secret".len() + TAG_LENGTH
        );
    }

    #[test]
    fn changing_the_authenticated_header_fails_recovery() {
        let password = b"password";
        let encrypted_text = protect_test_secret(b"test secret", password, DEFAULT_MAX_SECRET_SIZE);
        let mut decoded = decode_encrypted_text(&encrypted_text);
        decoded[12] ^= 1;
        let changed_text = encode_encrypted_data(&decoded);

        assert_eq!(
            recover(&changed_text, password),
            Err(MakiError::AuthenticationFailed)
        );
    }

    #[test]
    fn changing_the_encrypted_content_fails_recovery() {
        let password = b"password";
        let encrypted_text = protect_test_secret(b"test secret", password, DEFAULT_MAX_SECRET_SIZE);
        let mut decoded = decode_encrypted_text(&encrypted_text);
        let last = decoded.len() - 1;
        decoded[last] ^= 1;
        let changed_text = encode_encrypted_data(&decoded);

        assert_eq!(
            recover(&changed_text, password),
            Err(MakiError::AuthenticationFailed)
        );
    }

    #[test]
    fn unsafe_parameters_are_rejected_before_key_derivation() {
        let encrypted_text =
            protect_test_secret(b"test secret", b"password", DEFAULT_MAX_SECRET_SIZE);
        let mut decoded = decode_encrypted_text(&encrypted_text);
        decoded[0..4].copy_from_slice(&(Argon2Settings::default().memory_kib + 1).to_be_bytes());
        let changed_text = encode_encrypted_data(&decoded);

        assert_eq!(
            recover(&changed_text, b"password"),
            Err(MakiError::UnsafeParameters)
        );
    }

    #[test]
    fn different_salt_and_nonce_produce_different_text() {
        let first = protect_with_settings_and_material(
            b"test secret",
            b"password",
            DEFAULT_MAX_SECRET_SIZE,
            lightweight_test_settings(),
            [1; SALT_LENGTH],
            [2; NONCE_LENGTH],
        )
        .unwrap();
        let second = protect_with_settings_and_material(
            b"test secret",
            b"password",
            DEFAULT_MAX_SECRET_SIZE,
            lightweight_test_settings(),
            [3; SALT_LENGTH],
            [4; NONCE_LENGTH],
        )
        .unwrap();

        assert_ne!(first, second);
    }

    fn protect_test_secret(secret: &[u8], password: &[u8], max_secret_size: usize) -> String {
        protect_with_settings_and_material(
            secret,
            password,
            max_secret_size,
            lightweight_test_settings(),
            [0x2a; SALT_LENGTH],
            [0x7c; NONCE_LENGTH],
        )
        .unwrap()
    }

    fn decode_encrypted_text(encrypted_text: &str) -> Vec<u8> {
        Base64UrlUnpadded::decode_vec(
            encrypted_text
                .strip_prefix(TEXT_PREFIX)
                .expect("Maki prefix"),
        )
        .unwrap()
    }

    fn encode_encrypted_data(data: &[u8]) -> String {
        format!("{TEXT_PREFIX}{}", Base64UrlUnpadded::encode_string(data))
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

    fn lightweight_test_settings() -> Argon2Settings {
        Argon2Settings {
            memory_kib: 8 * 1024,
            passes: 1,
            lanes: 1,
        }
    }
}
