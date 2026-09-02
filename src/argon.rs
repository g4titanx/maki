//! Argon2id key derivation and salt generation.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::{RandomnessError, random_array};

/// Number of bytes in a Maki salt.
pub const SALT_LENGTH: usize = 16;

/// Number of bytes in a Maki encryption key.
pub const KEY_LENGTH: usize = 32;

const MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024;
const MAX_WORK_KIB: u64 = MAX_MEMORY_KIB as u64;
const MAX_PASSES: u32 = 10;
const MAX_LANES: u32 = 16;

/// Argon2id settings used when Maki creates new encrypted content.
///
/// Maki's defaults follow RFC 9106's first recommended Argon2id profile:
/// 2 GiB of memory, one pass, and four lanes. This profile prioritizes a large
/// memory requirement over repeated passes through a smaller memory area. See
/// <https://www.rfc-editor.org/rfc/rfc9106.html#section-7.4>.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Settings {
    /// Total memory used by one derivation, in KiB.
    ///
    /// This is the total across all lanes, not the amount used by each lane.
    /// With Maki's defaults, 2,097,152 KiB is 2 GiB total, divided into four
    /// lanes of approximately 512 MiB each.
    pub memory_kib: u32,
    /// Number of passes over the complete memory area.
    ///
    /// One pass means Argon2id initializes and mixes the complete 2-GiB memory
    /// area once. Increasing this value would make both legitimate recovery
    /// and every attacker password guess more expensive.
    pub passes: u32,
    /// Number of processing lanes into which the memory is divided.
    ///
    /// Four lanes allow a multicore CPU to process parts of the memory
    /// concurrently. This does not multiply the total memory by four and is
    /// not, by itself, a fourfold security increase.
    pub lanes: u32,
}

impl Default for Argon2Settings {
    fn default() -> Self {
        Self {
            memory_kib: 2 * 1024 * 1024,
            passes: 1,
            lanes: 4,
        }
    }
}

/// Errors produced while turning a password into an encryption key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDerivationError {
    InvalidSettings,
    DerivationFailed,
}

impl fmt::Display for KeyDerivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSettings => formatter.write_str("invalid Argon2id settings"),
            Self::DerivationFailed => formatter.write_str("Argon2id key derivation failed"),
        }
    }
}

impl std::error::Error for KeyDerivationError {}

/// Generates a fresh 128-bit salt using the operating system's secure random
/// number generator.
pub fn generate_salt() -> Result<[u8; SALT_LENGTH], RandomnessError> {
    random_array()
}

/// Derives Maki's 256-bit encryption key from `password` and `salt`.
///
/// The returned key is zeroized when it is dropped. The caller still owns the
/// password and is responsible for zeroizing its storage after use.
pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LENGTH],
) -> Result<Zeroizing<[u8; KEY_LENGTH]>, KeyDerivationError> {
    derive_key_with_settings(password, salt, Argon2Settings::default())
}

pub(crate) fn derive_key_with_settings(
    password: &[u8],
    salt: &[u8],
    settings: Argon2Settings,
) -> Result<Zeroizing<[u8; KEY_LENGTH]>, KeyDerivationError> {
    let params = Params::new(
        settings.memory_kib,
        settings.passes,
        settings.lanes,
        Some(KEY_LENGTH),
    )
    .map_err(|_| KeyDerivationError::InvalidSettings)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; KEY_LENGTH]);

    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| KeyDerivationError::DerivationFailed)?;

    Ok(key)
}

pub(crate) fn settings_are_safe(settings: Argon2Settings) -> bool {
    if settings.passes == 0
        || settings.passes > MAX_PASSES
        || settings.lanes == 0
        || settings.lanes > MAX_LANES
        || settings.memory_kib > MAX_MEMORY_KIB
    {
        return false;
    }

    let Some(minimum_memory) = settings.lanes.checked_mul(8) else {
        return false;
    };
    let work = u64::from(settings.memory_kib) * u64::from(settings.passes);
    if settings.memory_kib < minimum_memory || work > MAX_WORK_KIB {
        return false;
    }

    Params::new(
        settings.memory_kib,
        settings.passes,
        settings.lanes,
        Some(KEY_LENGTH),
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_match_the_agreed_profile() {
        assert_eq!(
            Argon2Settings::default(),
            Argon2Settings {
                memory_kib: 2_097_152,
                passes: 1,
                lanes: 4,
            }
        );
    }

    #[test]
    fn matches_the_argon2_reference_known_answer() {
        // Published by the Argon2 reference implementation for Argon2id v1.3:
        // password="password", salt="somesalt", m=65536, t=2, p=1.
        let expected = [
            0x09, 0x31, 0x61, 0x15, 0xd5, 0xcf, 0x24, 0xed, 0x5a, 0x15, 0xa3, 0x1a, 0x3b, 0xa3,
            0x26, 0xe5, 0xcf, 0x32, 0xed, 0xc2, 0x47, 0x02, 0x98, 0x7c, 0x02, 0xb6, 0x56, 0x6f,
            0x61, 0x91, 0x3c, 0xf7,
        ];

        let key = derive_key_with_settings(
            b"password",
            b"somesalt",
            Argon2Settings {
                memory_kib: 65_536,
                passes: 2,
                lanes: 1,
            },
        )
        .unwrap();

        assert_eq!(key.as_ref(), expected.as_slice());
    }

    #[test]
    fn salt_changes_the_derived_key() {
        let settings = lightweight_test_settings();
        let first =
            derive_key_with_settings(b"correct horse battery staple", &[1; SALT_LENGTH], settings)
                .unwrap();
        let second =
            derive_key_with_settings(b"correct horse battery staple", &[2; SALT_LENGTH], settings)
                .unwrap();

        assert_ne!(first.as_ref(), second.as_ref());
    }

    #[test]
    fn password_changes_the_derived_key() {
        let salt = [7; SALT_LENGTH];
        let settings = lightweight_test_settings();
        let first = derive_key_with_settings(b"first password", &salt, settings).unwrap();
        let second = derive_key_with_settings(b"second password", &salt, settings).unwrap();

        assert_ne!(first.as_ref(), second.as_ref());
    }

    fn lightweight_test_settings() -> Argon2Settings {
        Argon2Settings {
            memory_kib: 8 * 1024,
            passes: 1,
            lanes: 1,
        }
    }
}
