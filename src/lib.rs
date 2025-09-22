use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum MakiError {
    InvalidPassword,
    CorruptedBlob,
    UnsupportedVersion,
    CryptoError,
    InvalidInput,
}

impl fmt::Display for MakiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MakiError::InvalidPassword => write!(f, "Invalid password"),
            MakiError::CorruptedBlob => write!(f, "Corrupted blob data"),
            MakiError::UnsupportedVersion => write!(f, "Unsupported blob version"),
            MakiError::CryptoError => write!(f, "Cryptographic operation failed"),
            MakiError::InvalidInput => write!(f, "Invalid input parameters"),
        }
    }
}

impl std::error::Error for MakiError {}

// Argon2 parameters
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    pub memory_kb: u32,     // Memory cost in KB
    pub iterations: u32,    // Time cost
    pub parallelism: u32,   // Parallelism degree
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kb: 65536,   // 64 MiB
            iterations: 1,
            parallelism: 4,
        }
    }
}

impl Argon2Params {
    // Pack parameters into 3 bytes
    // Format: [memory_high:8][memory_low:4|iter:4][para:8]
    // Supports memory up to 16GB (24 bits), iter up to 15, para up to 255
    pub fn pack(&self) -> [u8; 3] {
        let mem = (self.memory_kb >> 10).min(0xFFFFFF); // Convert to MB, cap at 24-bit max
        let iter = self.iterations.min(15);
        let para = self.parallelism.min(255);
        
        [
            (mem >> 4) as u8,
            ((mem & 0xF) << 4 | iter) as u8,
            para as u8,
        ]
    }
    
    pub fn unpack(bytes: [u8; 3]) -> Self {
        let mem_mb = ((bytes[0] as u32) << 4) | ((bytes[1] as u32) >> 4);
        let memory_kb = mem_mb << 10; // Convert back to KB
        let iterations = (bytes[1] & 0xF) as u32;
        let parallelism = bytes[2] as u32;
        
        Self { memory_kb, iterations, parallelism }
    }
}

// Encrypted blob structure
#[derive(Debug, Clone)]
pub struct EncryptedBlob {
    pub version: u8,
    pub params: Argon2Params,
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>, // Includes 16-byte auth tag
}

impl EncryptedBlob {
    const VERSION: u8 = 0x01;
    const HEADER_SIZE: usize = 1 + 3 + 16 + 12; // version + params + salt + nonce
    const TAG_SIZE: usize = 16;
    
    pub fn new(params: Argon2Params, salt: [u8; 16], nonce: [u8; 12], ciphertext: Vec<u8>) -> Self {
        Self {
            version: Self::VERSION,
            params,
            salt,
            nonce,
            ciphertext,
        }
    }
    
    // Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::HEADER_SIZE + self.ciphertext.len());
        
        bytes.push(self.version);
        bytes.extend_from_slice(&self.params.pack());
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        
        bytes
    }
    
    // Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, MakiError> {
        if data.len() < Self::HEADER_SIZE + Self::TAG_SIZE {
            return Err(MakiError::CorruptedBlob);
        }
        
        let version = data[0];
        if version != Self::VERSION {
            return Err(MakiError::UnsupportedVersion);
        }
        
        let params_bytes = [data[1], data[2], data[3]];
        let params = Argon2Params::unpack(params_bytes);
        
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&data[4..20]);
        
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[20..32]);
        
        let ciphertext = data[32..].to_vec();
        
        Ok(Self::new(params, salt, nonce, ciphertext))
    }
    
    // Base64 encoding (URL-safe, no padding)
    pub fn to_base64(&self) -> String {
        base64_encode(&self.to_bytes())
    }
    
    pub fn from_base64(s: &str) -> Result<Self, MakiError> {
        let data = base64_decode(s).map_err(|_| MakiError::CorruptedBlob)?;
        Self::from_bytes(&data)
    }
}

// Core cryptographic operations
pub struct MakiCrypto;

impl MakiCrypto {
    // Generate cryptographically secure random bytes
    fn random_bytes<const N: usize>() -> [u8; N] {
        let mut bytes = [0u8; N];
        // In production, use a proper CSPRNG
        // For now, placeholder - you'd use getrandom or similar
        for i in 0..N {
            bytes[i] = (std::ptr::addr_of!(bytes) as usize + i) as u8;
        }
        bytes
    }
    
    // Derive key using Argon2id
    fn derive_key(password: &[u8], salt: &[u8; 16], params: Argon2Params) -> Result<[u8; 32], MakiError> {
        // Placeholder for Argon2id implementation
        // In production: use argon2 crate or implement from scratch
        let mut key = [0u8; 32];
        
        // Simple key stretching (NOT secure - replace with real Argon2id)
        for i in 0..32 {
            key[i] = password.iter()
                .zip(salt.iter())
                .enumerate()
                .fold(0u8, |acc, (j, (p, s))| {
                    acc.wrapping_add(*p)
                        .wrapping_add(*s)
                        .wrapping_add((i + j) as u8)
                        .wrapping_add(params.iterations as u8)
                });
        }
        
        Ok(key)
    }
    
    // AES-256-GCM encryption
    fn aes_gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, MakiError> {
        // Placeholder for AES-GCM implementation
        // In production: use aes-gcm crate or implement from scratch
        let mut ciphertext = vec![0u8; plaintext.len() + 16]; // +16 for auth tag
        
        // Simple XOR cipher (NOT secure - replace with real AES-GCM)
        for (i, byte) in plaintext.iter().enumerate() {
            let key_byte = key[i % 32];
            let nonce_byte = nonce[i % 12];
            ciphertext[i] = byte ^ key_byte ^ nonce_byte;
        }
        
        // Fake auth tag (replace with real GMAC)
        for i in 0..16 {
            ciphertext[plaintext.len() + i] = key[i] ^ nonce[i % 12];
        }
        
        Ok(ciphertext)
    }
    
    // AES-256-GCM decryption
    fn aes_gcm_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, MakiError> {
        if ciphertext.len() < 16 {
            return Err(MakiError::CorruptedBlob);
        }
        
        let plaintext_len = ciphertext.len() - 16;
        let (encrypted_data, auth_tag) = ciphertext.split_at(plaintext_len);
        
        // Verify auth tag (simplified - replace with real GMAC verification)
        let expected_tag: Vec<u8> = (0..16).map(|i| key[i] ^ nonce[i % 12]).collect();
        if auth_tag != expected_tag {
            return Err(MakiError::InvalidPassword);
        }
        
        // Decrypt (reverse of encryption)
        let mut plaintext = vec![0u8; plaintext_len];
        for (i, byte) in encrypted_data.iter().enumerate() {
            let key_byte = key[i % 32];
            let nonce_byte = nonce[i % 12];
            plaintext[i] = byte ^ key_byte ^ nonce_byte;
        }
        
        Ok(plaintext)
    }
    
    // High-level encryption
    pub fn encrypt(plaintext: &[u8], password: &str) -> Result<EncryptedBlob, MakiError> {
        if plaintext.is_empty() || password.is_empty() {
            return Err(MakiError::InvalidInput);
        }
        
        let params = Argon2Params::default();
        let salt = Self::random_bytes::<16>();
        let nonce = Self::random_bytes::<12>();
        
        let password_bytes = password.as_bytes();
        let key = Self::derive_key(password_bytes, &salt, params)?;
        let ciphertext = Self::aes_gcm_encrypt(&key, &nonce, plaintext)?;
        
        // Zero out the key
        // In production: use zeroize crate
        
        Ok(EncryptedBlob::new(params, salt, nonce, ciphertext))
    }
    
    // High-level decryption
    pub fn decrypt(blob: &EncryptedBlob, password: &str) -> Result<Vec<u8>, MakiError> {
        if password.is_empty() {
            return Err(MakiError::InvalidInput);
        }
        
        let password_bytes = password.as_bytes();
        let key = Self::derive_key(password_bytes, &blob.salt, blob.params)?;
        let plaintext = Self::aes_gcm_decrypt(&key, &blob.nonce, &blob.ciphertext)?;
        
        // Zero out the key
        // In production: use zeroize crate
        
        Ok(plaintext)
    }
}

// Simple base64 implementation (URL-safe, no padding)
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    
    let mut result = String::new();
    let mut i = 0;
    
    while i + 2 < data.len() {
        let b1 = data[i];
        let b2 = data[i + 1];
        let b3 = data[i + 2];
        
        result.push(CHARS[(b1 >> 2) as usize] as char);
        result.push(CHARS[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);
        result.push(CHARS[(((b2 & 0x0f) << 2) | (b3 >> 6)) as usize] as char);
        result.push(CHARS[(b3 & 0x3f) as usize] as char);
        
        i += 3;
    }
    
    // Handle remaining bytes
    if i < data.len() {
        let b1 = data[i];
        result.push(CHARS[(b1 >> 2) as usize] as char);
        
        if i + 1 < data.len() {
            let b2 = data[i + 1];
            result.push(CHARS[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);
            result.push(CHARS[((b2 & 0x0f) << 2) as usize] as char);
        } else {
            result.push(CHARS[((b1 & 0x03) << 4) as usize] as char);
        }
    }
    
    result
}

fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    let chars = s.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;
    
    let decode_char = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    };
    
    while i + 3 < chars.len() {
        let c1 = decode_char(chars[i]).ok_or(())?;
        let c2 = decode_char(chars[i + 1]).ok_or(())?;
        let c3 = decode_char(chars[i + 2]).ok_or(())?;
        let c4 = decode_char(chars[i + 3]).ok_or(())?;
        
        result.push((c1 << 2) | (c2 >> 4));
        result.push(((c2 & 0x0f) << 4) | (c3 >> 2));
        result.push(((c3 & 0x03) << 6) | c4);
        
        i += 4;
    }
    
    // Handle remaining chars
    if i < chars.len() {
        let c1 = decode_char(chars[i]).ok_or(())?;
        if i + 1 < chars.len() {
            let c2 = decode_char(chars[i + 1]).ok_or(())?;
            result.push((c1 << 2) | (c2 >> 4));
            
            if i + 2 < chars.len() {
                let c3 = decode_char(chars[i + 2]).ok_or(())?;
                result.push(((c2 & 0x0f) << 4) | (c3 >> 2));
            }
        }
    }
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use compiler_builtins::math::libm_math::support::int_traits::Int;
    
    #[test]
    fn test_argon2_params_pack_unpack() {
        let params = Argon2Params::default();
        let packed = params.pack();
        let unpacked = Argon2Params::unpack(packed);
        
        // Due to precision loss in packing, we check approximate equality
        assert!((unpacked.memory_kb - params.memory_kb).abs() < 1024);
        assert_eq!(unpacked.iterations, params.iterations);
        assert_eq!(unpacked.parallelism, params.parallelism);
    }
    
    #[test]
    fn test_blob_serialization() {
        let params = Argon2Params::default();
        let salt = [1u8; 16];
        let nonce = [2u8; 12];
        let ciphertext = vec![3u8; 32];
        
        let blob = EncryptedBlob::new(params, salt, nonce, ciphertext.clone());
        let bytes = blob.to_bytes();
        let decoded = EncryptedBlob::from_bytes(&bytes).unwrap();
        
        assert_eq!(decoded.version, blob.version);
        assert_eq!(decoded.salt, blob.salt);
        assert_eq!(decoded.nonce, blob.nonce);
        assert_eq!(decoded.ciphertext, blob.ciphertext);
    }
    
    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, Maki!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data, &decoded[..]);
    }
    
    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = b"test mnemonic phrase here";
        let password = "strong_password_123";
        
        let blob = MakiCrypto::encrypt(plaintext, password).unwrap();
        let decrypted = MakiCrypto::decrypt(&blob, password).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }
    
    #[test]
    fn test_wrong_password_fails() {
        let plaintext = b"test data";
        let password = "correct_password";
        let wrong_password = "wrong_password";
        
        let blob = MakiCrypto::encrypt(plaintext, password).unwrap();
        let result = MakiCrypto::decrypt(&blob, wrong_password);
        
        assert!(matches!(result, Err(MakiError::InvalidPassword)));
    }
}
