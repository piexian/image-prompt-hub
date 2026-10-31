//! 密钥与哈希工具：模板 ID、API 密钥、HMAC、SHA-256、邮箱明文加密。

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

const BASE32_LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const NONCE_LEN: usize = 12;

type HmacSha256 = Hmac<Sha256>;

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// 12 位小写 base32 字母表随机串，作为模板 ID。
pub fn generate_template_id() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    (0..12)
        .map(|_| BASE32_LOWER[rng.random_range(0..BASE32_LOWER.len())] as char)
        .collect()
}

fn encode_base32(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(BASE32_LOWER[index] as char);
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_LOWER[index] as char);
    }
    out
}

/// 32 字节随机数的 base32 编码，前缀 `iph_`。
pub fn generate_api_key() -> String {
    format!("iph_{}", encode_base32(&random_bytes(32)))
}

pub fn key_prefix(key: &str) -> String {
    key.chars().take(12).collect()
}

pub fn hmac_hex(secret: &[u8], data: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC 接受任意长度密钥");
    mac.update(data);
    hex(&mac.finalize().into_bytes())
}

/// 常量时间字节比较：长度不同直接返回 false（长度本身不是秘密），
/// 其余情况逐字节累积差异，避免用 `==` 造成时序泄漏。
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex(&hasher.finalize())
}

fn hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &byte in data {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// 32 字节一次性令牌，URL 安全 base64。
pub fn generate_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(32))
}

pub fn decode_base64_standard(data: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(data)
        .map_err(|_| "base64 解码失败".to_string())
}

/// 邮箱明文加密：nonce 前置的 ChaCha20-Poly1305，附带未加密的关联数据防止跨记录互换。
pub struct EmailCipher {
    cipher: ChaCha20Poly1305,
}

impl EmailCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
        }
    }

    pub fn encrypt(&self, email_hmac: &str, plaintext: &str) -> Vec<u8> {
        let nonce_bytes = random_bytes(NONCE_LEN);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: email_hmac.as_bytes(),
                },
            )
            .expect("ChaCha20 加密不会失败");
        [nonce_bytes, ciphertext].concat()
    }

    pub fn decrypt(&self, email_hmac: &str, data: &[u8]) -> Result<String, String> {
        if data.len() <= NONCE_LEN {
            return Err("邮箱密文损坏".to_string());
        }
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: email_hmac.as_bytes(),
                },
            )
            .map_err(|_| "邮箱密文解密失败".to_string())?;
        String::from_utf8(plaintext).map_err(|_| "邮箱明文不是有效的 UTF-8".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_id_format() {
        for _ in 0..100 {
            let id = generate_template_id();
            assert_eq!(id.len(), 12); // 12 位小写 base32
            assert!(id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        }
    }

    #[test]
    fn api_key_format() {
        let key = generate_api_key();
        assert!(key.starts_with("iph_"));
        assert_eq!(key.len(), 4 + 52); // 32 字节 base32 = 52 字符
        assert_eq!(key_prefix(&key), key[..12].to_string());
        assert_ne!(generate_api_key(), key);
    }

    #[test]
    fn hmac_and_sha256() {
        assert_eq!(hmac_hex(b"secret", b"data").len(), 64);
        assert_eq!(hmac_hex(b"secret", b"data"), hmac_hex(b"secret", b"data"));
        assert_ne!(hmac_hex(b"secret", b"data"), hmac_hex(b"other", b"data"));
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn email_cipher_roundtrip() {
        let cipher = EmailCipher::new(&[7u8; 32]);
        let hmac1 = hmac_hex(b"s", b"a@b.com");
        let sealed = cipher.encrypt(&hmac1, "a@b.com");
        assert_eq!(cipher.decrypt(&hmac1, &sealed).unwrap(), "a@b.com");
        // 关联数据不匹配（换一条记录）时解不开
        let hmac2 = hmac_hex(b"s", b"c@d.com");
        assert!(cipher.decrypt(&hmac2, &sealed).is_err());
        assert!(cipher.decrypt(&hmac1, &sealed[..5]).is_err());
        // 相同明文两次加密的密文不同（随机 nonce）
        assert_ne!(cipher.encrypt(&hmac1, "a@b.com"), sealed);
    }

    #[test]
    fn token_roundtrip() {
        let token = generate_token();
        assert_eq!(token.len(), 43);
        assert!(!token.contains('+') && !token.contains('/'));
    }
}
