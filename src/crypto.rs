/*

# Step 1 —— 增加一个真正的 KDF（最关键！）
pass_key = Argon2id(pass, salt)

# Step 2 —— 用 HKDF 派生不同用途的密钥
enc_key, mac_key, portal_id = HKDF(pass_key, info=f"portal-{tunnel_id}", L=96)

# Step 3 —— 签名使用 mac_key（不再用 pass_key）
portal_sign = HMAC_SHA256(portal_id + salt + nonce, mac_key)

# Step 4 —— 加密使用 enc_key（不再用 pass_key）
portal_data = salt + nonce + AES-GCM(Serialize(data), enc_key)

# Step 5 —— 最终消息保持你的结构
portal_msg = portal_sign + portal_data
*/

use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum PortalCryptoError {
    InvalidInput,
    EncryptionError,
    DecryptionError,
    InvalidSignature,
    Argon2Error,
    HkdfError,
}

impl fmt::Display for PortalCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PortalCryptoError::InvalidInput => write!(f, "Invalid input data"),
            PortalCryptoError::EncryptionError => write!(f, "Encryption failed"),
            PortalCryptoError::DecryptionError => write!(f, "Decryption failed"),
            PortalCryptoError::InvalidSignature => write!(f, "Invalid signature"),
            PortalCryptoError::Argon2Error => write!(f, "Argon2 key derivation failed"),
            PortalCryptoError::HkdfError => write!(f, "HKDF key derivation failed"),
        }
    }
}

impl Error for PortalCryptoError {}

pub struct PortalCrypto<'a> {
    pub tunnel_id: &'a str,
    pub pass: &'a str,
}

impl<'a> PortalCrypto<'a> {
    /// 创建新的PortalCrypto实例
    pub fn new(tunnel_id: &'a str, pass: &'a str) -> Self {
        Self { tunnel_id, pass }
    }

    /// 快速检查portal消息是否有效（只验证签名，不解密）
    pub fn check_valid(&self, portal_msg: &[u8]) -> Result<bool, PortalCryptoError> {
        // portal_msg长度至少需要：sign(32) + argon2_salt(32) + hkdf_salt(32) + salt(32) + nonce(12)
        if portal_msg.len() < 32 + 32 + 32 + 32 + 12 {
            return Ok(false);
        }

        // 分割sign和portal_data
        let (received_sign, portal_data) = portal_msg.split_at(32);
        let (argon2_salt, rest) = portal_data.split_at(32);
        let (hkdf_salt, rest2) = rest.split_at(32);
        let (salt, rest3) = rest2.split_at(32);
        let (nonce, _encrypted_data) = rest3.split_at(12);

        // Step 1: 使用 Argon2id 派生 pass_key
        let pass_key = self.derive_pass_key(
            argon2_salt
                .try_into()
                .map_err(|_| PortalCryptoError::InvalidInput)?,
        )?;

        // Step 2: 使用 HKDF 派生密钥
        let (_enc_key, mac_key, portal_id) = self.derive_keys(
            &pass_key,
            hkdf_salt
                .try_into()
                .map_err(|_| PortalCryptoError::InvalidInput)?,
        )?;

        // Step 3: 计算期望签名
        let expected_sign = self.compute_portal_sign(
            &portal_id,
            salt.try_into()
                .map_err(|_| PortalCryptoError::InvalidInput)?,
            nonce
                .try_into()
                .map_err(|_| PortalCryptoError::InvalidInput)?,
            &mac_key,
        )?;

        Ok(received_sign == expected_sign.as_slice())
    }

    /// Step 1: 使用 Argon2id 派生密钥
    pub fn derive_pass_key(&self, salt: &[u8; 32]) -> Result<[u8; 32], PortalCryptoError> {
        let argon2 = Argon2::default();
        let salt_string =
            SaltString::encode_b64(salt).map_err(|_| PortalCryptoError::Argon2Error)?;

        let password_hash = argon2
            .hash_password(self.pass.as_bytes(), &salt_string)
            .map_err(|_| PortalCryptoError::Argon2Error)?;

        let hash_bytes = password_hash.hash.unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes.as_bytes()[..32]);
        Ok(key)
    }

    /// Step 2: 使用 HKDF 派生不同用途的密钥
    /// 返回 (enc_key, mac_key, portal_id)
    pub fn derive_keys(
        &self,
        pass_key: &[u8; 32],
        hkdf_salt: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32], [u8; 32]), PortalCryptoError> {
        let hk = Hkdf::<Sha256>::new(Some(hkdf_salt), pass_key);
        let mut okm = [0u8; 96]; // 32 + 32 + 32

        let info = format!("portal-{}", self.tunnel_id);
        hk.expand(info.as_bytes(), &mut okm)
            .map_err(|_| PortalCryptoError::HkdfError)?;

        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        let mut portal_id = [0u8; 32];

        enc_key.copy_from_slice(&okm[0..32]);
        mac_key.copy_from_slice(&okm[32..64]);
        portal_id.copy_from_slice(&okm[64..96]);

        Ok((enc_key, mac_key, portal_id))
    }

    /// Step 3: 计算portal_sign = HMAC_SHA256(portal_id + salt + nonce, mac_key)
    pub fn compute_portal_sign(
        &self,
        portal_id: &[u8; 32],
        salt: &[u8; 32],
        nonce: &[u8; 12],
        mac_key: &[u8; 32],
    ) -> Result<[u8; 32], PortalCryptoError> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(mac_key)
            .map_err(|_| PortalCryptoError::InvalidInput)?;

        mac.update(portal_id);
        mac.update(salt);
        mac.update(nonce);

        let result = mac.finalize().into_bytes();
        Ok(result.into())
    }

    /// Step 4: 使用AES-GCM加密数据 (使用 enc_key)
    pub fn encrypt_data<T: Serialize>(
        &self,
        data: &T,
        enc_key: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>, PortalCryptoError> {
        let json_data = serde_json::to_vec(data).map_err(|_| PortalCryptoError::InvalidInput)?;

        let key = Key::<Aes256Gcm>::from_slice(enc_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);

        cipher
            .encrypt(nonce, json_data.as_ref())
            .map_err(|_| PortalCryptoError::EncryptionError)
    }

    /// Step 4: 使用AES-GCM解密数据 (使用 enc_key)
    pub fn decrypt_data<T: for<'de> Deserialize<'de>>(
        &self,
        ciphertext: &[u8],
        enc_key: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Result<T, PortalCryptoError> {
        let key = Key::<Aes256Gcm>::from_slice(enc_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| PortalCryptoError::DecryptionError)?;

        serde_json::from_slice(&plaintext).map_err(|_| PortalCryptoError::DecryptionError)
    }

    /// 生成随机salt (32字节)
    pub fn generate_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// 生成随机nonce (12字节)
    pub fn generate_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Step 5: 构建完整的portal消息
    pub fn build_portal_message<T: Serialize>(
        &self,
        data: &T,
    ) -> Result<Vec<u8>, PortalCryptoError> {
        // Step 1: 生成 Argon2id salt 并派生 pass_key
        let argon2_salt = Self::generate_salt();
        let pass_key = self.derive_pass_key(&argon2_salt)?;

        // Step 2: 生成 HKDF salt 并派生密钥
        let hkdf_salt = Self::generate_salt();
        let (enc_key, mac_key, portal_id) = self.derive_keys(&pass_key, &hkdf_salt)?;

        // Step 3: 生成加密用的 salt 和 nonce
        let salt = Self::generate_salt();
        let nonce = Self::generate_nonce();

        // Step 4: portal_sign = HMAC_SHA256(portal_id + salt + nonce, mac_key)
        let portal_sign = self.compute_portal_sign(&portal_id, &salt, &nonce, &mac_key)?;

        // Step 5: portal_data = salt + nonce + AES-GCM(Serialize(data), enc_key)
        let encrypted_data = self.encrypt_data(data, &enc_key, &nonce)?;

        let mut portal_data = Vec::with_capacity(32 + 32 + 12 + encrypted_data.len());
        portal_data.extend_from_slice(&argon2_salt); // Argon2id salt (32)
        portal_data.extend_from_slice(&hkdf_salt); // HKDF salt (32)
        portal_data.extend_from_slice(&salt); // Encryption salt (32)
        portal_data.extend_from_slice(&nonce); // Nonce (12)
        portal_data.extend_from_slice(&encrypted_data); // Encrypted data

        // Step 6: portal_msg = portal_sign + portal_data
        let mut portal_msg = Vec::with_capacity(32 + portal_data.len());
        portal_msg.extend_from_slice(&portal_sign);
        portal_msg.extend_from_slice(&portal_data);

        Ok(portal_msg)
    }

    /// Step 5: 验证并解析portal消息
    pub fn parse_portal_message<T: for<'de> Deserialize<'de>>(
        &self,
        portal_msg: &[u8],
    ) -> Result<T, PortalCryptoError> {
        if portal_msg.len() < 32 + 32 + 32 + 32 + 12 {
            return Err(PortalCryptoError::InvalidInput);
        }

        // 1. 解析portal_msg
        let (received_sign, portal_data) = portal_msg.split_at(32);
        let (argon2_salt, rest) = portal_data.split_at(32);
        let (hkdf_salt, rest2) = rest.split_at(32);
        let (salt, rest3) = rest2.split_at(32);
        let (nonce, encrypted_data) = rest3.split_at(12);

        // Step 1: 使用 Argon2id 派生 pass_key
        let pass_key = self.derive_pass_key(
            argon2_salt
                .try_into()
                .map_err(|_| PortalCryptoError::InvalidInput)?,
        )?;

        // Step 2: 使用 HKDF 派生密钥
        let (enc_key, mac_key, portal_id) = self.derive_keys(
            &pass_key,
            hkdf_salt
                .try_into()
                .map_err(|_| PortalCryptoError::InvalidInput)?,
        )?;

        // Step 3: 验证签名
        let expected_sign = self.compute_portal_sign(
            &portal_id,
            salt.try_into()
                .map_err(|_| PortalCryptoError::InvalidInput)?,
            nonce
                .try_into()
                .map_err(|_| PortalCryptoError::InvalidInput)?,
            &mac_key,
        )?;

        if received_sign != expected_sign.as_slice() {
            return Err(PortalCryptoError::InvalidSignature);
        }

        // Step 4: 解密数据
        self.decrypt_data(
            encrypted_data,
            &enc_key,
            nonce
                .try_into()
                .map_err(|_| PortalCryptoError::InvalidInput)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestData {
        message: String,
        number: i32,
        timestamp: u64,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct ComplexData {
        user_info: UserInfo,
        metadata: Vec<String>,
        config: Config,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct UserInfo {
        username: String,
        id: u32,
        active: bool,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Config {
        timeout: u32,
        retries: u8,
        enabled: bool,
    }

    #[test]
    fn test_portal_crypto_basic_flow() {
        let portal = PortalCrypto::new("test_tunnel_123", "secure_password_456");

        let data = TestData {
            message: "Hello, Portal!".to_string(),
            number: 42,
            timestamp: 1703920800,
        };

        // 构建portal消息
        let portal_msg = portal
            .build_portal_message(&data)
            .expect("Failed to build portal message");

        // 解析portal消息
        let parsed_data: TestData = portal
            .parse_portal_message(&portal_msg)
            .expect("Failed to parse portal message");

        assert_eq!(data, parsed_data);
    }

    #[test]
    fn test_portal_crypto_check_valid() {
        let portal = PortalCrypto::new("test_tunnel_123", "secure_password_456");

        let data = TestData {
            message: "Validation test".to_string(),
            number: 123,
            timestamp: 1703920800,
        };

        // 构建portal消息
        let portal_msg = portal
            .build_portal_message(&data)
            .expect("Failed to build portal message");

        // 检查消息有效性
        let is_valid = portal
            .check_valid(&portal_msg)
            .expect("Failed to check portal message");

        assert!(is_valid);

        // 测试无效消息 - 修改签名
        let mut invalid_msg = portal_msg.clone();
        invalid_msg[0] ^= 0xFF;
        let is_invalid = portal
            .check_valid(&invalid_msg)
            .expect("Failed to check portal message");

        assert!(!is_invalid);

        // 测试无效消息 - 修改数据
        let mut invalid_msg2 = portal_msg.clone();
        invalid_msg2[100] ^= 0xFF;
        let is_invalid2 = portal
            .check_valid(&invalid_msg2)
            .expect("Failed to check portal message");

        assert!(!is_invalid2);
    }

    #[test]
    fn test_different_passwords_produce_different_keys() {
        let portal1 = PortalCrypto::new("test_tunnel", "password1");
        let portal2 = PortalCrypto::new("test_tunnel", "password2");

        let data = TestData {
            message: "Test".to_string(),
            number: 1,
            timestamp: 1703920800,
        };

        let msg1 = portal1.build_portal_message(&data).unwrap();
        let msg2 = portal2.build_portal_message(&data).unwrap();

        // 相同数据，不同密码应该产生不同的消息
        assert_ne!(msg1, msg2);

        // 交叉验证应该失败
        let result1: Result<TestData, _> = portal1.parse_portal_message(&msg2);
        let result2: Result<TestData, _> = portal2.parse_portal_message(&msg1);

        assert!(result1.is_err());
        assert!(result2.is_err());
    }

    #[test]
    fn test_different_tunnel_ids_produce_different_keys() {
        let portal1 = PortalCrypto::new("tunnel1", "same_password");
        let portal2 = PortalCrypto::new("tunnel2", "same_password");

        let data = TestData {
            message: "Test".to_string(),
            number: 1,
            timestamp: 1703920800,
        };

        let msg1 = portal1.build_portal_message(&data).unwrap();
        let msg2 = portal2.build_portal_message(&data).unwrap();

        // 相同密码和隧道ID应该产生不同的消息
        assert_ne!(msg1, msg2);

        // 交叉验证应该失败
        let result1: Result<TestData, _> = portal1.parse_portal_message(&msg2);
        let result2: Result<TestData, _> = portal2.parse_portal_message(&msg1);

        assert!(result1.is_err());
        assert!(result2.is_err());
    }

    #[test]
    fn test_complex_data_structures() {
        let portal = PortalCrypto::new("complex_tunnel", "complex_password");

        let data = ComplexData {
            user_info: UserInfo {
                username: "alice".to_string(),
                id: 12345,
                active: true,
            },
            metadata: vec!["tag1".to_string(), "tag2".to_string(), "tag3".to_string()],
            config: Config {
                timeout: 30000,
                retries: 3,
                enabled: true,
            },
        };

        let portal_msg = portal.build_portal_message(&data).unwrap();
        let parsed_data: ComplexData = portal.parse_portal_message(&portal_msg).unwrap();

        assert_eq!(data, parsed_data);
    }

    #[test]
    fn test_large_data() {
        let portal = PortalCrypto::new("large_tunnel", "large_password");

        let large_string = "x".repeat(10000);
        let data = TestData {
            message: large_string,
            number: 999999,
            timestamp: 1703920800,
        };

        let portal_msg = portal.build_portal_message(&data).unwrap();
        let parsed_data: TestData = portal.parse_portal_message(&portal_msg).unwrap();

        assert_eq!(data, parsed_data);
    }

    #[test]
    fn test_invalid_message_formats() {
        let portal = PortalCrypto::new("test_tunnel", "test_password");

        // 测试空消息
        let result = portal.check_valid(&[]);
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // 测试太短的消息
        let short_msg = vec![0u8; 50];
        let result = portal.check_valid(&short_msg);
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // 测试解析无效消息
        let invalid_msg = vec![0u8; 100];
        let result: Result<TestData, _> = portal.parse_portal_message(&invalid_msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_salt_and_nonce_generation() {
        // 测试生成的salt和nonce是唯一的
        let salt1 = PortalCrypto::generate_salt();
        let salt2 = PortalCrypto::generate_salt();
        assert_ne!(salt1, salt2);

        let nonce1 = PortalCrypto::generate_nonce();
        let nonce2 = PortalCrypto::generate_nonce();
        assert_ne!(nonce1, nonce2);

        // 测试长度
        assert_eq!(salt1.len(), 32);
        assert_eq!(nonce1.len(), 12);
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let portal = PortalCrypto::new("test_tunnel", "test_password");

        let salt = PortalCrypto::generate_salt();
        let hkdf_salt = PortalCrypto::generate_salt();

        // 相同输入应该产生相同的密钥
        let pass_key1 = portal.derive_pass_key(&salt).unwrap();
        let pass_key2 = portal.derive_pass_key(&salt).unwrap();
        assert_eq!(pass_key1, pass_key2);

        let keys1 = portal.derive_keys(&pass_key1, &hkdf_salt).unwrap();
        let keys2 = portal.derive_keys(&pass_key2, &hkdf_salt).unwrap();
        assert_eq!(keys1, keys2);
    }

    #[test]
    fn test_signature_deterministic() {
        let portal = PortalCrypto::new("test_tunnel", "test_password");

        let portal_id = PortalCrypto::generate_salt();
        let salt = PortalCrypto::generate_salt();
        let nonce = PortalCrypto::generate_nonce();
        let mac_key = PortalCrypto::generate_salt();

        // 相同输入应该产生相同的签名
        let sign1 = portal
            .compute_portal_sign(&portal_id, &salt, &nonce, &mac_key)
            .unwrap();
        let sign2 = portal
            .compute_portal_sign(&portal_id, &salt, &nonce, &mac_key)
            .unwrap();
        assert_eq!(sign1, sign2);

        // 不同输入应该产生不同的签名
        let mut different_nonce = nonce;
        different_nonce[0] ^= 0xFF;
        let sign3 = portal
            .compute_portal_sign(&portal_id, &salt, &different_nonce, &mac_key)
            .unwrap();
        assert_ne!(sign1, sign3);
    }

    #[test]
    fn test_encryption_decryption_isolation() {
        let portal = PortalCrypto::new("test_tunnel", "test_password");

        let enc_key = PortalCrypto::generate_salt();
        let nonce = PortalCrypto::generate_nonce();

        let data = TestData {
            message: "Isolation test".to_string(),
            number: 42,
            timestamp: 1703920800,
        };

        let encrypted = portal.encrypt_data(&data, &enc_key, &nonce).unwrap();
        let decrypted: TestData = portal.decrypt_data(&encrypted, &enc_key, &nonce).unwrap();

        assert_eq!(data, decrypted);

        // 测试用不同密钥解密失败
        let wrong_key = PortalCrypto::generate_salt();
        let result: Result<TestData, _> = portal.decrypt_data(&encrypted, &wrong_key, &nonce);
        assert!(result.is_err());

        // 测试用不同nonce解密失败
        let wrong_nonce = PortalCrypto::generate_nonce();
        let result2: Result<TestData, _> = portal.decrypt_data(&encrypted, &enc_key, &wrong_nonce);
        assert!(result2.is_err());
    }

    #[test]
    fn test_multiple_encryptions_produce_different_ciphertexts() {
        let portal = PortalCrypto::new("test_tunnel", "test_password");

        let data = TestData {
            message: "Randomness test".to_string(),
            number: 42,
            timestamp: 1703920800,
        };

        // 多次加密相同数据应该产生不同的密文（因为nonce不同）
        let msg1 = portal.build_portal_message(&data).unwrap();
        let msg2 = portal.build_portal_message(&data).unwrap();
        let msg3 = portal.build_portal_message(&data).unwrap();

        assert_ne!(msg1, msg2);
        assert_ne!(msg2, msg3);
        assert_ne!(msg1, msg3);

        // 但解密后应该得到相同的数据
        let parsed1: TestData = portal.parse_portal_message(&msg1).unwrap();
        let parsed2: TestData = portal.parse_portal_message(&msg2).unwrap();
        let parsed3: TestData = portal.parse_portal_message(&msg3).unwrap();

        assert_eq!(parsed1, data);
        assert_eq!(parsed2, data);
        assert_eq!(parsed3, data);
    }

    #[test]
    fn test_empty_and_edge_case_data() {
        let portal = PortalCrypto::new("edge_tunnel", "edge_password");

        // 测试空字符串
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct EmptyData {
            empty_string: String,
            zero_number: i32,
            false_bool: bool,
        }

        let data = EmptyData {
            empty_string: "".to_string(),
            zero_number: 0,
            false_bool: false,
        };

        let portal_msg = portal.build_portal_message(&data).unwrap();
        let parsed_data: EmptyData = portal.parse_portal_message(&portal_msg).unwrap();

        assert_eq!(data, parsed_data);
    }
}
