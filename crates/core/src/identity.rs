//! 设备身份管理 — Ed25519 密钥对
//!
//! 首次运行时生成密钥对并持久化到磁盘。
//! 后续启动自动加载，保证设备身份唯一且稳定。

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::fs;
use tracing::{debug, info, warn};

/// 密钥文件名
const KEY_FILE: &str = "identity.key";

/// 设备身份
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// 加载或生成身份密钥对
    ///
    /// 优先从 `data_dir/identity.key` 加载；
    /// 如果文件不存在则生成新密钥并保存。
    pub fn load_or_generate(data_dir: &std::path::Path) -> Result<Self, String> {
        let key_path = data_dir.join(KEY_FILE);

        if key_path.exists() {
            // 加载已有密钥
            let key_bytes = fs::read(&key_path).map_err(|e| format!("读取密钥文件失败: {}", e))?;
            if key_bytes.len() != 32 {
                warn!(
                    "[身份] 密钥文件长度异常 ({}字节), 重新生成",
                    key_bytes.len()
                );
                return Self::generate_and_save(&key_path);
            }
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&key_bytes);
            let signing_key = SigningKey::from_bytes(&secret);
            let pub_key = signing_key.verifying_key();
            info!(
                "[身份] 已加载密钥 (公钥: {})",
                hex_short(&pub_key.to_bytes())
            );
            Ok(Self { signing_key })
        } else {
            // 首次生成
            info!("[身份] 首次启动, 生成新密钥对...");
            Self::generate_and_save(&key_path)
        }
    }

    /// 生成新密钥并保存到文件
    fn generate_and_save(key_path: &std::path::Path) -> Result<Self, String> {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_key = signing_key.verifying_key();

        // 确保目录存在
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("创建数据目录失败: {}", e))?;
        }

        // 写入私钥（32 字节）
        fs::write(key_path, signing_key.to_bytes())
            .map_err(|e| format!("保存密钥文件失败: {}", e))?;

        info!(
            "[身份] 新密钥已生成并保存 (公钥: {})",
            hex_short(&pub_key.to_bytes())
        );
        debug!("[身份] 密钥路径: {:?}", key_path);

        Ok(Self { signing_key })
    }

    /// 获取公钥字节（32 字节）
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }

    /// 获取 VerifyingKey
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// 用私钥签名数据，返回 64 字节签名
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// 获取用户可读的短 ID（公钥前 8 个十六进制字符）
    pub fn short_id(&self) -> String {
        hex_short(&self.public_key_bytes())
    }
}

/// 将字节数组转为短十六进制字符串（前 4 字节 = 8 字符）
fn hex_short(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{:02x}", b)).collect()
}
