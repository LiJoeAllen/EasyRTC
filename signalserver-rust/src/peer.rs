/// 对端(Peer)注册表管理
/// 维护所有已连接的 WebSocket 对端信息, 支持按 UUID 查找和发送消息

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message;

/// 对端句柄 - 注册表中存储的对端信息
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PeerHandle {
    /// 连接唯一标识
    pub conn_id: u64,
    /// 消息发送通道 (用于向此对端发送 WebSocket 消息)
    pub sender: mpsc::UnboundedSender<Message>,
    /// 32字节认证密钥
    pub mykey: [u8; 32],
    /// 128位序列号 (4 x uint32)
    pub mysn: [u32; 4],
    /// 角色: 0=未设置, 1=设备端(Offer), 2=客户端(Answer)
    pub role: i32,
    /// 是否在线
    pub alive: bool,
    /// 额外数据长度
    pub extradatalen0: u16,
    /// 额外数据 (转发给连接方)
    pub extradata0: Vec<u8>,
}

/// 对端注册表类型: UUID -> PeerHandle 的线程安全映射
pub type PeerRegistry = Arc<RwLock<HashMap<[u32; 4], PeerHandle>>>;

/// 创建新的对端注册表
pub fn new_registry() -> PeerRegistry {
    Arc::new(RwLock::new(HashMap::new()))
}

/// 检查 UUID 是否全零 (未设置)
pub fn uuid_is_zero(id: &[u32; 4]) -> bool {
    id[0] == 0 && id[1] == 0 && id[2] == 0 && id[3] == 0
}

/// 生成客户端 UUID (用于纯客户端, 由信令服务器分配)
pub fn generate_client_uuid() -> [u32; 4] {
    let u = uuid::Uuid::new_v4();
    let b = u.as_bytes();
    [
        u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
    ]
}

/// 将 [u32;4] 格式的 UUID 转为注册表键
pub fn make_uuid_key(id: &[u32; 4]) -> [u32; 4] {
    *id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_is_zero() {
        assert!(uuid_is_zero(&[0, 0, 0, 0]));
        assert!(!uuid_is_zero(&[1, 0, 0, 0]));
        assert!(!uuid_is_zero(&[0, 0, 0, 1]));
    }

    #[test]
    fn test_generate_client_uuid_非零() {
        let id = generate_client_uuid();
        assert!(!uuid_is_zero(&id));
    }

    #[test]
    fn test_generate_client_uuid_唯一性() {
        let id1 = generate_client_uuid();
        let id2 = generate_client_uuid();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_make_uuid_key() {
        let id = [0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222];
        assert_eq!(make_uuid_key(&id), id);
    }

    #[tokio::test]
    async fn test_new_registry_初始为空() {
        let reg = new_registry();
        assert!(reg.read().await.is_empty());
    }

    #[tokio::test]
    async fn test_registry_插入和查找() {
        let reg = new_registry();
        let key = [1, 2, 3, 4];
        let (_tx, _rx) = mpsc::unbounded_channel();
        let handle = PeerHandle {
            conn_id: 42,
            sender: _tx,
            mykey: [0u8; 32],
            mysn: [0u32; 4],
            role: 1,
            alive: true,
            extradatalen0: 0,
            extradata0: Vec::new(),
        };
        reg.write().await.insert(key, handle);
        assert!(reg.read().await.contains_key(&key));
    }
}
