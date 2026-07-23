//! 幻梦P2P 共享消息协议
//!
//! 客户端和服务端共用的消息类型定义。
//! 序列化使用 MessagePack (rmp-serde)，比 JSON 更小更快。

use serde::{Deserialize, Serialize};

/// ICE 候选地址类型（RFC 8445 §5.1.1）
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateType {
    /// 主机候选：本机实际网卡 IP
    Host,
    /// 服务器反射候选：通过 STUN 探测到的公网 IP:port
    ServerReflexive,
    /// 中继候选：通过 TURN/中继服务器分配
    Relay,
}

/// ICE 候选地址（RFC 8445 §5.1.1）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    /// 候选 IP 地址
    pub ip: String,
    /// 候选端口
    pub port: u16,
    /// 候选类型
    pub ctype: CandidateType,
    /// ICE 优先级（RFC 8445 §5.1.2.1）
    pub priority: u32,
    /// 候选基础标识（同源候选相同）
    pub foundation: String,
}

/// 预分配中继信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayPreAllocInfo {
    pub room_code: String,
    pub relay_addr: String,
    pub token: String,
}

/// serde 辅助：将 [u8; 32] 作为字节序列（而非数组）序列化
mod serde_bytes_array_32 {
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(bytes.as_slice(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let bytes: serde_bytes::ByteBuf = serde_bytes::deserialize(d)?;
        let v = bytes.into_vec();
        v.try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

/// serde 辅助：将 [u8; 64] 作为字节序列（而非数组）序列化
mod serde_bytes_array_64 {
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(bytes.as_slice(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let bytes: serde_bytes::ByteBuf = serde_bytes::deserialize(d)?;
        let v = bytes.into_vec();
        v.try_into()
            .map_err(|_| D::Error::custom("expected 64 bytes"))
    }
}

// ============================================================
// 客户端 → 服务端 消息
// ============================================================

/// 客户端发往服务端的消息
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum ClientMessage {
    /// 心跳
    #[serde(rename = "ping")]
    Ping,

    /// 创建房间
    #[serde(rename = "create_room")]
    CreateRoom,

    /// Host TUN is ready and the room can accept guests.
    #[serde(rename = "host_ready")]
    HostReady,

    /// 加入房间
    #[serde(rename = "join_room")]
    JoinRoom { room_code: String },

    /// 离开当前房间
    #[serde(rename = "leave_room")]
    LeaveRoom,

    /// 关闭房间（仅 host 可操作）
    #[serde(rename = "close_room")]
    CloseRoom,

    /// 鉴权响应（签名 nonce）
    #[serde(rename = "auth")]
    Auth {
        #[serde(with = "serde_bytes_array_32")]
        public_key: [u8; 32],
        #[serde(with = "serde_bytes_array_64")]
        signature: [u8; 64],
    },

    /// 请求中继（打洞失败后）
    #[serde(rename = "relay_request")]
    RelayRequest,

    /// 上报 ICE 候选地址集合
    #[serde(rename = "ice_candidates")]
    IceCandidates {
        #[serde(default)]
        target_peer_session_id: Option<String>,
        candidates: Vec<IceCandidate>,
        ufrag: String,
        pwd: String,
        nat_type: String,
    },

    /// 请求服务端触发静默中继升级
    #[serde(rename = "relay_upgrade_request")]
    RelayUpgradeRequest,

    /// Request a persistent virtual address for future Host rooms.
    #[serde(rename = "request_fixed_host_ip")]
    RequestFixedHostIp,

    /// Release the persistent Host virtual address.
    #[serde(rename = "release_fixed_host_ip")]
    ReleaseFixedHostIp,

    /// Query the persistent Host virtual address.
    #[serde(rename = "get_fixed_host_ip")]
    GetFixedHostIp,
}

// ============================================================
// 服务端 → 客户端 消息
// ============================================================

/// 服务端发往客户端的消息
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum ServerMessage {
    /// 连接成功，返回 session_id
    #[serde(rename = "welcome")]
    Welcome { session_id: String },

    /// 心跳响应
    #[serde(rename = "pong")]
    Pong,

    /// 房间创建成功
    #[serde(rename = "room_created")]
    RoomCreated {
        room_code: String,
        subnet: String,
        virtual_ip: String,
    },

    /// 加入房间成功
    #[serde(rename = "join_ok")]
    JoinOk {
        room_code: String,
        host_session_id: String,
        /// 分配的虚拟子网段（如 "10.0.1" 表示 10.0.1.0/24）
        subnet: String,
        virtual_ip: String,
        host_virtual_ip: String,
    },

    /// 加入房间失败
    #[serde(rename = "join_failed")]
    JoinFailed { reason: String },

    /// 有新的 guest 加入（通知 host）
    #[serde(rename = "peer_joined")]
    PeerJoined {
        peer_session_id: String,
        guest_count: usize,
    },

    /// 有 guest 离开（通知 host）
    #[serde(rename = "peer_left")]
    PeerLeft {
        peer_session_id: String,
        guest_count: usize,
    },

    /// 房间被 host 关闭（通知 guest）
    #[serde(rename = "room_closed")]
    RoomClosed { reason: String },

    /// 通用错误
    #[serde(rename = "error")]
    Error { message: String },

    /// 鉴权挑战
    #[serde(rename = "auth_challenge")]
    AuthChallenge {
        #[serde(with = "serde_bytes_array_32")]
        nonce: [u8; 32],
    },

    /// 鉴权成功
    #[serde(rename = "auth_ok")]
    AuthOk { user_id: String },

    /// Persistent Host address status.
    #[serde(rename = "fixed_host_ip_status")]
    FixedHostIpStatus {
        enabled: bool,
        virtual_ip: Option<String>,
    },

    /// 鉴权失败
    #[serde(rename = "auth_failed")]
    AuthFailed { reason: String },

    /// 中继就绪
    #[serde(rename = "relay_ready")]
    RelayReady {
        room_code: String,
        relay_addr: String,
        relay_quic_port: u16,
        token: String,
    },

    /// 中继预分配完成
    #[serde(rename = "relay_pre_allocated")]
    RelayPreAllocated {
        room_code: String,
        relay_addr: String,
        relay_quic_port: u16,
        token: String,
    },

    /// 转发对端 ICE 候选地址
    #[serde(rename = "peer_candidates")]
    PeerCandidates {
        peer_session_id: String,
        candidates: Vec<IceCandidate>,
        peer_ufrag: String,
        peer_pwd: String,
        peer_nat_type: String,
        start_at_ms: u64,
    },
}

// ============================================================
// 序列化/反序列化辅助函数
// ============================================================

/// 将消息序列化为 MessagePack 二进制
pub fn serialize<T: Serialize>(msg: &T) -> Result<Vec<u8>, rmp_serde::encode::Error> {
    rmp_serde::to_vec_named(msg)
}

/// 从 MessagePack 二进制反序列化消息
pub fn deserialize<'a, T: Deserialize<'a>>(data: &'a [u8]) -> Result<T, rmp_serde::decode::Error> {
    rmp_serde::from_slice(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_message_roundtrip() {
        let msg = ClientMessage::CreateRoom;
        let bytes = serialize(&msg).unwrap();
        let decoded: ClientMessage = deserialize(&bytes).unwrap();
        match decoded {
            ClientMessage::CreateRoom => {}
            _ => panic!("消息类型不匹配"),
        }
    }

    #[test]
    fn targeted_ice_candidates_roundtrip() {
        let msg = ClientMessage::IceCandidates {
            target_peer_session_id: Some("guest-42".to_string()),
            candidates: Vec::new(),
            ufrag: String::new(),
            pwd: String::new(),
            nat_type: "port_restricted_cone".to_string(),
        };
        let bytes = serialize(&msg).unwrap();
        let decoded: ClientMessage = deserialize(&bytes).unwrap();
        match decoded {
            ClientMessage::IceCandidates {
                target_peer_session_id,
                ..
            } => assert_eq!(target_peer_session_id.as_deref(), Some("guest-42")),
            _ => panic!("unexpected message"),
        }
    }

    #[test]
    fn test_server_message_roundtrip() {
        let msg = ServerMessage::RoomCreated {
            room_code: "X7K9M2".to_string(),
            subnet: "172.16.1".to_string(),
            virtual_ip: "172.16.1.1".to_string(),
        };
        let bytes = serialize(&msg).unwrap();
        let decoded: ServerMessage = deserialize(&bytes).unwrap();
        match decoded {
            ServerMessage::RoomCreated {
                room_code,
                subnet,
                virtual_ip,
            } => {
                assert_eq!(room_code, "X7K9M2");
                assert_eq!(subnet, "172.16.1");
                assert_eq!(virtual_ip, "172.16.1.1");
            }
            _ => panic!("消息类型不匹配"),
        }
    }

    #[test]
    fn test_join_ok_roundtrip() {
        let msg = ServerMessage::JoinOk {
            room_code: "ABC123".to_string(),
            host_session_id: "sess_host_001".to_string(),
            subnet: "10.0.1".to_string(),
            virtual_ip: "10.0.1.2".to_string(),
            host_virtual_ip: "10.0.1.1".to_string(),
        };
        let bytes = serialize(&msg).unwrap();
        let decoded: ServerMessage = deserialize(&bytes).unwrap();
        match decoded {
            ServerMessage::JoinOk {
                room_code,
                host_session_id,
                subnet,
                virtual_ip,
                host_virtual_ip,
            } => {
                assert_eq!(room_code, "ABC123");
                assert_eq!(host_session_id, "sess_host_001");
                assert_eq!(subnet, "10.0.1");
                assert_eq!(virtual_ip, "10.0.1.2");
                assert_eq!(host_virtual_ip, "10.0.1.1");
            }
            _ => panic!("消息类型不匹配"),
        }
    }

    #[test]
    fn test_peer_joined_roundtrip() {
        let msg = ServerMessage::PeerJoined {
            peer_session_id: "sess_guest_001".to_string(),
            guest_count: 3,
        };
        let bytes = serialize(&msg).unwrap();
        let decoded: ServerMessage = deserialize(&bytes).unwrap();
        match decoded {
            ServerMessage::PeerJoined {
                peer_session_id,
                guest_count,
            } => {
                assert_eq!(peer_session_id, "sess_guest_001");
                assert_eq!(guest_count, 3);
            }
            _ => panic!("消息类型不匹配"),
        }
    }

    #[test]
    fn test_fixed_host_ip_messages_roundtrip() {
        for msg in [
            ClientMessage::RequestFixedHostIp,
            ClientMessage::ReleaseFixedHostIp,
            ClientMessage::GetFixedHostIp,
        ] {
            let bytes = serialize(&msg).unwrap();
            let _: ClientMessage = deserialize(&bytes).unwrap();
        }

        let msg = ServerMessage::FixedHostIpStatus {
            enabled: true,
            virtual_ip: Some("172.24.0.1".to_string()),
        };
        let bytes = serialize(&msg).unwrap();
        match deserialize::<ServerMessage>(&bytes).unwrap() {
            ServerMessage::FixedHostIpStatus {
                enabled,
                virtual_ip,
            } => {
                assert!(enabled);
                assert_eq!(virtual_ip.as_deref(), Some("172.24.0.1"));
            }
            _ => panic!("unexpected message"),
        }
    }
}
