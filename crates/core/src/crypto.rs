//! Overlay 端到端加密
//!
//! # 为什么在 overlay 层加密
//!
//! 数据面统一走 QUIC DATAGRAM 之后，**中继模式下 QUIC 是逐跳的**：
//! Guest↔中继 一条连接，中继↔Host 另一条连接，中继站在中间能看到明文。
//! 所以真正的机密性必须由 overlay 自己提供，让中继退化成盲转发器。
//!
//! P2P 直连时这一层是冗余的（QUIC 本就加密），但保持两条路径的数据面一致
//! 比省下这点开销更重要——否则中继与直连要维护两套收发逻辑，
//! bug 会互相掩盖。
//!
//! # 握手
//!
//! 双方各生成一对**临时** X25519 密钥，用长期 Ed25519 身份密钥对其公钥签名，
//! 通过信令交换。签名是必需的：信令服务器同时也是中继运营方，
//! 若不签名它可以替换双方公钥完成中间人攻击。
//!
//! ```text
//! A: eph_pub_a, sign(id_a, eph_pub_a)  ──信令──>  B 验签
//! B: eph_pub_b, sign(id_b, eph_pub_b)  ──信令──>  A 验签
//! 双方: shared = X25519(eph_priv, eph_pub_peer)
//!       HKDF-SHA256(shared, salt=session_salt) → 两个方向各一把密钥
//! ```
//!
//! # 报文格式
//!
//! ```text
//! [ 8 字节大端计数器 ][ ChaCha20-Poly1305 密文 + 16 字节 tag ]
//! ```
//!
//! 计数器同时充当 nonce 与重放检测序号。**同一把密钥下 nonce 绝不能重复**，
//! 因此收发使用两把独立派生的密钥，各自维护自己的计数器。

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};
use x25519_dalek::{PublicKey, StaticSecret};

/// 计数器前缀长度
const COUNTER_LEN: usize = 8;
/// Poly1305 认证标签长度
const TAG_LEN: usize = 16;
/// 加密后相对明文的固定膨胀
pub const OVERHEAD: usize = COUNTER_LEN + TAG_LEN;

/// 重放窗口宽度（包）。乱序是 DATAGRAM 的常态，窗口不能太窄。
///
/// **这个宽度量的是全连接共享的计数器距离，不是这条流自己收发过多少个包**
/// ——`tx_counter` 是整条连接共享的（见上面握手/报文格式的说明），而重放窗口
/// 虽然是按流（`FlowReplayTable`）分开建的，`check()` 里比较用的 `counter`
/// 仍然是这个全局值。这意味着窗口的真实容忍度不取决于这条流本身的流量，
/// 而是取决于**整条连接**（所有流量总和：这条流自己的、其它并发流的、
/// 局域网广播噪音的、乃至补包重发用掉的计数器)在这段时间里一共走了多少个
/// 计数器——连接越忙，这条流能承受的乱序容忍度反而越窄。
///
/// 实测踩过这个坑：Minecraft 刚进服那几秒，世界同步的大流量和局域网发现
/// 广播（mDNS/SSDP/NetBIOS）同时挤在一起，把全局计数器推进得很快，
/// 于是 Minecraft 这条 TCP 流里本来完全合法、只是正常网络乱序晚到一点的
/// 新包，被错判成"滑出窗口"直接丢弃——不是真的丢包，是本端自己拒收的。
/// TCP 重传的包一样是新计数器，一样会被同样的逻辑拒收，反复几次只能
/// reset。日志里表现为短时间内大量 `丢弃重复/过旧的 overlay 报文`。
///
/// 2048 在窗口关闭、单流量场景下够用，但撑不住这种多流并发+突发的场景。
/// 64K 覆盖的是"连接总计数器在几十秒内推进多远"，而不是几秒——现实里
/// 不存在正常网络乱序会让一个包晚到几十秒这种情况，留出这么大的余量
/// 本质是用内存换绝对安全边际（每条流的位图从 256 字节涨到 8KB，
/// 最坏情况 [`crate::tun_bridge`] 里 `MAX_TRACKED_FLOWS`=4096 条流一起用满
/// 也就 32MB，这版不在乎内存，能不误杀合法包才是硬要求）。
///
/// # 订正：加宽窗口并没有修好上面那个 bug
///
/// 上面这段"2048 太窄"的判断后来被证明是**误诊**。真正的成因是
/// [`ReplayWindow::check_and_set`] 文档里写的那个环形位图绕回缺陷，跟窗口
/// 宽度无关；把 2048 加宽到 65536 只是把发作时间从约 2 秒推到约 65 秒，
/// 症状从"进服几秒刷屏"变成"进服 1 分钟后刷屏"，是同一个 bug 的两次现身。
/// 这段文字保留下来是为了记住这个教训：**当时没有任何一个测试连续走过一圈
/// 边界**（全都是跳跃式推进，走的是整体清空快路径），所以加宽窗口"看起来
/// 有效"，实际只是把引信拉长了。
///
/// # 这个宽度仍然有一根随吞吐量自己变短的引信
///
/// 安全边际是按**包数**而不是按**时间**度量的，所以它会随连接吞吐量
/// 反比缩水：1000 包/秒 时容忍约 65 秒的乱序，100k 包/秒 时就只剩约
/// 0.65 秒。真正的需求其实是按时间界定的——去重只需要覆盖冗余错峰窗口
/// （60ms）加 ARQ 截止时间（150ms~2s），几秒足矣。把窗口从"最近 N 个包"
/// 改成"最近 T 秒"就能和包速率彻底解耦，这是已知的后续改进项（见
/// 《抗丢包方案设计》），当前吞吐量下 65536 还留着两个数量级的余量。
const REPLAY_WINDOW: u64 = 65536;

/// 本端的临时密钥对（一次会话一对，用完即弃）
pub struct EphemeralKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// 与对端公钥做 DH，派生出双向会话密钥。
    ///
    /// `is_initiator` 决定两个方向的密钥如何分配——**双方必须得出相反的角色**，
    /// 否则会各自用同一把密钥发送，导致 nonce 复用（灾难性）。
    /// 用房间内的固定规则确定角色，例如 Host 恒为 initiator。
    pub fn derive(self, peer_public: &[u8; 32], salt: &[u8], is_initiator: bool) -> SessionCrypto {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer_public));
        let hk = Hkdf::<Sha256>::new(Some(salt), shared.as_bytes());

        let mut k_init = [0u8; 32];
        let mut k_resp = [0u8; 32];
        // info 串不同 → 两个方向的密钥不同，即使 DH 结果相同
        hk.expand(b"phantom-p2p initiator->responder", &mut k_init)
            .expect("HKDF 输出长度合法");
        hk.expand(b"phantom-p2p responder->initiator", &mut k_resp)
            .expect("HKDF 输出长度合法");

        let (tx_key, rx_key) = if is_initiator {
            (k_init, k_resp)
        } else {
            (k_resp, k_init)
        };

        SessionCrypto {
            tx: ChaCha20Poly1305::new(Key::from_slice(&tx_key)),
            rx: ChaCha20Poly1305::new(Key::from_slice(&rx_key)),
            tx_counter: AtomicU64::new(0),
        }
    }
}

/// 一条 overlay 连接的加解密状态
pub struct SessionCrypto {
    tx: ChaCha20Poly1305,
    rx: ChaCha20Poly1305,
    tx_counter: AtomicU64,
}

impl SessionCrypto {
    /// 加密一个 IP 包。返回 `[计数器][密文+tag]`。
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let counter = self.tx_counter.fetch_add(1, Ordering::Relaxed);
        let nonce = nonce_from(counter);
        let ct = self
            .tx
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    // 计数器纳入 AAD，防止攻击者改写序号做重放/乱序注入
                    aad: &counter.to_be_bytes(),
                },
            )
            .map_err(|_| "overlay 加密失败".to_string())?;

        let mut out = Vec::with_capacity(COUNTER_LEN + ct.len());
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// 解密一个 overlay 报文。**不做重放判定**，把计数器随明文一起交还调用方。
    ///
    /// # 为什么重放判定不能放在这里
    ///
    /// 计数器是整条隧道会话共享的（同一把密钥下 nonce 不能重复），但隧道里同时
    /// 复用着多条互不相关的内层流量。若重放窗口也按会话全局维护，一条流的突发
    /// 就会把窗口整体往前推，导致另一条几乎静默的流延迟到达的**合法**包被判成
    /// "已滑出窗口"而丢弃——这不是攻击，只是正常的多路复用乱序。
    ///
    /// 实测后果：突发流量（例如同时在传文件）之后，游戏流量开始被成片丢弃，
    /// 积累到心跳也被误伤时，看门狗判定连接已死，整条隧道掉线重连。
    ///
    /// 调用方拿到明文后能看到内层 IP 头，按五元组把窗口拆开维护即可。
    pub fn open(&self, packet: &[u8]) -> Result<(u64, Vec<u8>), String> {
        if packet.len() < OVERHEAD {
            return Err("overlay 报文过短".to_string());
        }
        let mut c = [0u8; COUNTER_LEN];
        c.copy_from_slice(&packet[..COUNTER_LEN]);
        let counter = u64::from_be_bytes(c);

        let nonce = nonce_from(counter);
        let pt = self
            .rx
            .decrypt(
                &nonce,
                Payload {
                    msg: &packet[COUNTER_LEN..],
                    aad: &counter.to_be_bytes(),
                },
            )
            .map_err(|_| "overlay 解密失败（认证不通过）".to_string())?;

        Ok((counter, pt))
    }
}

/// 计数器 → 12 字节 nonce（前 4 字节留零）
fn nonce_from(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    *Nonce::from_slice(&n)
}

/// 滑动窗口重放检测。
///
/// 独立成模块只是为了把位运算的细节圈起来——DATAGRAM 天然乱序，
/// 这里必须容忍窗口内的任意顺序，只拒绝重复与过旧的包。
pub(crate) use ring::{ReplayVerdict, ReplayWindow};

mod ring {
    use super::REPLAY_WINDOW;

    /// 一次重放判定的结果。
    ///
    /// 拒绝的两种原因必须分开报：它们的成因和处置完全不同，混成一句
    /// "重复/过旧" 会让日志失去诊断价值——上一次这个模块出 bug 时，
    /// 刷屏的正是那句合并过的日志，看起来像网络症状，实际是本端的环形
    /// 位图绕回误判，排查因此多绕了两轮。附带的 `highest`/`slot` 就是
    /// 用来一眼认出绕回的：`counter` 远大于 `highest` 却报重复，除了
    /// 环形绕回没有别的可能。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum ReplayVerdict {
        /// 新序号，已记账，放行。
        Fresh,
        /// 窗口内已经收到过：冗余补发份、NACK 重传份，或真正的重放。
        Duplicate { highest: u64, slot: u64 },
        /// 比窗口下沿还旧，位图里已经没有它的信息，只能拒。
        TooOld { highest: u64, floor: u64 },
    }

    pub(crate) struct ReplayWindow {
        /// 已接受过的最大序号。位图覆盖的有效区间是
        /// `[highest - REPLAY_WINDOW + 1, highest]`，**恰好** REPLAY_WINDOW
        /// 个值，多一个都不行：环形位图按 `counter % REPLAY_WINDOW` 取槽，
        /// 区间只要超过一圈，两端就会落到同一个槽位上，判定必然出错。
        highest: u64,
        seen: Vec<u64>,
    }

    impl ReplayWindow {
        pub(crate) fn new() -> Self {
            Self {
                highest: 0,
                seen: vec![0u64; (REPLAY_WINDOW / 64) as usize],
            }
        }

        /// 判定并记账，一次完成。
        ///
        /// # 为什么这必须是**一个**函数
        ///
        /// 这里要维持的不变量是：**位图里置位的槽，都属于当前窗口**
        /// `[highest-REPLAY_WINDOW+1, highest]`。窗口前移时清掉新进来的槽
        /// （它们还留着整整一圈之前的旧位）是维持这个不变量的唯一手段。
        ///
        /// 这里曾经拆成 `check()` + `accept()` 两个函数，而只有 `accept()`
        /// 会滑动窗口、`check()` 直接读位图。于是当一个**比 `highest` 还新**
        /// 的序号到来时，它在环里的槽位仍留着一圈之前那个序号置的位，
        /// `check()` 把它当成重复拒掉，`accept()` 因此永远不会被调用，窗口
        /// 永远不再滑动，这条流之后的每一个包都撞上同样的陈旧位——
        /// **一条长命流跨过第一圈就被永久锁死，且不可恢复**。
        ///
        /// 实机表现：Minecraft 联机约 1000 包/秒，进服约 65 秒
        /// （65536 ÷ 1000）后连接必然 reset；而同一时刻 tcping 同一个端口
        /// 全程正常——每次探测都是新五元组、新窗口，走的是下面那条整体
        /// 清空的快路径，于是"端口通着但游戏就是断"。这个 bug 还被误诊过
        /// 一次，当时把窗口从 2048 加宽到 65536，只是把发作时间从约 2 秒
        /// 推到约 65 秒，并没有解决任何问题。
        ///
        /// 合并成一个函数之后，"读到未滑动的环"这条路径在结构上不存在了。
        pub(crate) fn check_and_set(&mut self, counter: u64) -> ReplayVerdict {
            if counter > self.highest {
                // 比见过的最大序号还新，**不可能**是重放，直接放行。
                // 绝不能去查位图：那个槽位此刻记的是一圈之前的历史。
                self.slide_to(counter);
                self.set(counter);
                return ReplayVerdict::Fresh;
            }

            // 窗口宽度恰好一圈，所以 `counter + REPLAY_WINDOW == highest`
            // 就已经出界了——它和 `highest` 取模后是同一个槽位，放进来必然
            // 被误判成重复。判据用 `<=` 而不是 `<`。
            if counter + REPLAY_WINDOW <= self.highest {
                return ReplayVerdict::TooOld {
                    highest: self.highest,
                    floor: self.highest.saturating_sub(REPLAY_WINDOW - 1),
                };
            }

            if self.test(counter) {
                ReplayVerdict::Duplicate {
                    highest: self.highest,
                    slot: counter % REPLAY_WINDOW,
                }
            } else {
                self.set(counter);
                ReplayVerdict::Fresh
            }
        }

        /// 把窗口前移到 `counter`，清掉因此新进入窗口的那些槽位。
        fn slide_to(&mut self, counter: u64) {
            debug_assert!(counter > self.highest);
            if counter - self.highest >= REPLAY_WINDOW {
                // 跳跃超过整个窗口宽度：位图里每一位记的都是已经过时的历史，
                // 逐位回收等于白转一整圈，直接清空。
                //
                // 这条快路径对**按流拆分**是必需的：每条流的窗口是第一次见到
                // 该流时才建的，而计数器整条会话共享，所以它的第一个包计数器
                // 可能已经是几十万——没有这条，滑动会退化成 O(counter) 的循环，
                // 一条新流就能把收包线程卡死。
                self.seen.iter_mut().for_each(|w| *w = 0);
            } else {
                // `slot(c) == slot(c - REPLAY_WINDOW)`，所以直接按新序号清即可：
                // 清掉的正是它一圈之前那个"前任"留下的位。第一圈内这些槽位
                // 本来就是空的，清了也无妨。
                for c in (self.highest + 1)..=counter {
                    self.clear(c);
                }
            }
            self.highest = counter;
        }

        fn idx(counter: u64) -> (usize, u64) {
            let slot = (counter % REPLAY_WINDOW) as usize;
            (slot / 64, 1u64 << (slot % 64))
        }
        fn test(&self, counter: u64) -> bool {
            let (w, b) = Self::idx(counter);
            self.seen[w] & b != 0
        }
        fn set(&mut self, counter: u64) {
            let (w, b) = Self::idx(counter);
            self.seen[w] |= b;
        }
        fn clear(&mut self, counter: u64) {
            let (w, b) = Self::idx(counter);
            self.seen[w] &= !b;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 建立一对已完成握手的双方
    fn pair() -> (SessionCrypto, SessionCrypto) {
        let a = EphemeralKeypair::generate();
        let b = EphemeralKeypair::generate();
        let (pa, pb) = (a.public_bytes(), b.public_bytes());
        let salt = b"room-XYZ";
        (a.derive(&pb, salt, true), b.derive(&pa, salt, false))
    }

    #[test]
    fn roundtrip_between_peers() {
        let (a, b) = pair();
        let msg = b"the quick brown fox jumps over the lazy dog";
        let sealed = a.seal(msg).unwrap();
        assert_eq!(b.open(&sealed).unwrap().1, msg);

        // 反方向同样要通
        let sealed = b.seal(msg).unwrap();
        assert_eq!(a.open(&sealed).unwrap().1, msg);
    }

    /// 双方必须派生出**相反**的角色，否则会各自用同一把密钥发送，
    /// 造成 nonce 复用——这对 ChaCha20-Poly1305 是灾难性的。
    #[test]
    fn directional_keys_are_distinct() {
        let (a, b) = pair();
        let sealed_by_a = a.seal(b"hello").unwrap();
        // A 不能解开自己发的包（那是 tx 密钥，它只有 rx 能解）
        assert!(a.open(&sealed_by_a).is_err());
        // B 可以
        assert!(b.open(&sealed_by_a).is_ok());
    }

    #[test]
    fn mismatched_peer_cannot_decrypt() {
        let (a, _b) = pair();
        let (_c, d) = pair();
        let sealed = a.seal(b"secret").unwrap();
        assert!(d.open(&sealed).is_err(), "不同握手的密钥不该能解密");
    }

    #[test]
    fn tampering_is_detected() {
        let (a, b) = pair();
        let mut sealed = a.seal(b"payload").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(b.open(&sealed).is_err(), "篡改密文必须认证失败");
    }

    /// 计数器纳入 AAD，改写序号必须导致认证失败——
    /// 否则攻击者可以把包挪到窗口内的其它位置绕过重放检测。
    #[test]
    fn counter_is_authenticated() {
        let (a, b) = pair();
        let mut sealed = a.seal(b"payload").unwrap();
        sealed[7] ^= 0xFF; // 改写计数器最低字节
        assert!(b.open(&sealed).is_err());
    }

    /// `open` 只负责认证解密，重放判定已移交调用方按内层流处理，
    /// 所以同一个密文能被反复解开——去重是上层的事。
    #[test]
    fn open_no_longer_rejects_replays_itself() {
        let (a, b) = pair();
        let sealed = a.seal(b"once").unwrap();
        assert!(b.open(&sealed).is_ok());
        assert!(
            b.open(&sealed).is_ok(),
            "重放判定已交给调用方，open 本身不该再拒绝"
        );
    }

    /// 判定放行与否，丢掉拒绝原因——只关心"通不通"的测试用它。
    fn ok(w: &mut ReplayWindow, counter: u64) -> bool {
        w.check_and_set(counter) == ReplayVerdict::Fresh
    }

    #[test]
    fn replay_window_rejects_duplicates() {
        let mut w = ReplayWindow::new();
        assert!(ok(&mut w, 10));
        assert!(!ok(&mut w, 10), "重复序号必须被拒绝");
    }

    /// DATAGRAM 天然乱序，窗口内的任意顺序都必须接受
    #[test]
    fn replay_window_accepts_any_order_inside_window() {
        let mut w = ReplayWindow::new();
        for c in (0..64).rev() {
            assert!(ok(&mut w, c), "窗口内乱序不应被拒");
        }
        assert!(!ok(&mut w, 10), "但重复仍要拒");
    }

    #[test]
    fn replay_window_drops_packets_that_slid_out() {
        let mut w = ReplayWindow::new();
        assert!(ok(&mut w, 0));
        assert!(ok(&mut w, REPLAY_WINDOW + 64));
        assert!(!ok(&mut w, 0), "滑出窗口的包应被丢弃");
    }

    /// 窗口下沿的边界：有效区间恰好是一圈（REPLAY_WINDOW 个值），
    /// 多放一个进来，它就会和 `highest` 落到同一个槽位上被误判成重复。
    #[test]
    fn replay_window_floor_is_exactly_one_lap_wide() {
        let mut w = ReplayWindow::new();
        let top = 3 * REPLAY_WINDOW;
        assert!(ok(&mut w, top));
        assert!(
            ok(&mut w, top - REPLAY_WINDOW + 1),
            "窗口下沿的第一个序号必须还在窗口内"
        );
        assert!(
            !ok(&mut w, top - REPLAY_WINDOW),
            "正好差一整圈的序号必须判为过旧——它和 highest 是同一个槽位"
        );
    }

    /// 一条长命流连续走过环形位图的整圈边界之后，必须还能继续收下去。
    ///
    /// 这是整个模块最关键的一个测试，因为它覆盖的正是长命流**唯一**会走的
    /// 路径。此前所有测试都是跳跃式推进（走"整体清空"快路径），没有任何一个
    /// 连续走过一圈边界，于是环形绕回缺陷藏了两轮：Minecraft 联机约 1000
    /// 包/秒，进服约 65 秒（65536÷1000）后这条流开始把**每一个**新包都判成
    /// 重复，游戏随即 reset，而同时 tcping 同一个端口全程正常（每次探测都是
    /// 新五元组、新窗口）。
    ///
    /// 走 3 圈而不是 1 圈：1 圈只能证明第一次绕回没炸，多圈才能证明滑动窗口
    /// 的清位逻辑是稳态正确的。
    #[test]
    fn replay_window_survives_many_laps_of_the_ring() {
        let mut w = ReplayWindow::new();
        for c in 0..(3 * REPLAY_WINDOW) {
            assert!(ok(&mut w, c), "连续推进时的新序号被误拒 (counter={c})");
        }
    }

    /// 修复不能矫枉过正：跨过圈边界之后，**重复**仍然必须被拒，
    /// 否则等于把重放保护整个修没了。
    #[test]
    fn replay_window_still_rejects_duplicates_across_a_lap_boundary() {
        let mut w = ReplayWindow::new();
        for c in 0..(REPLAY_WINDOW + 1000) {
            assert!(ok(&mut w, c));
        }
        // 刚跨过边界的那些序号，重发一遍必须全被拒。
        for c in (REPLAY_WINDOW - 10)..(REPLAY_WINDOW + 10) {
            assert!(!ok(&mut w, c), "跨圈之后重复仍必须被拒 (counter={c})");
        }
    }

    /// 跨圈 + 窗口内乱序 + 重复混在一起：不管顺序怎么打乱，
    /// **同一个序号被放行两次**这件事永远不能发生。
    #[test]
    fn replay_window_never_admits_the_same_counter_twice() {
        let mut w = ReplayWindow::new();
        let mut admitted = std::collections::HashSet::new();
        // 确定性的伪随机乱序：在推进的同时反复回插已经走过的序号。
        let mut seed = 0x9E3779B97F4A7C15u64;
        let mut highest = 0u64;
        for _ in 0..(4 * REPLAY_WINDOW) {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            // 大部分时候往前走，偶尔回插一个窗口内的旧序号。
            let counter = if seed % 4 == 0 && highest > 64 {
                highest - (seed >> 33) % 64
            } else {
                highest += 1;
                highest
            };
            if ok(&mut w, counter) {
                assert!(
                    admitted.insert(counter),
                    "同一个序号被放行了两次 (counter={counter})"
                );
            }
        }
        assert!(
            highest > 3 * REPLAY_WINDOW,
            "这个测试必须真的跨过多圈边界才有意义"
        );
    }

    /// 拒绝的两种原因必须分得清——日志靠它诊断，混成一句话会让
    /// 环形绕回这类本端自己的 bug 看起来像网络丢包。
    #[test]
    fn replay_window_reports_why_it_rejected() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.check_and_set(100), ReplayVerdict::Fresh);
        assert!(matches!(
            w.check_and_set(100),
            ReplayVerdict::Duplicate { highest: 100, .. }
        ));
        assert_eq!(w.check_and_set(100 + REPLAY_WINDOW), ReplayVerdict::Fresh);
        assert!(matches!(w.check_and_set(100), ReplayVerdict::TooOld { .. }));
    }

    /// 每条流的窗口是第一次见到该流时才建的，而计数器整条会话共享，
    /// 所以新流的第一个包计数器可能已经很大。这个跳跃必须被高效处理，
    /// 否则一条新流就能让收包线程转几十万次空循环。
    #[test]
    fn replay_window_handles_large_initial_jump() {
        let mut w = ReplayWindow::new();
        let start = 1_000_000u64;
        assert!(ok(&mut w, start));
        assert!(!ok(&mut w, start), "刚接受过的序号不能重复接受");
        assert!(ok(&mut w, start + 1), "窗口内的新序号应可接受");
        assert!(ok(&mut w, start - 1), "窗口内的乱序回退也应可接受");
    }

    #[test]
    fn overhead_matches_declared_constant() {
        let (a, _b) = pair();
        let pt = b"1234567890";
        let ct = a.seal(pt).unwrap();
        assert_eq!(ct.len(), pt.len() + OVERHEAD);
    }

    #[test]
    fn rejects_truncated_packets() {
        let (_a, b) = pair();
        assert!(b.open(&[0u8; OVERHEAD - 1]).is_err());
        assert!(b.open(&[]).is_err());
    }

    #[test]
    fn salt_separates_sessions() {
        let a = EphemeralKeypair::generate();
        let b = EphemeralKeypair::generate();
        let (pa, pb) = (a.public_bytes(), b.public_bytes());
        let ca = a.derive(&pb, b"room-A", true);
        let cb = b.derive(&pa, b"room-B", false); // 不同 salt
        let sealed = ca.seal(b"x").unwrap();
        assert!(cb.open(&sealed).is_err(), "salt 不同应派生出不同密钥");
    }
}
