//! 抗丢包补发的控制层。
//!
//! # 这里为什么是一个独立模块
//!
//! 补发机制的历史问题不是某个参数调错了，而是**它根本不是一个控制器**：
//! 按测到的丢包率查一张写死的表，从不检查自己的动作有没有效果。开环加正增益，
//! 结果必然发散——实测就是这么塌的：微量丢包 → 加码 → 副本挤掉原包 →
//! 丢包更多 → 继续加码 → 连接超时。
//!
//! 把控制逻辑单独拆出来，核心目的是**让它能被测试**。这里的每一块都写成纯逻辑：
//! 不读时钟（`now` 由调用方传入）、不加锁、不碰网络。于是整套升降档时序可以在
//! 单元测试里精确复现，不需要真建 QUIC 连接、不需要 sleep、不需要第二台机器。
//! 上一版的控制逻辑散在 `tun_bridge.rs` 的收包热路径里，跟 quinn 连接死死绑在
//! 一起，没有任何一条路径能在没有真实网络的情况下验证——这正是它带着一个
//! 必然发散的正反馈环上线的原因。
//!
//! # 与 `tun_bridge.rs` 的分工
//!
//! - `tun_bridge.rs`：数据面。收发包、加解密、重放去重、维护发送缓冲。
//! - 这里：控制面。看链路状态，回答"这一刻允许补几份"。
//!
//! 控制面只做**减法**：数据面按丢包率算出该补几份，控制面可以往下压，
//! 但永远不会往上加。

pub mod budget;
pub mod classify;
pub mod gate;
pub mod signals;

pub use budget::RepairBudget;
pub use classify::{is_bulk_sized, is_tcp_control, FlowClass, FlowProfile};
pub use gate::{Gate, GateController, MinRttFilter, Observation, TripReason};
pub use signals::{spawn_sampler, LinkSignals};
